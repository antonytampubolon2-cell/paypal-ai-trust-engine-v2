import os, tempfile, threading, time, unittest, json, hashlib, base64
from pathlib import Path
from decimal import Decimal
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from trustguard_security import SQLiteReplayStore, authenticate_kyapay_jwt, authorize_delegated_transaction, verify_dpop_proof, canonicalize_transaction
from main_public import process_payment_request

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.store=SQLiteReplayStore(str(Path(self.tmp.name)/"replay.sqlite3"))
        self.key=ec.generate_private_key(ec.SECP256R1())
        pem=self.key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        os.environ.update(KYAPAY_ISSUER="issuer-test",KYAPAY_AUDIENCE="audience-test",KYAPAY_PUBLIC_KEY_PEM=pem,KYAPAY_JWT_ALGORITHM="ES256")
    def tearDown(self):
        self.tmp.cleanup()
        for k in ("KYAPAY_ISSUER","KYAPAY_AUDIENCE","KYAPAY_PUBLIC_KEY_PEM","KYAPAY_JWT_ALGORITHM"): os.environ.pop(k,None)
    def token(self, **overrides):
        now=int(time.time())
        c={"iss":"issuer-test","sub":"agent","aud":"audience-test","iat":now,"exp":now+600,"jti":str(time.time_ns()),"cnf":{"jkt":"not-the-test-jwk"},"delegation_grant":{"allowed_merchants":["merchant-1"],"max_spend":"50","currency":"USD","valid_until":now+300}}
        c.update(overrides)
        return jwt.encode(c,self.key,algorithm="ES256")
    def signed_request(self, *, token_jti=None, proof_jti=None, htm="POST", htu="https://example.test/pay"):
        now=int(time.time())
        dpop_key=ec.generate_private_key(ec.SECP256R1())
        jwk=jwt.algorithms.ECAlgorithm.to_jwk(dpop_key.public_key(),as_dict=True)
        jwk_json=json.dumps({k:jwk[k] for k in ("crv","kty","x","y")},separators=(",",":"),sort_keys=True)
        jkt=base64.urlsafe_b64encode(hashlib.sha256(jwk_json.encode()).digest()).decode().rstrip("=")
        overrides={"cnf":{"jkt":jkt}}
        if token_jti is not None:
            overrides["jti"]=token_jti
        token=self.token(**overrides)
        ath=base64.urlsafe_b64encode(hashlib.sha256(token.encode("ascii")).digest()).decode().rstrip("=")
        proof=jwt.encode(
            {"htm":htm,"htu":htu,"jti":proof_jti or "proof-"+str(time.time_ns()),"iat":now,"ath":ath},
            dpop_key,algorithm="ES256",headers={"typ":"dpop+jwt","jwk":jwk},
        )
        return token, proof

    class MockPayPal:
        def __init__(self, response=None, error=None):
            self.calls=[]
            self.response=response if response is not None else {"id":"SYNTHETIC-MOCK-ORDER"}
            self.error=error
        def run(self, **kwargs):
            self.calls.append(kwargs)
            if self.error:
                raise self.error
            return self.response

    def valid_transaction(self):
        return {"merchant":"merchant-1","amount":"12.34","currency":"USD"}

    def valid_mapping(self):
        return {"merchant-1":"SYNTHETIC-PAYPAL-MERCHANT"}

    def test_missing_config_fails_closed(self):
        os.environ.pop("KYAPAY_ISSUER")
        self.assertFalse(authenticate_kyapay_jwt("a.b.c").authenticated)
    def test_bad_signature_rejected(self):
        token=self.token()
        decoded=jwt.decode(token,self.key.public_key(),algorithms=["ES256"],issuer="issuer-test",audience="audience-test")
        other=ec.generate_private_key(ec.SECP256R1())
        self.assertFalse(authenticate_kyapay_jwt(jwt.encode(decoded,other,algorithm="ES256")).authenticated)
    def test_wrong_audience_rejected(self):
        self.assertFalse(authenticate_kyapay_jwt(self.token(aud="wrong")).authenticated)
    def test_expired_token_rejected(self):
        self.assertFalse(authenticate_kyapay_jwt(self.token(exp=int(time.time())-5)).authenticated)
    def test_merchant_limit_currency_rejected(self):
        base={"exp":time.time()+100,"delegation_grant":{"allowed_merchants":["merchant-1"],"max_spend":"10","currency":"USD","valid_until":time.time()+100}}
        for merchant,amount,currency in [("attacker","1","USD"),("merchant-1","10.01","USD"),("merchant-1","1","EUR")]:
            claims={**base,"jti":str(time.time_ns())}
            self.assertFalse(authorize_delegated_transaction(claims,{"merchant":merchant,"amount":amount,"currency":currency},self.store).allowed)
    def test_replay_claim_has_one_winner_under_contention(self):
        outcomes=[]; barrier=threading.Barrier(8)
        def run():
            barrier.wait(); outcomes.append(self.store.claim_once("test","same",time.time()+60))
        threads=[threading.Thread(target=run) for _ in range(8)]
        [t.start() for t in threads]; [t.join() for t in threads]
        self.assertEqual(sum(outcomes),1)
    def test_dict_proof_rejected(self):
        self.assertFalse(verify_dpop_proof({"htm":"POST"},expected_method="POST",expected_url="https://example.test/pay",replay_store=self.store).allowed)

    def test_valid_signed_token_and_dpop_reach_mock_with_same_checked_transaction(self):
        now=int(time.time())
        dpop_key=ec.generate_private_key(ec.SECP256R1())
        jwk=jwt.algorithms.ECAlgorithm.to_jwk(dpop_key.public_key(),as_dict=True)
        canonical=json.dumps({k:jwk[k] for k in ("crv","kty","x","y")},separators=(",",":"),sort_keys=True)
        jkt=base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).decode().rstrip("=")
        token=self.token(cnf={"jkt":jkt})
        ath=base64.urlsafe_b64encode(hashlib.sha256(token.encode("ascii")).digest()).decode().rstrip("=")
        proof=jwt.encode({"htm":"POST","htu":"https://example.test/pay","jti":"proof-"+str(time.time_ns()),"iat":now,"ath":ath},dpop_key,algorithm="ES256",headers={"typ":"dpop+jwt","jwk":jwk})
        class MockPayPal:
            def __init__(self): self.calls=[]
            def run(self,**kwargs): self.calls.append(kwargs); return {"id":"MOCK-ORDER"}
        mock=MockPayPal()
        result=process_payment_request(
            compact_token=token, compact_dpop_proof=proof,
            transaction={"merchant":"merchant-1","amount":"12.34","currency":"USD"},
            replay_store=self.store, paypal_api=mock, expected_url="https://example.test/pay",
            merchant_mapping={"merchant-1":"PAYPAL-MERCHANT-VERIFIED"},
            rest_items=[
                {"name":"Line item A","quantity":"1","unit_amount":{"currency_code":"USD","value":"10.00"}},
                {"name":"Line item B","quantity":"1","unit_amount":{"currency_code":"USD","value":"2.34"}},
            ],
        )
        self.assertEqual((result.authentication_status,result.policy_status,result.delivery_status),("PASSED","PASSED","ORDER_CREATED"))
        # Creating an order is not proof of a completed payment or capture.
        self.assertNotEqual(result.delivery_status,"SUCCEEDED")
        self.assertEqual(len(mock.calls),1)
        self.assertEqual(mock.calls[0]["method"],"create_order")
        self.assertEqual(mock.calls[0]["params"]["intent"],"AUTHORIZE")
        self.assertNotIn("capture",mock.calls[0]["method"].lower())
        payload=mock.calls[0]["params"]["purchase_units"][0]
        canonical=canonicalize_transaction(
            {"merchant":"merchant-1","amount":"12.34","currency":"USD"},
            merchant_mapping={"merchant-1":"PAYPAL-MERCHANT-VERIFIED"},
        )
        self.assertEqual(payload["payee"]["merchant_id"],canonical.paypal_merchant_id)
        self.assertEqual(payload["amount"],{
            "currency_code":canonical.currency,
            "value":canonical.amount_text,
        })
        self.assertEqual(payload["description"],canonical.description)
        self.assertEqual(payload["amount"]["breakdown"]["item_total"], {
            "currency_code": "USD", "value": "12.34"
        })
        self.assertEqual(
            sum(Decimal(item["unit_amount"]["value"]) * int(item["quantity"]) for item in payload["items"]),
            canonical.amount,
        )


    def test_canonical_amount_rejects_excess_precision_and_invalid_values(self):
        mapping={"merchant-1":"PAYPAL-MERCHANT-VERIFIED"}
        for amount in ("1.239", "0", "-1", "NaN", "Infinity", "-Infinity", "not-a-number"):
            with self.subTest(amount=amount):
                with self.assertRaises(ValueError):
                    canonicalize_transaction({"merchant":"merchant-1","amount":amount,"currency":"USD"},merchant_mapping=mapping)

    def test_canonical_currency_minor_units_and_unsupported_currency(self):
        mapping={"merchant-1":"PAYPAL-MERCHANT-VERIFIED"}
        self.assertEqual(canonicalize_transaction({"merchant":"merchant-1","amount":"1.239","currency":"BHD"},merchant_mapping=mapping).amount_text,"1.239")
        self.assertEqual(canonicalize_transaction({"merchant":"merchant-1","amount":"123","currency":"JPY"},merchant_mapping=mapping).amount_text,"123")
        for currency,amount in (("JPY","1.2"),("XYZ","1.00")):
            with self.subTest(currency=currency,amount=amount):
                with self.assertRaises(ValueError):
                    canonicalize_transaction({"merchant":"merchant-1","amount":amount,"currency":currency},merchant_mapping=mapping)

    def test_canonical_merchant_mapping_is_explicit(self):
        tx={"merchant":"merchant-1","amount":"1.00","currency":"USD"}
        with self.assertRaises(ValueError):
            canonicalize_transaction(tx,merchant_mapping={})
        canonical=canonicalize_transaction(tx,merchant_mapping={"merchant-1":"PAYPAL-REAL-ID-EXPLICIT"})
        self.assertEqual(canonical.paypal_merchant_id,"PAYPAL-REAL-ID-EXPLICIT")
        self.assertNotEqual(canonical.paypal_merchant_id,canonical.merchant)

    def test_spending_limit_boundary(self):
        now=time.time()
        claims={"exp":now+100,"jti":"limit-boundary","delegation_grant":{"allowed_merchants":["merchant-1"],"max_spend":"10.00","currency":"USD","valid_until":now+100}}
        allowed=authorize_delegated_transaction(claims,{"merchant":"merchant-1","amount":"10.00","currency":"USD"},self.store,now=now)
        self.assertTrue(allowed.allowed)
        over={"exp":now+100,"jti":"limit-over","delegation_grant":{"allowed_merchants":["merchant-1"],"max_spend":"10.00","currency":"USD","valid_until":now+100}}
        denied=authorize_delegated_transaction(over,{"merchant":"merchant-1","amount":"10.01","currency":"USD"},self.store,now=now)
        self.assertFalse(denied.allowed)

    def test_bad_token_never_calls_paypal(self):
        class NeverCall:
            def run(self,**kwargs): raise AssertionError("unexpected outbound request")
        result=process_payment_request(compact_token="bad",compact_dpop_proof="bad",transaction={"merchant":"merchant-1","amount":"1","currency":"USD"},replay_store=self.store,paypal_api=NeverCall(),expected_url="https://example.test/pay")
        self.assertEqual(result.delivery_status,"NOT_ATTEMPTED")


    def test_invalid_request_transactions_never_call_paypal(self):
        """Every invalid request is rejected before the injected PayPal adapter is invoked."""
        scenarios = [
            ("usd_excess_precision", {"merchant":"merchant-1","amount":"1.239","currency":"USD"}, {"merchant-1":"PAYPAL-MERCHANT-VERIFIED"}),
            ("zero", {"merchant":"merchant-1","amount":"0","currency":"USD"}, {"merchant-1":"PAYPAL-MERCHANT-VERIFIED"}),
            ("negative", {"merchant":"merchant-1","amount":"-1","currency":"USD"}, {"merchant-1":"PAYPAL-MERCHANT-VERIFIED"}),
            ("malformed", {"merchant":"merchant-1","amount":"one-dollar","currency":"USD"}, {"merchant-1":"PAYPAL-MERCHANT-VERIFIED"}),
            ("nan", {"merchant":"merchant-1","amount":"NaN","currency":"USD"}, {"merchant-1":"PAYPAL-MERCHANT-VERIFIED"}),
            ("infinity", {"merchant":"merchant-1","amount":"Infinity","currency":"USD"}, {"merchant-1":"PAYPAL-MERCHANT-VERIFIED"}),
            ("excess_precision", {"merchant":"merchant-1","amount":"1.230","currency":"USD"}, {"merchant-1":"PAYPAL-MERCHANT-VERIFIED"}),
            ("unsupported_currency", {"merchant":"merchant-1","amount":"1.00","currency":"XYZ"}, {"merchant-1":"PAYPAL-MERCHANT-VERIFIED"}),
            ("missing_mapping", {"merchant":"merchant-1","amount":"1.00","currency":"USD"}, {}),
            ("empty_mapping_value", {"merchant":"merchant-1","amount":"1.00","currency":"USD"}, {"merchant-1":""}),
            ("delegation_merchant_mismatch", {"merchant":"other-merchant","amount":"1.00","currency":"USD"}, {"other-merchant":"PAYPAL-OTHER-EXPLICIT"}),
        ]
        for label, transaction, mapping in scenarios:
            with self.subTest(scenario=label):
                now=int(time.time())
                dpop_key=ec.generate_private_key(ec.SECP256R1())
                jwk=jwt.algorithms.ECAlgorithm.to_jwk(dpop_key.public_key(),as_dict=True)
                canonical=json.dumps({k:jwk[k] for k in ("crv","kty","x","y")},separators=(",",":"),sort_keys=True)
                jkt=base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).decode().rstrip("=")
                token=self.token(cnf={"jkt":jkt},jti="invalid-"+label+"-"+str(time.time_ns()))
                ath=base64.urlsafe_b64encode(hashlib.sha256(token.encode("ascii")).digest()).decode().rstrip("=")
                proof=jwt.encode(
                    {"htm":"POST","htu":"https://example.test/pay","jti":"proof-"+label+"-"+str(time.time_ns()),"iat":now,"ath":ath},
                    dpop_key,algorithm="ES256",headers={"typ":"dpop+jwt","jwk":jwk},
                )
                class NeverCallPayPal:
                    def __init__(self): self.calls=[]
                    def run(self,**kwargs):
                        self.calls.append(kwargs)
                        raise AssertionError("PayPal mock must not be called for invalid request")
                mock=NeverCallPayPal()
                result=process_payment_request(
                    compact_token=token,compact_dpop_proof=proof,transaction=transaction,
                    replay_store=self.store,paypal_api=mock,expected_url="https://example.test/pay",
                    merchant_mapping=mapping,
                )
                self.assertEqual(result.delivery_status,"NOT_ATTEMPTED",label)
                self.assertEqual(result.policy_status,"FAILED",label)
                self.assertEqual(mock.calls,[],label)

    def test_status_contract_capture_stays_not_attempted_after_order_creation(self):
        token,proof=self.signed_request()
        mock=self.MockPayPal()
        result=process_payment_request(compact_token=token,compact_dpop_proof=proof,
            transaction=self.valid_transaction(),replay_store=self.store,paypal_api=mock,
            expected_url="https://example.test/pay",merchant_mapping=self.valid_mapping())
        self.assertEqual((result.authentication_status,result.dpop_status,result.authorization_status),
            ("PASSED","PASSED","PASSED"))
        self.assertEqual((result.order_status,result.delivery_status,result.capture_status),
            ("ORDER_CREATED","ORDER_CREATED","NOT_ATTEMPTED"))
        self.assertEqual(len(mock.calls),1)
        self.assertEqual(mock.calls[0]["method"],"create_order")
        self.assertNotIn("capture",mock.calls[0]["method"].lower())

    def test_invalid_dpop_never_calls_paypal(self):
        token,proof=self.signed_request()
        mock=self.MockPayPal()
        result=process_payment_request(compact_token=token,compact_dpop_proof="invalid-proof",
            transaction=self.valid_transaction(),replay_store=self.store,paypal_api=mock,
            expected_url="https://example.test/pay",merchant_mapping=self.valid_mapping())
        self.assertEqual(result.dpop_status,"FAILED")
        self.assertEqual(result.order_status,"NOT_ATTEMPTED")
        self.assertEqual(mock.calls,[])

    def test_authorization_denial_never_calls_paypal(self):
        token,proof=self.signed_request()
        tx={"merchant":"not-allowed","amount":"1.00","currency":"USD"}
        mock=self.MockPayPal()
        result=process_payment_request(compact_token=token,compact_dpop_proof=proof,
            transaction=tx,replay_store=self.store,paypal_api=mock,
            expected_url="https://example.test/pay",
            merchant_mapping={"not-allowed":"SYNTHETIC-PAYPAL-MERCHANT"})
        self.assertEqual(result.authorization_status,"FAILED")
        self.assertEqual(result.order_status,"NOT_ATTEMPTED")
        self.assertEqual(mock.calls,[])

    def test_token_replay_never_creates_second_order(self):
        token,proof1=self.signed_request(token_jti="same-token-jti")
        _,proof2=self.signed_request(token_jti="unused-token-jti")
        # Bind proof2 to the original token while using a distinct proof JTI.
        dpop_key=ec.generate_private_key(ec.SECP256R1())
        jwk=jwt.algorithms.ECAlgorithm.to_jwk(dpop_key.public_key(),as_dict=True)
        jwk_json=json.dumps({k:jwk[k] for k in ("crv","kty","x","y")},separators=(",",":"),sort_keys=True)
        # Make a matching token whose cnf uses this key and reuse it for both requests.
        jkt=base64.urlsafe_b64encode(hashlib.sha256(jwk_json.encode()).digest()).decode().rstrip("=")
        token=self.token(cnf={"jkt":jkt},jti="same-token-jti")
        ath=base64.urlsafe_b64encode(hashlib.sha256(token.encode("ascii")).digest()).decode().rstrip("=")
        def proof(jti):
            return jwt.encode({"htm":"POST","htu":"https://example.test/pay","jti":jti,"iat":int(time.time()),"ath":ath},
                dpop_key,algorithm="ES256",headers={"typ":"dpop+jwt","jwk":jwk})
        mock=self.MockPayPal()
        first=process_payment_request(compact_token=token,compact_dpop_proof=proof("proof-token-first"),
            transaction=self.valid_transaction(),replay_store=self.store,paypal_api=mock,
            expected_url="https://example.test/pay",merchant_mapping=self.valid_mapping())
        second=process_payment_request(compact_token=token,compact_dpop_proof=proof("proof-token-second"),
            transaction=self.valid_transaction(),replay_store=self.store,paypal_api=mock,
            expected_url="https://example.test/pay",merchant_mapping=self.valid_mapping())
        self.assertEqual(first.order_status,"ORDER_CREATED")
        self.assertEqual(second.authorization_status,"FAILED")
        self.assertEqual(len(mock.calls),1)

    def test_dpop_replay_never_creates_second_order(self):
        token,proof=self.signed_request()
        mock=self.MockPayPal()
        first=process_payment_request(compact_token=token,compact_dpop_proof=proof,
            transaction=self.valid_transaction(),replay_store=self.store,paypal_api=mock,
            expected_url="https://example.test/pay",merchant_mapping=self.valid_mapping())
        # Use same token, so DPoP replay rejection occurs before token replay policy.
        second=process_payment_request(compact_token=token,compact_dpop_proof=proof,
            transaction=self.valid_transaction(),replay_store=self.store,paypal_api=mock,
            expected_url="https://example.test/pay",merchant_mapping=self.valid_mapping())
        self.assertEqual(first.order_status,"ORDER_CREATED")
        self.assertEqual(second.dpop_status,"FAILED")
        self.assertEqual(len(mock.calls),1)

    def test_same_jti_concurrent_requests_at_most_one_order(self):
        token,proof=self.signed_request(token_jti="concurrent-token-jti",proof_jti="concurrent-proof-jti")
        mock=self.MockPayPal()
        barrier=threading.Barrier(2)
        results=[]
        def invoke():
            barrier.wait()
            result=process_payment_request(compact_token=token,compact_dpop_proof=proof,
                transaction=self.valid_transaction(),replay_store=self.store,paypal_api=mock,
                expected_url="https://example.test/pay",merchant_mapping=self.valid_mapping())
            results.append(result)
        threads=[threading.Thread(target=invoke) for _ in range(2)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(len(results),2)
        self.assertEqual(sum(r.order_status=="ORDER_CREATED" for r in results),1)
        self.assertEqual(len(mock.calls),1)

    def test_replay_store_failure_fails_closed_before_paypal(self):
        token,proof=self.signed_request()
        class BrokenReplayStore:
            def claim_once(self, namespace, identifier, expires_at):
                raise OSError("synthetic replay store outage")
        mock=self.MockPayPal()
        result=process_payment_request(compact_token=token,compact_dpop_proof=proof,
            transaction=self.valid_transaction(),replay_store=BrokenReplayStore(),paypal_api=mock,
            expected_url="https://example.test/pay",merchant_mapping=self.valid_mapping())
        self.assertEqual(result.order_status,"NOT_ATTEMPTED")
        self.assertEqual(result.dpop_status,"FAILED")
        self.assertEqual(mock.calls,[])

    def test_sqlite_replay_claim_survives_store_reinitialization(self):
        path=str(Path(self.tmp.name)/"persistent-replay.sqlite3")
        first=SQLiteReplayStore(path)
        expires=time.time()+60
        self.assertTrue(first.claim_once("kyapay","restart-token-jti",expires))
        restarted=SQLiteReplayStore(path)
        self.assertFalse(restarted.claim_once("kyapay","restart-token-jti",expires))

    def test_ambiguous_order_transport_failure_is_unknown_not_failed(self):
        token,proof=self.signed_request()
        # A transport exception may happen after the provider accepted the request.
        mock=self.MockPayPal(error=TimeoutError("synthetic ambiguous provider timeout"))
        result=process_payment_request(compact_token=token,compact_dpop_proof=proof,
            transaction=self.valid_transaction(),replay_store=self.store,paypal_api=mock,
            expected_url="https://example.test/pay",merchant_mapping=self.valid_mapping())
        self.assertEqual(result.order_status,"UNKNOWN")
        self.assertEqual(result.capture_status,"NOT_ATTEMPTED")
        self.assertEqual(len(mock.calls),1)
        self.assertEqual(mock.calls[0]["method"],"create_order")

    def test_order_unknown_response_does_not_claim_capture_success(self):
        token,proof=self.signed_request()
        mock=self.MockPayPal(response={"status":"CREATED"})
        result=process_payment_request(compact_token=token,compact_dpop_proof=proof,
            transaction=self.valid_transaction(),replay_store=self.store,paypal_api=mock,
            expected_url="https://example.test/pay",merchant_mapping=self.valid_mapping())
        self.assertEqual(result.order_status,"UNKNOWN")
        self.assertEqual(result.capture_status,"NOT_ATTEMPTED")
        self.assertEqual(len(mock.calls),1)


    def test_current_entrypoint_contract_is_keyword_only_and_legacy_entrypoint_is_absent(self):
        """Old positional calls fail before any adapter can be invoked."""
        import inspect
        import main_public

        signature = inspect.signature(process_payment_request)
        self.assertTrue(all(
            parameter.kind is inspect.Parameter.KEYWORD_ONLY
            for parameter in signature.parameters.values()
        ))
        self.assertFalse(hasattr(main_public, "execute_safe_payment"))
        mock = self.MockPayPal()
        with self.assertRaises(TypeError):
            process_payment_request("legacy-token", "legacy-proof", self.valid_transaction(),
                                    self.store, mock, "POST", "https://example.test/pay")
        self.assertEqual(mock.calls, [])

    def test_runtime_modules_have_no_direct_paypal_sdk_or_capture_bypass(self):
        """Only the guarded dispatcher may call the injected create-order adapter."""
        import ast
        root = Path(__file__).resolve().parent
        runtime_files = [
            root / name for name in (
                "main_public.py", "trustguard_security.py", "paypal_rest.py",
                "build_pages.py", "deployment_probe.py",
            ) if (root / name).is_file()
        ]
        direct_sdk_modules = {"paypal", "paypalrestsdk", "paypal_agent_toolkit", "paypal_agent"}
        direct_sdk_imports = []
        adapter_calls = []
        capture_calls = []
        for path in runtime_files:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    direct_sdk_imports.extend(alias.name for alias in node.names
                                              if alias.name.split(".")[0].lower() in direct_sdk_modules)
                elif isinstance(node, ast.ImportFrom):
                    if node.module and node.module.split(".")[0].lower() in direct_sdk_modules:
                        direct_sdk_imports.append(node.module)
                elif isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Attribute) and func.attr == "run":
                        keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg}
                        method = keywords.get("method")
                        if isinstance(method, ast.Constant) and method.value == "create_order":
                            adapter_calls.append((path.name, node.lineno))
                        if isinstance(method, ast.Constant) and "capture" in str(method.value).lower():
                            capture_calls.append((path.name, node.lineno))
                    if isinstance(func, ast.Attribute) and "capture" in func.attr.lower():
                        capture_calls.append((path.name, node.lineno))
        self.assertEqual(direct_sdk_imports, [])
        self.assertEqual(adapter_calls, [("main_public.py", next(
            node.lineno for node in ast.walk(ast.parse((root / "main_public.py").read_text(encoding="utf-8")))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "run"
        ))])
        self.assertEqual(capture_calls, [])



if __name__=="__main__": unittest.main()
