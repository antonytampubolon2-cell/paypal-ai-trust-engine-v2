import os, tempfile, threading, time, unittest, json, hashlib, base64
from pathlib import Path
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
        result=process_payment_request(compact_token=token,compact_dpop_proof=proof,transaction={"merchant":"merchant-1","amount":"12.34","currency":"USD"},replay_store=self.store,paypal_api=mock,expected_url="https://example.test/pay",merchant_mapping={"merchant-1":"PAYPAL-MERCHANT-VERIFIED"})
        self.assertEqual((result.authentication_status,result.policy_status,result.delivery_status),("PASSED","PASSED","ORDER_CREATED"))
        # Creating an order is not proof of a completed payment or capture.
        self.assertNotEqual(result.delivery_status,"SUCCEEDED")
        self.assertEqual(len(mock.calls),1)
        self.assertEqual(mock.calls[0]["method"],"create_order")
        self.assertEqual(mock.calls[0]["params"]["intent"],"AUTHORIZE")
        self.assertNotIn("capture",mock.calls[0]["method"].lower())
        payload=mock.calls[0]["params"]["purchase_units"][0]
        self.assertEqual(payload["payee"]["merchant_id"],"merchant-1")
        self.assertEqual(payload["amount"],{"currency_code":"USD","value":"12.34"})


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

if __name__=="__main__": unittest.main()
