import os
import jwt
import math
from urllib.parse import urlsplit, urlunsplit

# Kredensial dibaca dari environment, bukan ditulis di kode.
PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET")

toolkit = None
tools = []

if PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET:
    from paypal_agent_toolkit.openai.toolkit import PayPalToolkit
    from paypal_agent_toolkit.shared.configuration import Configuration, Context

    configuration = Configuration(
        actions={
            "orders": {
                "create": True,
                "get": True,
                "capture": False
            }
        },
        context=Context(sandbox=True)
    )

    toolkit = PayPalToolkit(
        client_id=PAYPAL_CLIENT_ID,
        secret=PAYPAL_CLIENT_SECRET,
        configuration=configuration
    )

    tools = toolkit.get_tools()
    print("PayPal Agent Toolkit berhasil diinisialisasi.")
    print(f"Jumlah tools tersedia: {len(tools)}")
else:
    print("Mode aman: kredensial belum dikonfigurasi.")
    print("PayPal belum diinisialisasi.")
    # ==========================================
# MODUL KEAMANAN: TRUSTGUARD AGENT
# ==========================================

import time
import uuid

# 1. Replay Cache Sederhana (Pengganti Redis untuk saat ini)
class JtiReplayCache:
    def __init__(self):
        self.cache = {}

    def is_valid(self, jti, exp_time):
        current_time = time.time()
        self.cache = {k: v for k, v in self.cache.items() if v > current_time}
        if jti in self.cache:
            return False
        self.cache[jti] = exp_time
        return True

replay_cache = JtiReplayCache()

# 2. Fungsi Verifikasi KYAPay Token (Simulasi)
def verify_kyapay_token(token_jwt):
    if not isinstance(token_jwt, str) or token_jwt.count(".") != 2:
        return {
            "valid": False,
            "reason": "Token harus berupa JWT bertanda tangan."
        }

    public_key = os.getenv(
        "TRUSTGUARD_KYAPAY_PUBLIC_KEY", ""
    ).replace("\\n", "\n")

    issuer = os.getenv("TRUSTGUARD_KYAPAY_ISSUER", "")
    audience = os.getenv("TRUSTGUARD_KYAPAY_AUDIENCE", "")
    algorithm = os.getenv("TRUSTGUARD_KYAPAY_ALGORITHM", "")

    if not public_key or not issuer or not audience:
        return {
            "valid": False,
            "reason": "Konfigurasi verifikasi KYAPay belum lengkap."
        }

    if algorithm not in {"ES256", "RS256"}:
        return {
            "valid": False,
            "reason": "Algoritma tanda tangan belum dikonfigurasi."
        }

    try:
        claims = jwt.decode(
            token_jwt,
            public_key,
            algorithms=[algorithm],
            issuer=issuer,
            audience=audience,
            options={
                "require": [
                    "iss", "sub", "aud", "exp", "jti",
                    "delegation_grant", "cnf"
                ]
            }
        )
    except jwt.PyJWTError:
        return {
            "valid": False,
            "reason": "Tanda tangan atau klaim token tidak valid."
        }

    grant = claims.get("delegation_grant")
    if not isinstance(grant, dict):
        return {
            "valid": False,
            "reason": "Delegation grant tidak valid."
        }

    spend = grant.get("max_spend")
    valid_until = grant.get("valid_until")
    merchants = grant.get("allowed_merchants")
    allowed_currency = grant.get("currency")
    if (
    not isinstance(allowed_currency, str)
    or not allowed_currency
    or allowed_currency != allowed_currency.upper()
):
     return {
        "valid": False,
        "reason": "Mata uang dalam delegation grant tidak valid."
    }
    cnf = claims.get("cnf")

    if (
        isinstance(spend, bool)
        or not isinstance(spend, (int, float))
        or not math.isfinite(spend)
        or spend <= 0
    ):
        return {
            "valid": False,
            "reason": "Batas pengeluaran tidak valid."
        }

    if (
        isinstance(valid_until, bool)
        or not isinstance(valid_until, (int, float))
        or not math.isfinite(valid_until)
        or valid_until <= time.time()
    ):
        return {
            "valid": False,
            "reason": "Delegation grant kedaluwarsa atau tidak valid."
        }

    if (
        not isinstance(merchants, list)
        or not merchants
        or any(not isinstance(m, str) or not m for m in merchants)
    ):
        return {
            "valid": False,
            "reason": "Daftar merchant yang diizinkan tidak valid."
        }

    if not isinstance(cnf, dict) or not isinstance(cnf.get("jkt"), str) or not cnf["jkt"]:
        return {
            "valid": False,
            "reason": "Pengikatan kunci DPoP tidak tersedia."
        }

    # Tolak token KYAPay yang digunakan kembali
    token_jti = claims.get("jti")
    token_exp = claims.get("exp")

    if not isinstance(token_jti, str) or not token_jti:
        return {
            "valid": False,
            "reason": "Klaim jti token tidak valid."
        }

    if not replay_cache.is_valid(token_jti, token_exp):
        return {
            "valid": False,
            "reason": "Replay KYAPay terdeteksi."
        }
    return {
        "valid": True,
        "reason": "Tanda tangan dan klaim token berhasil diverifikasi.",
        "claims": claims
    }




# ==========================================
# MODUL KEAMANAN: DPoP (Demonstrating Proof-of-Possession)
# ==========================================
# Referensi: RFC 9449

import hashlib
import base64

class DPoPVerifier:
    def __init__(self):
        self.dpop_replay_cache = {}

    def generate_jwk_thumbprint(self, jwk: dict):
        # Menghitung thumbprint SHA-256 dari JWK (sesuai RFC 7638)
        # Untuk simulasi, kita asumsikan JWK memiliki 'kty', 'crv', 'x', 'y'
        if jwk.get("kty") == "EC":
            canonical = f'{{"crv":"{jwk["crv"]}","kty":"EC","x":"{jwk["x"]}","y":"{jwk["y"]}"}}'
        else:
            return None
        
        sha256 = hashlib.sha256(canonical.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(sha256).decode('utf-8').rstrip('=')

    def verify_dpop_proof(
        self,
        dpop_proof,
        token_cnf_jkt,
        expected_method,
        expected_url,
        access_token
    ):
        def reject(reason):
            return {"valid": False, "reason": reason}

        # 1. Proof harus berupa JWT bertanda tangan
        if not isinstance(dpop_proof, str) or dpop_proof.count(".") != 2:
            return reject("DPoP proof harus berupa JWT bertanda tangan.")

        if not isinstance(token_cnf_jkt, str) or not token_cnf_jkt:
            return reject("cnf.jkt tidak tersedia.")

        if not isinstance(access_token, str) or not access_token:
            return reject("Access token tidak tersedia untuk pemeriksaan ath.")

        # 2. Periksa header JWT
        try:
            header = jwt.get_unverified_header(dpop_proof)
        except jwt.PyJWTError:
            return reject("Header DPoP tidak valid.")

        if header.get("typ") != "dpop+jwt":
            return reject("Header typ DPoP tidak valid.")

        if header.get("alg") != "ES256":
            return reject("Algoritma DPoP tidak diizinkan.")

        jwk = header.get("jwk")
        if not isinstance(jwk, dict):
            return reject("JWK publik tidak tersedia.")

        if (
            jwk.get("kty") != "EC"
            or jwk.get("crv") != "P-256"
            or not isinstance(jwk.get("x"), str)
            or not isinstance(jwk.get("y"), str)
            or "d" in jwk
        ):
            return reject("JWK publik EC P-256 tidak valid.")

        # 3. Verifikasi tanda tangan kriptografis
        try:
            public_key = jwt.PyJWK.from_dict(
                jwk, algorithm="ES256"
            ).key

            claims = jwt.decode(
                dpop_proof,
                public_key,
                algorithms=["ES256"],
                options={
                    "require": ["jti", "htm", "htu", "iat"],
                    "verify_aud": False
                }
            )
        except (jwt.PyJWTError, ValueError, TypeError):
            return reject("Tanda tangan atau klaim DPoP tidak valid.")

        # 4. Cocokkan thumbprint kunci dengan cnf.jkt
        try:
            thumbprint = self.generate_jwk_thumbprint(jwk)
        except (KeyError, TypeError, ValueError):
            return reject("Thumbprint JWK tidak dapat dihitung.")

        if not thumbprint or thumbprint != token_cnf_jkt:
            return reject("Kunci DPoP tidak cocok dengan cnf.jkt.")

        # 5. Cocokkan metode HTTP
        if (
            not isinstance(expected_method, str)
            or not isinstance(claims.get("htm"), str)
            or claims["htm"] != expected_method.upper()
        ):
            return reject("Metode HTTP DPoP tidak cocok.")

        # 6. Cocokkan URI target
        try:
            proof_uri = urlsplit(claims["htu"])
            target_uri = urlsplit(expected_url)

            if (
                proof_uri.scheme not in ("https", "http")
                or not proof_uri.netloc
                or proof_uri.username is not None
                or proof_uri.password is not None
                or proof_uri.query
                or proof_uri.fragment
                or target_uri.scheme not in ("https", "http")
                or not target_uri.netloc
                or target_uri.username is not None
                or target_uri.password is not None
            ):
                return reject("URI DPoP tidak valid.")

            proof_htu = urlunsplit((
                proof_uri.scheme, proof_uri.netloc,
                proof_uri.path, "", ""
            ))
            target_htu = urlunsplit((
                target_uri.scheme, target_uri.netloc,
                target_uri.path, "", ""
            ))
        except (TypeError, ValueError):
            return reject("URI DPoP tidak dapat diperiksa.")

        if proof_htu != target_htu:
            return reject("URI DPoP tidak cocok.")

        # 7. Periksa waktu pembuatan dan JTI
        iat = claims.get("iat")
        jti = claims.get("jti")
        now = time.time()

        if (
            isinstance(iat, bool)
            or not isinstance(iat, (int, float))
            or now - iat > 300
            or iat > now + 30
        ):
            return reject("Waktu pembuatan proof DPoP tidak valid.")

        if not isinstance(jti, str) or not jti:
            return reject("JTI DPoP tidak valid.")

        # 8. Periksa ath terhadap access token
        try:
            token_hash = hashlib.sha256(
                access_token.encode("ascii")
            ).digest()
            expected_ath = base64.urlsafe_b64encode(
                token_hash
            ).decode("ascii").rstrip("=")
        except (UnicodeEncodeError, TypeError):
            return reject("Access token tidak valid untuk pemeriksaan ath.")

        if claims.get("ath") != expected_ath:
            return reject("ath DPoP tidak cocok dengan access token.")

        # 9. Tolak proof yang digunakan ulang
        self.dpop_replay_cache = {
            key: expiry
            for key, expiry in self.dpop_replay_cache.items()
            if expiry > now
        }

        if jti in self.dpop_replay_cache:
            return reject("Replay DPoP terdeteksi.")

        self.dpop_replay_cache[jti] = now + 300

        return {
            "valid": True,
            "reason": "Tanda tangan dan klaim DPoP berhasil diverifikasi."
        }



dpop_verifier = DPoPVerifier()


# ==========================================
# TRUSTGUARD AGENT (LOGIKA UTAMA)
# ==========================================
class TrustGuardAgent:
    def __init__(self, toolkit, dpop_verifier):
        self.toolkit = toolkit
        self.dpop_verifier = dpop_verifier

    def process_payment_request(
        self, token_jwt, dpop_proof, method, url, amount, currency, merchant_id
    ):
        print("\n" + "=" * 50)
        print("[TrustGuard] Memproses permintaan transaksi...")

        # 1. Verifikasi tanda tangan dan klaim KYAPay
        kya_result = verify_kyapay_token(token_jwt)

        if not isinstance(kya_result, dict) or not kya_result.get("valid"):
            reason = (
                kya_result.get("reason", "Verifikasi KYAPay gagal.")
                if isinstance(kya_result, dict)
                else "Hasil verifikasi KYAPay tidak valid."
            )
            print(f"[TrustGuard] DITOLAK: {reason}")
            return False

        # Gunakan klaim yang sudah diverifikasi, bukan payload mentah
        claims = kya_result.get("claims")

        if not isinstance(claims, dict):
            print("[TrustGuard] DITOLAK: Klaim terverifikasi tidak tersedia.")
            return False

        # Periksa batas delegasi sebelum membuat pesanan.
        grant = claims.get('delegation_grant')
        from decimal import Decimal, InvalidOperation
        allowed_merchants = grant.get('allowed_merchants') if isinstance(grant, dict) else None
        try:
            requested_amount = Decimal(str(amount))
            max_spend = Decimal(str(grant.get('max_spend'))) if isinstance(grant, dict) else Decimal('NaN')
        except (InvalidOperation, ValueError, TypeError):
            print('[TrustGuard] DITOLAK: batas delegasi tidak valid.')
            return False
        if (
            not requested_amount.is_finite()
            or requested_amount <= 0
            or not max_spend.is_finite()
            or requested_amount > max_spend
            or not isinstance(currency, str)
            or not isinstance(grant, dict)
            or currency != grant.get('currency')
            or not isinstance(merchant_id, str)
            or not merchant_id
            or not isinstance(allowed_merchants, list)
            or merchant_id not in allowed_merchants
        ):
            print('[TrustGuard] DITOLAK: order tidak sesuai delegation grant.')
            return False

        # 2. Pastikan pengikatan kunci DPoP tersedia
        cnf = claims.get("cnf")

        if (
            not isinstance(cnf, dict)
            or not isinstance(cnf.get("jkt"), str)
            or not cnf["jkt"]
        ):
            print("[TrustGuard] DITOLAK: Pengikatan kunci DPoP tidak tersedia.")
            return False

        # 3. Verifikasi DPoP; harus gagal tertutup jika proof belum sah
        dpop_result = self.dpop_verifier.verify_dpop_proof(
    dpop_proof,
    cnf["jkt"],
    method,
    url,
    token_jwt
)

        if (
            not isinstance(dpop_result, dict)
            or not dpop_result.get("valid")
        ):
            reason = (
                dpop_result.get("reason", "Verifikasi DPoP gagal.")
                if isinstance(dpop_result, dict)
                else "Hasil verifikasi DPoP tidak valid."
            )
            print(f"[TrustGuard] DITOLAK: {reason}")
            return False

        print("[TrustGuard] Verifikasi KYAPay dan DPoP berhasil.")
        return True

# ==========================================
# UJI COBA INTEGRASI TRUSTGUARD AGENT
# ==========================================
# Pengujian simulasi dinonaktifkan agar tidak
# berjalan otomatis saat file dibuka.
# Verifikasi token dan DPoP yang sesungguhnya
# harus diuji secara terpisah.

# ==========================================
# INTEGRASI END-TO-END: TRUSTGUARD + PAYPAL
# ==========================================
def normalize_toolkit_items(items, currency):
    """Normalize local item inputs to the PayPal Orders v2 item schema."""
    from decimal import Decimal, InvalidOperation

    if currency != "USD":
        raise ValueError("Prototipe hanya mendukung USD.")
    if not isinstance(items, list) or not 1 <= len(items) <= 50:
        raise ValueError("Order harus memiliki 1 sampai 50 item.")

    output = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Format item tidak valid.")
        name = item.get("name")
        qty = item.get("quantity", 1)
        raw = item.get("item_cost", item.get("unit_price"))
        if raw is None:
            raw = item.get("unit_amount")
            if isinstance(raw, dict):
                raw = raw.get("value")
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 127:
            raise ValueError("Nama item wajib diisi dan maksimal 127 karakter.")
        if isinstance(qty, bool) or not isinstance(qty, int) or not 1 <= qty <= 10000:
            raise ValueError("Kuantitas harus berupa bilangan bulat 1-10000.")
        try:
            cost = Decimal(str(raw))
            tax = Decimal(str(item.get("tax_percent", 0)))
            given_total = item.get("item_total")
            given_total = Decimal(str(given_total)) if given_total is not None else None
        except (InvalidOperation, ValueError, TypeError):
            raise ValueError("Harga, total, atau pajak tidak valid.") from None
        if not cost.is_finite() or cost <= 0 or cost.as_tuple().exponent < -2:
            raise ValueError("Harga harus positif dan maksimal dua desimal.")
        if not tax.is_finite() or tax != 0:
            raise ValueError("Prototipe ini hanya mendukung pajak 0%.")
        total = (cost * qty).quantize(Decimal("0.01"))
        if given_total is not None and (not given_total.is_finite() or given_total != total):
            raise ValueError("Total item tidak cocok dengan harga dan kuantitas.")
        output.append({
            "name": name.strip(),
            "quantity": str(qty),
            "unit_amount": {
                "currency_code": currency,
                "value": format(cost.quantize(Decimal("0.01")), ".2f"),
            },
        })
    return output


def execute_safe_payment(agent, token_jwt, dpop_proof, method, url, currency, items):
    """Validate then create a PayPal Orders v2 order only; never capture."""
    print("\n" + "="*60)
    print("ALUR END-TO-END: VERIFIKASI TRUSTGUARD -> PAYPAL ORDER")
    print("="*60)

    try:
        items = normalize_toolkit_items(items, currency)
    except ValueError as exc:
        print('[E2E] Item tidak valid; diblokir sebelum PayPal.')
        return {'status': 'BLOCKED', 'reason': str(exc)}

    from decimal import Decimal
    order_total = sum(
        Decimal(item["unit_amount"]["value"]) * int(item["quantity"])
        for item in items
    )
    merchant_id = os.getenv('TRUSTGUARD_MERCHANT_ID', '')
    is_safe = agent.process_payment_request(
        token_jwt, dpop_proof, method, url, order_total, currency, merchant_id
    )
    if not is_safe:
        print("[E2E] DITOLAK oleh TrustGuard; PayPal tidak dipanggil.")
        return {"status": "BLOCKED", "reason": "Verifikasi keamanan gagal"}

    amount_text = format(order_total.quantize(Decimal("0.01")), ".2f")
    purchase_unit = {
        "amount": {
            "currency_code": currency,
            "value": amount_text,
            "breakdown": {
                "item_total": {"currency_code": currency, "value": amount_text}
            },
        },
        "items": items,
    }
    params = {"intent": "AUTHORIZE", "purchase_units": [purchase_unit]}
    try:
        paypal_api = agent.toolkit.get_paypal_api()
        print("[E2E] Memanggil PayPal create_order; parameter disembunyikan.")
        result = paypal_api.run(method="create_order", params=params)
        parsed_result = __import__("json").loads(result) if isinstance(result, str) else result
        order_id = parsed_result.get("id") if isinstance(parsed_result, dict) else None
        if not isinstance(order_id, str) or not order_id.strip():
            print("[E2E] Respons provider tidak memiliki Order ID yang dapat diverifikasi; status UNKNOWN.")
            return {"status": "UNKNOWN", "reason": "Respons PayPal tidak memuat Order ID yang dapat diverifikasi"}
        print("[E2E] Order dibuat; pembayaran belum ditangkap.")
        return {"status": "ORDER_CREATED", "order_id": order_id}
    except Exception as exc:
        print(f"[E2E] Hasil order tidak dapat dipastikan ({type(exc).__name__}); status UNKNOWN.")
        return {
            "status": "UNKNOWN",
            "reason": "Hasil permintaan PayPal ambigu; jangan mengulang otomatis tanpa rekonsiliasi",
        }


# UJI COBA END-TO-END PERTAMA DINONAKTIFKAN
# ==========================================
# Pengujian transaksi tidak dijalankan otomatis.
# Token dan bukti DPoP pada pengujian sebelumnya
# hanya berupa data simulasi, bukan bukti kriptografis.
# Lakukan pengujian keamanan secara terpisah
# sebelum mengaktifkan integrasi PayPal Sandbox.


def main():
    import json
    names = ("TRUSTGUARD_KYAPAY_TOKEN", "TRUSTGUARD_DPOP_PROOF",
             "TRUSTGUARD_MERCHANT_ID", "TRUSTGUARD_TARGET_URL")
    v = {n: os.getenv(n, "").strip() for n in names}
    missing = [n for n in names if not v[n]]
    if missing:
        print("[TrustGuard] MODE AMAN; variabel belum diatur: " + ", ".join(missing))
        print("[TrustGuard] Jangan bagikan token atau secret ke chat.")
        return 2
    if not PAYPAL_CLIENT_ID or not PAYPAL_CLIENT_SECRET or toolkit is None:
        print("[TrustGuard] Kredensial PayPal Sandbox belum siap."); return 2
    if os.getenv("TRUSTGUARD_CONFIRM_SANDBOX_ORDER", "") != "CREATE SANDBOX ORDER":
        print("[TrustGuard] MODE PERSIAPAN: tidak ada order dibuat.")
        print('Untuk mengonfirmasi order Sandbox: set "TRUSTGUARD_CONFIRM_SANDBOX_ORDER=CREATE SANDBOX ORDER"')
        return 0
    try:
        items = json.loads(os.getenv("TRUSTGUARD_ORDER_ITEMS",
            '[{"name":"TrustGuard Sandbox Demo Item","quantity":1,"item_cost":"1.00"}]'))
        if not isinstance(items, list) or not items: raise ValueError("daftar item kosong/tidak valid")
        currency = os.getenv("TRUSTGUARD_CURRENCY", "USD").strip().upper()
        method = os.getenv("TRUSTGUARD_METHOD", "POST").strip().upper()
        if currency != "USD" or method != "POST": raise ValueError("prototipe hanya USD dan POST")
        agent = TrustGuardAgent(toolkit, dpop_verifier)
        r = execute_safe_payment(agent, v[names[0]], v[names[1]], method,
                                 v[names[3]], currency, items)
    except Exception as e:
        print("[TrustGuard] Gagal aman: " + type(e).__name__); return 1
    if isinstance(r, dict) and r.get("status") == "ORDER_CREATED":
        print("[TrustGuard] ORDER_CREATED; ID=" + str(r.get("order_id", "tidak tersedia")))
        print("[TrustGuard] Pembayaran belum ditangkap; capture nonaktif."); return 0
    print("[TrustGuard] Status: " + str(r.get("status", "ERROR") if isinstance(r, dict) else "ERROR"))
    print("[TrustGuard] Tidak ada konfirmasi keberhasilan order."); return 1

if __name__ == "__main__":
    raise SystemExit(main())
