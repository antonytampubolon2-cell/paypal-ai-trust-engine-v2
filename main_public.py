import os
from paypal_agent_toolkit.openai.toolkit import PayPalToolkit
from paypal_agent_toolkit.shared.configuration import Configuration, Context

# --- MASUKKAN KREDENSIAL BARU ANDA DI SINI ---
os.environ["PAYPAL_CLIENT_ID"] = "MASUKKAN_CLIENT_ID_ANDA_DI_SINI"
os.environ["PAYPAL_CLIENT_SECRET"] = "MASUKKAN_SECRET_ANDA_DI_SINI"
# ---------------------------------------------

configuration = Configuration(
    actions={"orders": {"create": True, "get": True, "capture": True}},
    context=Context(sandbox=True)
)

toolkit = PayPalToolkit(
    client_id=os.environ["PAYPAL_CLIENT_ID"],
    secret=os.environ["PAYPAL_CLIENT_SECRET"],
    configuration=configuration
)

tools = toolkit.get_tools()
print("PayPal Agent Toolkit berhasil diinisialisasi!")
print(f"Jumlah tools yang tersedia: {len(tools)}")
for tool in tools:
    print(f"   - {tool.name}")
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
def verify_kyapay_token(token_payload: dict):
    print("\n[TrustGuard] Memverifikasi KYAPay Token...")
    required_claims = ["iss", "sub", "aud", "exp", "jti", "delegation_grant"]
    for claim in required_claims:
        if claim not in token_payload:
            return {"valid": False, "reason": f"Klaim '{claim}' tidak ditemukan"}

    if token_payload["exp"] < time.time():
        return {"valid": False, "reason": "Token sudah kedaluwarsa"}

    grant = token_payload["delegation_grant"]
    if grant.get("max_spend", 0) <= 0:
        return {"valid": False, "reason": "max_spend tidak valid"}
    if grant.get("valid_until", 0) < time.time():
        return {"valid": False, "reason": "Delegation grant sudah kedaluwarsa"}

    if not replay_cache.is_valid(token_payload["jti"], token_payload["exp"]):
        return {"valid": False, "reason": "Replay attack terdeteksi! JTI sudah digunakan."}

    return {"valid": True, "reason": "Token valid dan aman"}

# ==========================================
# UJI COBA MODUL KEAMANAN
# ==========================================
print("\n--- Memulai Uji Coba TrustGuard Agent ---")

mock_token = {
    "iss": "https://api.paypal-ai-trust-engine.com",
    "sub": "user-12345",
    "aud": "paypal-merchant-api",
    "exp": time.time() + 3600,
    "jti": str(uuid.uuid4()),
    "delegation_grant": {
        "allowed_merchants": ["MERCHANT-123"],
        "max_spend": 10000,
        "currency": "USD",
        "valid_until": time.time() + 1800
    }
}

print(f"\nUji 1: Token Valid")
hasil1 = verify_kyapay_token(mock_token)
print(f"Hasil: {hasil1}")

print(f"\nUji 2: Replay Attack (Token yang sama)")
hasil2 = verify_kyapay_token(mock_token)
print(f"Hasil: {hasil2}")

mock_token_expired = mock_token.copy()
mock_token_expired["exp"] = time.time() - 10
mock_token_expired["jti"] = str(uuid.uuid4())
print(f"\nUji 3: Token Kedaluwarsa")
hasil3 = verify_kyapay_token(mock_token_expired)
print(f"Hasil: {hasil3}")

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

    def verify_dpop_proof(self, dpop_proof: dict, token_cnf_jkt: str, expected_method: str, expected_url: str):
        print("\n[TrustGuard] Memverifikasi DPoP Proof...")
        
        # 1. Validasi klaim wajib DPoP
        required = ["htm", "htu", "jti", "jwk"]
        for claim in required:
            if claim not in dpop_proof:
                return {"valid": False, "reason": f"DPoP claim '{claim}' tidak ditemukan"}

        # 2. Validasi HTTP Method dan URI
        if dpop_proof["htm"] != expected_method:
            return {"valid": False, "reason": "DPoP htm mismatch"}
        if dpop_proof["htu"] != expected_url:
            return {"valid": False, "reason": "DPoP htu mismatch"}

        # 3. Validasi binding: thumbprint DPoP key harus sama dengan cnf.jkt di token
        dpop_thumbprint = self.generate_jwk_thumbprint(dpop_proof["jwk"])
        if dpop_thumbprint != token_cnf_jkt:
            return {"valid": False, "reason": "DPoP key tidak cocok dengan cnf.jkt token"}

        # 4. Anti-Replay untuk DPoP Proof itu sendiri
        current_time = time.time()
        self.dpop_replay_cache = {k: v for k, v in self.dpop_replay_cache.items() if v > current_time}
        if dpop_proof["jti"] in self.dpop_replay_cache:
            return {"valid": False, "reason": "Replay DPoP proof terdeteksi!"}
        self.dpop_replay_cache[dpop_proof["jti"]] = current_time + 300  # Berlaku 5 menit

        return {"valid": True, "reason": "DPoP proof valid dan terikat dengan aman"}

# ==========================================
# UJI COBA MODUL DPoP
# ==========================================
print("\n--- Memulai Uji Coba DPoP Verifier ---")

dpop_verifier = DPoPVerifier()

# Simulasi JWK dari agen AI
mock_jwk = {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
}

# Hitung thumbprint untuk digunakan sebagai cnf.jkt
mock_jkt = dpop_verifier.generate_jwk_thumbprint(mock_jwk)
print(f"Simulasi JWK Thumbprint (cnf.jkt): {mock_jkt}")

# Simulasi DPoP Proof yang valid
mock_dpop_proof = {
    "htm": "POST",
    "htu": "https://api.merchant.com/pay",
    "jti": str(uuid.uuid4()),
    "jwk": mock_jwk
}

# Uji 1: DPoP Valid
print("\nUji 1: DPoP Proof Valid")
hasil_dpop1 = dpop_verifier.verify_dpop_proof(
    mock_dpop_proof, mock_jkt, "POST", "https://api.merchant.com/pay"
)
print(f"Hasil: {hasil_dpop1}")

# Uji 2: DPoP Replay (Proof yang sama digunakan lagi)
print("\nUji 2: DPoP Replay Attack")
hasil_dpop2 = dpop_verifier.verify_dpop_proof(
    mock_dpop_proof, mock_jkt, "POST", "https://api.merchant.com/pay"
)
print(f"Hasil: {hasil_dpop2}")

# Uji 3: DPoP dengan URL yang salah (simulasi token dicuri & digunakan di tempat lain)
print("\nUji 3: DPoP URL Mismatch")
mock_dpop_proof_baru = mock_dpop_proof.copy()
mock_dpop_proof_baru["jti"] = str(uuid.uuid4())  # JTI baru agar tidak terdeteksi replay
hasil_dpop3 = dpop_verifier.verify_dpop_proof(
    mock_dpop_proof_baru, mock_jkt, "POST", "https://api.penyerang.com/curi"
)
print(f"Hasil: {hasil_dpop3}")

# ==========================================
# TRUSTGUARD AGENT (LOGIKA UTAMA)
# ==========================================
class TrustGuardAgent:
    def __init__(self, toolkit, dpop_verifier):
        self.toolkit = toolkit
        self.dpop_verifier = dpop_verifier

    def process_payment_request(self, token_payload, dpop_proof, method, url):
        print("\n" + "="*50)
        print("[TrustGuard Agent] Memproses permintaan transaksi...")
        
        # 1. Verifikasi KYAPay Token (termasuk JTI Anti-Replay)
        kya_result = verify_kyapay_token(token_payload)
        if not kya_result["valid"]:
            print(f"[TrustGuard Agent] ❌ DITOLAK: {kya_result['reason']}")
            return False

        # 2. Verifikasi DPoP Proof (pengikatan kriptografis)
        cnf_jkt = token_payload.get("cnf", {}).get("jkt", "")
        if not cnf_jkt:
            print("[TrustGuard Agent] ❌ DITOLAK: Klaim 'cnf.jkt' tidak ditemukan di token.")
            return False
            
        dpop_result = self.dpop_verifier.verify_dpop_proof(
            dpop_proof, cnf_jkt, method, url
        )
        if not dpop_result["valid"]:
            print(f"[TrustGuard Agent] ❌ DITOLAK: {dpop_result['reason']}")
            return False

        # 3. Jika semua aman, lanjutkan transaksi
        print("[TrustGuard Agent] ✅ SEMUA VERIFIKASI LULUS. Transaksi aman untuk diproses.")
        # Di sini nanti kita akan memanggil fungsi create_order dari toolkit PayPal
        return True

# ==========================================
# UJI COBA INTEGRASI TRUSTGUARD AGENT
# ==========================================
print("\n--- Memulai Uji Coba Integrasi TrustGuard Agent ---")

# Inisialisasi Agen
trust_guard = TrustGuardAgent(toolkit, dpop_verifier)

# Siapkan data uji (JKT yang benar agar DPoP lolos)
mock_jkt_baru = dpop_verifier.generate_jwk_thumbprint(mock_jwk)

valid_token_payload = {
    "iss": "https://api.paypal-ai-trust-engine.com",
    "sub": "user-12345",
    "aud": "paypal-merchant-api",
    "exp": time.time() + 3600,
    "jti": str(uuid.uuid4()), # JTI baru
    "cnf": {"jkt": mock_jkt_baru},
    "delegation_grant": {
        "allowed_merchants": ["MERCHANT-123"],
        "max_spend": 10000,
        "currency": "USD",
        "valid_until": time.time() + 1800
    }
}

valid_dpop_proof = {
    "htm": "POST",
    "htu": "https://api.merchant.com/pay",
    "jti": str(uuid.uuid4()), # DPoP JTI baru
    "jwk": mock_jwk
}

# Jalankan Uji Coba
print("\nUji Coba: Transaksi dengan Token & DPoP yang Valid")
hasil_akhir = trust_guard.process_payment_request(
    valid_token_payload, valid_dpop_proof, "POST", "https://api.merchant.com/pay"
)
print(f"Status Akhir: {'BERHASIL' if hasil_akhir else 'GAGAL'}")

# ==========================================
# INTEGRASI END-TO-END: TRUSTGUARD + PAYPAL
# ==========================================
def execute_safe_payment(agent, token_payload, dpop_proof, method, url, currency, items):
    print("\n" + "="*60)
    print("ALUR END-TO-END: VERIFIKASI TRUSTGUARD -> PAYPAL ORDER")
    print("="*60)
    
    # TAHAP 1: Verifikasi Keamanan Berlapis
    is_safe = agent.process_payment_request(token_payload, dpop_proof, method, url)
    
    if not is_safe:
        print("\n[E2E] ❌ TRANSAKSI DIBLOKIR oleh TrustGuard.")
        return {"status": "BLOCKED", "reason": "Verifikasi keamanan gagal"}
    
    # TAHAP 2: Panggil PayPal create_order (hanya jika aman)
    print("\n[E2E] ✅ TrustGuard LULUS. Meneruskan ke PayPal create_order...")
    
    try:
        paypal_api = toolkit.get_paypal_api()
        params = {
            "currency_code": currency,
            "items": items
        }
        
        print(f"[E2E] Memanggil PayPal dengan params: {params}")
        result = paypal_api.run(method="create_order", params=params)
        
        print(f"\n[E2E] 📦 RESPONS PAYPAL:")
        print(f"{result}")
        
        return {"status": "SUCCESS", "paypal_response": result}
    
    except Exception as e:
        print(f"\n[E2E] ❌ Gagal memanggil PayPal: {e}")
        return {"status": "ERROR", "reason": str(e)}


# ==========================================
# UJI COBA END-TO-END PERTAMA
# ==========================================
print("\n" + "#"*60)
print("# UJI COBA E2E: TRANSAKSI AMAN KE PAYPAL SANDBOX #")
print("#"*60)

# Buat token baru dengan cnf yang benar
e2e_jkt = dpop_verifier.generate_jwk_thumbprint(mock_jwk)
e2e_token = {
    "iss": "https://api.paypal-ai-trust-engine.com",
    "sub": "user-12345",
    "aud": "paypal-merchant-api",
    "exp": time.time() + 3600,
    "jti": str(uuid.uuid4()),
    "cnf": {"jkt": e2e_jkt},
    "delegation_grant": {
        "allowed_merchants": ["MERCHANT-123"],
        "max_spend": 10000,
        "currency": "USD",
        "valid_until": time.time() + 1800
    }
}

e2e_dpop = {
    "htm": "POST",
    "htu": "https://api.merchant.com/pay",
    "jti": str(uuid.uuid4()),
    "jwk": mock_jwk
}

# Format items sesuai PayPal Orders API v2
e2e_items = [
    {
        "name": "TrustGuard AI Security License",
        "quantity": "1",
        "unit_amount": {
            "currency_code": "USD",
            "value": "50.00"
        },
        "item_cost": 50.00,
        "item_total": 50.00
    }
]

# Jalankan Transaksi E2E Pertama!
hasil_e2e = execute_safe_payment(
    trust_guard,
    e2e_token,
    e2e_dpop,
    "POST",
    "https://api.merchant.com/pay",
    "USD",
    e2e_items
)

print("\n" + "="*60)
print(f"STATUS AKHIR TRANSAKSI: {hasil_e2e['status']}")
print("="*60)
