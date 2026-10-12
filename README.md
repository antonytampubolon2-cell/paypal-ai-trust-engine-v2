# PayPal AI Trust Engine

Sistem keamanan berlapis untuk transaksi Agen AI dengan PayPal.

## Fitur Utama
- **KYAPay Token Verifier** — Validasi identitas agen AI
- **JTI Anti-Replay Cache** — Mencegah penggunaan ulang token
- **DPoP Binding (RFC 9449)** — Pengikatan kriptografis token ke private key agen
- **TrustGuard Agent** — Orkestrator verifikasi berlapis
- **Integrasi PayPal API** — End-to-end transaction verified

## Lapisan Keamanan
| Lapisan | Komponen | Standar |
|---|---|---|
| 1 | KYAPay Token | Draft Skyfire |
| 2 | Anti-Replay (JTI) | RFC 7523 |
| 3 | DPoP Binding | RFC 9449 |
| 4 | TrustGuard Agent | Custom |

## Bukti End-to-End
- **Order ID PayPal Sandbox**: `9E3172696H384860R`
- **Status**: `PAYER_ACTION_REQUIRED`
- **Hasil**: Transaksi berhasil setelah verifikasi TrustGuard

## Cara Menjalankan
1. Install dependensi: `pip install paypal-agent-toolkit openai-agents`
2. Isi kredensial PayPal di `main_public.py`
3. Jalankan: `python main_public.py`

## Kompetisi
Dibuat untuk **PayPal AI Hackathon 2026** (1 Okt - 12 Nov 2026).

## Keunggulan Kompetitif
Proyek ini mengisi celah yang belum tersentuh pemenang 2025: **keamanan transaksi agen AI**. Bukan hanya membuat agen bisa membayar, tetapi memastikan pembayaran itu **aman, terverifikasi, dan terbatas**.
