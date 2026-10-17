# PayPal AI Trust Engine

Sistem keamanan berlapis untuk transaksi Agen AI dengan PayPal.

## 🌐 Live Dashboard Demo
Klik tautan berikut untuk melihat dashboard interaktif secara langsung:
👉 **[PayPal AI Trust Engine Dashboard](https://antonytampubolon2-cell.github.io/paypal-ai-trust-engine-v2/dashboard_v2.html)**



## Latar Belakang Masalah

Ketika agen AI diberi kemampuan untuk bertransaksi dengan uang pengguna, muncul pertanyaan kritis:
- Bagaimana memastikan agen AI benar-benar terautentikasi?
- Bagaimana mencegah token yang dicuri digunakan ulang?
- Bagaimana menegakkan batas kewenangan agen?

PayPal AI Trust Engine menjawab pertanyaan-pertanyaan ini dengan **TrustGuard Agent** — sebuah gerbang keamanan yang memverifikasi setiap permintaan transaksi sebelum diteruskan ke PayPal.

## Arsitektur Keamanan

| Lapisan | Komponen | Status |
|---|---|---|
| 1 | KYAPay Token Verifier | ✅ Berfungsi (verifikasi berbasis klaim) |
| 2 | JTI Anti-Replay Cache | ✅ Berfungsi |
| 3 | DPoP Verifier (RFC 9449) | ⚠️ Sebagian (verifikasi klaim, bukan signature) |
| 4 | TrustGuard Agent | ✅ Berfungsi |

**Catatan Jujur:** Implementasi saat ini fokus pada **verifikasi berbasis klaim**. Verifikasi tanda tangan kriptografis penuh (JWT signature) dan integrasi AI Agent nyata sedang dalam pengembangan.

## Bukti Transaksi End-to-End

Tiga order berhasil dibuat di PayPal Sandbox sebagai bukti integrasi:

| Order ID | Status PayPal | Keterangan |
|---|---|---|
| `7R3064957MB0759941` | PAYER_ACTION_REQUIRED | Order dibuat, menunggu persetujuan |
| `3HD92730V0626752B` | PAYER_ACTION_REQUIRED | Order dibuat, menunggu persetujuan |
| `8RJ05941XL2772705` | PAYER_ACTION_REQUIRED | Order dibuat, menunggu persetujuan |

**Catatan:** Status `PAYER_ACTION_REQUIRED` berarti order berhasil dibuat, tetapi pembayaran belum selesai (menunggu persetujuan pembeli). Proses `capture_order` belum diimplementasikan.

## Cara Menjalankan

1. Install dependensi:
