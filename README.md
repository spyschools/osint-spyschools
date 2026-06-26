# 🕵️ OSINT SpySchools

<p align="center">
  <img src="https://img.shields.io/badge/version-v2.0%202026-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/shell-bash-blue?style=for-the-badge&logo=gnu-bash" />
  <img src="https://img.shields.io/badge/license-MIT-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=for-the-badge" />
</p>

<p align="center">
  Toolkit OSINT berbasis terminal untuk investigasi domain, IP, HTTP, dan metadata file — open source, ringan, dan siap pakai.
</p>

---

## 🔍 Tentang

**OSINT SpySchools** adalah toolkit open-source berbasis Bash untuk aktivitas intelijen sumber terbuka (OSINT). Dirancang untuk analis keamanan, peneliti, dan siapa saja yang ingin menggali informasi publik secara cepat dan efisien dari terminal.

---

## 🛠️ Tools yang Digunakan

| Kategori | Tools |
|---|---|
| 🌐 Domain & IP | WHOIS / RDAP |
| 🔎 DNS | Dig, nslookup |
| 📜 Sertifikat | crt.sh |
| 📸 Arsip Web | Wayback Machine |
| 🔒 Keamanan HTTP | Header HTTP |
| 🛡️ Enkripsi | Info TLS/SSL |
| 📷 Media | Analisis Foto |
| 📁 Metadata | Metadata File (EXIF, dll.) |

---

## ⚙️ Instalasi

```bash
$ git clone https://github.com/spyschools/osint-spyschools.git
$ cd osint-spyschools
$ chmod +x osint_toolkit.sh
```

---

## 🚀 Penggunaan

### Mode Langsung (CLI)

```bash
# Analisis domain
$ ./osint_toolkit.sh domain example.com

# Analisis IP
$ ./osint_toolkit.sh ip 1.1.1.1

# Analisis header HTTP
$ ./osint_toolkit.sh http https://example.com

# Analisis metadata file / foto
$ ./osint_toolkit.sh file ./foto.jpg
```

### 🖥️ Mode Interaktif (Menu)

Jalankan tanpa argumen untuk masuk ke mode menu interaktif:

```bash
$ ./osint_toolkit.sh
```

---

## 📄 Output Laporan

Toolkit ini mendukung output laporan dalam format **TXT** maupun **Markdown (`.md`)**.

Gunakan opsi `--md` di depan perintah untuk menghasilkan laporan Markdown:

```bash
$ ./osint_toolkit.sh --md domain example.com
$ ./osint_toolkit.sh --md ip 1.1.1.1
$ ./osint_toolkit.sh --md http https://example.com
$ ./osint_toolkit.sh --md file ./foto.jpg
```

> 📁 Laporan otomatis tersimpan dengan nama seperti:
> `osint_report_20250904_123456.md`

---

## 🆕 VERSI V2 — 2026

Versi terbaru dengan peningkatan performa dan fitur tambahan:

```bash
# Analisis domain
$ ./osint_toolkit_v2.sh domain example.com

# Analisis IP
$ ./osint_toolkit_v2.sh ip 1.1.1.1

# Analisis header HTTP
$ ./osint_toolkit_v2.sh http https://example.com

# Analisis metadata file / foto
$ ./osint_toolkit_v2.sh file ./foto.jpg
```

### Mode Interaktif V2

```bash
$ ./osint_toolkit_v2.sh
```

### Output Laporan V2

```bash
$ ./osint_toolkit_v2.sh --md domain example.com
```

> 📁 Hasil tersimpan otomatis ke file dengan timestamp, misalnya:
> `osint_report_v2_20260101_090000.md`

---

## 📂 Struktur Proyek

```
osint-spyschools/
├── osint_toolkit.sh        # Toolkit versi utama
├── osint_toolkit_v2.sh     # Toolkit versi V2 2026
├── README.md
└── reports/                # Folder output laporan (auto-generated)
```

---

## ⚠️ Disclaimer

> Tools ini dibuat **hanya untuk tujuan edukasi dan penelitian keamanan yang sah**.
> Penggunaan terhadap target tanpa izin adalah **ilegal dan tidak etis**.
> Pengguna sepenuhnya bertanggung jawab atas penggunaan toolkit ini.

---

## 👤 Author

**SpySchools**
- GitHub: [@spyschools](https://github.com/spyschools)

---

<p align="center">
  Made with ❤️ for the OSINT community
</p>
