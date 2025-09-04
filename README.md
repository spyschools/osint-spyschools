# osint-spyschools
Osint Spyschools untuk Linux sebuah Tools memakai sumber publik dan non-sensitif (WHOIS/RDAP, DNS, crt.sh, Wayback, header HTTP, info TLS, metadata file)

$ git clone https://github.com/spyschools/osint-spyschools.git

$ cd osint-spyschools

$ chmod +x osint_toolkit.sh

Contoh:

$ ./osint_toolkit.sh domain example.com

$ ./osint_toolkit.sh ip 1.1.1.1

$ ./osint_toolkit.sh http https://example.com

$ ./osint_toolkit.sh file ./foto.jpg

*menu untuk mode interaktif.
$ ./osint_toolkit.sh

Tool ini bisa menghasilkan laporan dalam TXT atau Markdown (.md).
Cukup jalankan dengan opsi --md di depan, misalnya:

$ ./osint_toolkit.sh --md domain example.com

Hasilnya otomatis tersimpan ke file seperti:
osint_report_20250904_123456.md
