Majalengka Cyber Tester 🚀

![image](https://github.com/user-attachments/assets/50c109e1-62c3-431e-b5a7-9284a990f920)


Majalengka Cyber Tester adalah alat uji keamanan web yang dirancang untuk mengidentifikasi kerentanan dalam aplikasi web. Alat ini melakukan pengumpulan informasi, pemindaian port, perayapan web, pengujian keamanan, dan menghasilkan laporan terperinci.
Fitur Utama 🌟

    🚀 Pengumpulan Informasi  : Mengumpulkan informasi penting tentang URL target.
    🚀 Pemindaian Port        : Memindai port umum untuk mengidentifikasi yang terbuka.
    🚀 Perayapan Web          : Menemukan semua tautan yang dapat diakses di situs web.
    🚀 Pengujian Keamanan     : Melakukan serangkaian pengujian keamanan pada tautan yang ditemukan.
    🚀 Pembuatan Laporan      : Menghasilkan laporan terperinci dari temuan.
    
Instalasi 🔧

Clone repositori atau unduh skrip ini.

Instal paket Python yang diperlukan:

    pip install argparse logging tqdm colorama tabulate jinja2 collections datetime requests BeautifulSoup warnings certifi time retrying tabulate re threading textwrap

Argumen

    <url>: URL target untuk pengujian keamanan.
    --verbose: Mengaktifkan output yang lebih rinci.
    --depth <n>: Kedalaman perayapan (default: 3).
Penggunaan 🛠️
    
    python main.py example.com
    python main.py <url> [--verbose] [--depth <n>]

Output 📋

![image](https://github.com/user-attachments/assets/5d32cc2d-e854-4456-8c38-7e213ea3e93c)



Alat ini memberikan output terperinci dari setiap langkah, termasuk:

    Pengumpulan Informasi      : Menampilkan informasi yang dikumpulkan dalam format tabel.
    Pemindaian Port            : Menampilkan port yang terbuka.
    Perayapan Web              : Menampilkan tautan yang ditemukan.
    Pengujian Keamanan         : Menampilkan kerentanan yang ditemukan.
    Pembuatan Laporan          : Mengkonfirmasi keberhasilan pembuatan laporan.
