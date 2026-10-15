# entropi-password

Alat terminal untuk menganalisis kekuatan password, berjalan **100% lokal**.
Tidak ada koneksi internet, tidak ada penyimpanan, tidak ada pengiriman data.

Alat ini sengaja memisahkan tiga hal yang sering dicampuradukkan:

| Hasil | Artinya | Seberapa bisa dipercaya |
|---|---|---|
| **Entropi generator** | Entropi dari *cara password dibuat* (misalnya dadu atau generator acak) | Entropi sebenarnya, **jika** asumsinya terpenuhi |
| **Skor heuristik** | Estimasi dari pola lemah yang dikenali program | Perkiraan kasar, **bukan** entropi terukur |
| **Estimasi waktu tebak** | Ilustrasi waktu berdasarkan skor heuristik dan laju tebakan contoh | Hanya ilustrasi, bukan prediksi |

Satu string password tidak membawa informasi tentang bagaimana ia dibuat. Karena itu entropi
sebenarnya hanya bisa dihitung kalau kamu menyebutkan cara pembuatannya (opsi `--mode`).

## Privasi dan keamanan

- Hanya memakai library bawaan Python. Tidak ada dependensi yang perlu di-install.
- Tidak ada kode jaringan. Kamu bisa memeriksanya sendiri:

  ```bash
  grep -rnE "socket|urllib|requests|subprocess|http" --include=*.py .
  ```

  Perintah itu harus tidak menghasilkan apa pun.
- Password tidak ditulis ke file atau log, dan tidak ditampilkan ulang di laporan.
  Password hanya ada di memori selama program berjalan.
- Input password disembunyikan secara default (lewat `getpass`).
- Modul `random` hanya dipakai untuk membuat data sintetis pada fitur validasi (dengan seed tetap),
  bukan untuk membuat password.

## Kebutuhan

Python 3.9 atau lebih baru (diuji pada Python 3.12). Tidak perlu `pip install`.

## Struktur

```
entropi_password.py        # program utama (CLI)
entropi/
  charset.py               # analisis ukuran charset
  generators.py            # entropi generator (random-chars, diceware, dst.)
  heuristic.py             # skor heuristik berbasis pola
  estimator.py             # estimasi waktu tebak (ilustratif)
  report.py                # penyusun laporan
  validators.py            # validasi detektor dengan data sintetis
  detectors/               # detektor pola lemah
  tests/test_entropi.py    # unit test
```

## Cara pakai

Jalankan dari folder repositori.

```bash
python entropi_password.py
```

Program akan bertanya apakah password ditampilkan saat diketik, lalu meminta password
berulang kali. Kosongkan input lalu tekan Enter untuk keluar.

```bash
python entropi_password.py --show      # input langsung terlihat, tanpa pertanyaan awal
```

### Menghitung entropi generator

Tambahkan `--mode` dan parameter cara pembuatannya:

```bash
# 16 karakter acak seragam dari 95 karakter
python entropi_password.py --mode random-chars --length 16 --charset-size 95

# Diceware 6 kata (daftar 7776 kata)
python entropi_password.py --mode diceware --words 6

# 4 kata acak dari daftar berukuran 10000
python entropi_password.py --mode passphrase --words 4 --wordlist-size 10000

# 12 karakter acak dari charset sendiri
python entropi_password.py --mode custom-charset --length 12 --charset abcdef0123456789
```

Catatan: program tetap meminta password untuk skor heuristik. Angka entropi generator dihitung
**hanya dari parameter yang kamu berikan**, bukan dari password yang diketik. Tanpa `--mode`,
entropi generator dinyatakan tidak dapat dihitung.

### Semua opsi

| Opsi | Fungsi |
|---|---|
| `--show` | Tampilkan input password, lewati pertanyaan awal |
| `--mode` | `random-chars`, `diceware`, `passphrase`, `custom-charset`, atau `unknown` (default) |
| `-l`, `--length` | Panjang password (`random-chars`, `custom-charset`) |
| `-c`, `--charset-size` | Ukuran charset (`random-chars`, default 95) |
| `-w`, `--words` | Jumlah kata (`diceware`, `passphrase`) |
| `--wordlist-size` | Ukuran daftar kata (default 7776) |
| `-s`, `--separator` | Pemisah kata |
| `--add-digits` | Jumlah digit acak tambahan (`diceware`) |
| `--capitalization` | `none`, `first`, `random`, `all` (`passphrase`) |
| `--charset` | Charset kustom (`custom-charset`) |
| `--legacy-only` | Hanya format laporan lama |
| `--new-only` | Hanya format laporan baru |
| `--validate` | Jalankan validasi detektor dengan data sintetis |
| `--validate-samples` | Jumlah sampel validasi (default 500) |
| `--test` | Jalankan unit test |

## Contoh output

Password `P@ssw0rd2024` dengan `--new-only` (ringkas):

```
------------------------------------------------------------
ENTROPI GENERATOR
------------------------------------------------------------
  Mode: TIDAK DIKETAHUI (gunakan --mode untuk menghitung)
  Entropi generator TIDAK DAPAT dihitung tanpa mengetahui
  cara password dibuat. Lihat opsi --mode.

------------------------------------------------------------
SKOR HEURISTIK (Estimasi Berbasis Pola - BUKAN Entropi Sebenarnya)
------------------------------------------------------------
  Panjang password        : 12 karakter
  Ukuran charset          : 95
  Entropi charset (naif)  : 78.8 bit
  Entropi Shannon (freq)  : 37.0 bit
  Skor heuristik          : 14.7 bit
  Karakter bebas pola     : 0
  Pola terdeteksi (dipakai): 2

------------------------------------------------------------
POLA LEMAH TERDETEKSI
------------------------------------------------------------
  - [leet] leet word 'password' -> 'P@ssw0rd' (cost: 7.7 bit)
  - [dates] year '2024' (cost: 7.0 bit)

------------------------------------------------------------
ESTIMASI WAKTU TEBAK (ILUSTRATIF SAJA)
------------------------------------------------------------
  Online attack (rate limited)                       : 2.2 menit
  Offline attack, slow hash (bcrypt, scrypt, Argon2) : 1.3 detik
  Offline attack, fast hash (MD5, SHA1, SHA256)      : kurang dari 1 detik
  Offline attack, very fast (NTLM, raw SHA256)       : kurang dari 1 detik
```

Password ini tampak rumit (huruf besar, angka, simbol), tetapi hanya kata "password"
dengan substitusi umum ditambah tahun, sehingga skor heuristiknya rendah.

Dengan `--mode diceware --words 6`, bagian generator menjadi:

```
ENTROPI GENERATOR (Entropi Sebenarnya)
  Mode Pembuatan : diceware
  Entropi        : 77.5 bit

  Asumsi:
    - 6 words chosen independently
    - Uniform distribution over 7776 words
    - Attacker knows the wordlist and word count
```

Entropi generator selalu disertai asumsinya. Angka itu hanya benar jika asumsi tersebut
terpenuhi, misalnya kata benar-benar dipilih seragam dan independen.

## Cara kerja skor heuristik

1. Menentukan kumpulan karakter yang dipakai dan batas atas teoretis (`panjang x log2(charset)`).
2. Menjalankan detektor pola lemah, lalu memilih pola terpanjang yang tidak tumpang tindih.
3. Karakter di luar pola dihitung penuh, sedangkan setiap pola dihitung dengan biaya bit yang lebih kecil.
4. Hasilnya dibatasi tidak melebihi batas atas teoretis.

Detektor bawaan:

- kata umum (Indonesia dan Inggris) dan substitusi leet (`p@ssw0rd`)
- tanggal dan tahun
- karakter atau blok berulang
- urutan naik/turun (`abc`, `321`)
- pola keyboard (`qwerty`, `asdf`)
- nama umum
- khusus Indonesia: lokasi (kota, provinsi, pulau), pola identitas (nomor telepon, NIK, NPWP, dan sejenisnya), dan plat kendaraan

"Entropi Shannon" pada laporan hanyalah keragaman karakter di dalam satu string. Itu bukan
entropi dari proses pembuatan password, dan tidak dipakai untuk menghitung skor heuristik.

## Estimasi waktu tebak

Waktu rata-rata dihitung dari separuh ruang pencarian (`2^(bit - 1)`) dibagi laju tebakan contoh:

| Skenario | Laju tebakan contoh |
|---|---|
| Online, dibatasi rate limiting | 100 per detik |
| Offline, hash lambat (bcrypt, scrypt, Argon2) | 10 ribu per detik |
| Offline, hash cepat (MD5, SHA1, SHA256) | 10 miliar per detik |
| Offline, sangat cepat (NTLM, SHA256 mentah) | 100 miliar per detik |

Estimasi ini dihitung dari **skor heuristik**, bukan dari entropi generator. Angka nyata sangat
bergantung pada algoritma hash, salt, perangkat keras, pembatasan percobaan, dan MFA.

## Tes dan validasi

```bash
python entropi_password.py --test       # unit test (45 tes)
python entropi_password.py --validate   # evaluasi detektor pada data sintetis
```

Contoh hasil `--validate --validate-samples 300`:

```
common_words: P=1.00 R=0.36
leet:         P=1.00 R=0.43
dates:        P=1.00 R=0.16
repetition:   P=0.97 R=0.20
sequences:    P=1.00 R=0.09
keyboard:     P=0.98 R=0.14
names:        P=1.00 R=0.14
Avg random entropy: 90.9 bit | Avg human entropy: 18.5 bit
```

Cara membacanya dengan jujur:

- Presisi tinggi artinya detektor jarang salah menandai password acak sebagai berpola.
- **Recall rendah (9% sampai 43%) wajar**: tiap detektor hanya menangkap satu jenis pola, sedangkan
  satu password berpola bisa lolos dari detektor lain.
- Dataset dibuat sendiri oleh program ini, dengan daftar kata yang mirip dengan daftar detektor.
  Ini **bukan validasi independen** dan tidak membuktikan akurasi pada password nyata.

## Keterbatasan

- Skor heuristik hanya mengenali pola yang ada di daftar program. Daftar kata, nama, dan lokasi
  bawaan terbatas, jadi password buatan manusia bisa lebih lemah daripada skornya.
- Entropi generator hanya valid jika password benar-benar dibuat dengan proses yang kamu sebutkan
  dan semua pilihan seragam serta independen. Memilih sendiri "kata acak" dari kepala tidak termasuk.
- Estimasi waktu bukan prediksi atau jaminan keamanan.
- Alat ini untuk belajar dan pemeriksaan kasar, bukan pengganti password manager atau praktik
  keamanan lain seperti MFA dan password unik per layanan.
- Jangan mengunggah password asli ke repositori, termasuk di contoh, tangkapan layar, dan data tes.

## Lisensi

Dirilis di bawah [Lisensi MIT](LICENSE).
