# entropi-password

Program Python untuk mengukur entropi password, berjalan **100% lokal di terminal**.
Tidak ada koneksi internet, tidak ada penyimpanan, tidak ada pengiriman data.

## Kenapa program ini aman dipakai

- Hanya memakai library bawaan Python (`argparse`, `getpass`, `math`, `re`, `collections`).
- Tidak ada import jaringan sama sekali. Kamu bisa memeriksanya sendiri di kode sumber.
- Password tidak ditulis ke file, log, maupun riwayat apa pun. Semuanya hanya ada di memori selama program berjalan.
- Input bisa disembunyikan (default) agar aman dari orang yang mengintip layar.

## Fitur

- **Entropi charset**: batas atas teoritis, yaitu panjang x log2(ukuran karakter yang dipakai).
- **Entropi Shannon**: berdasarkan sebaran karakter di dalam password.
- **Entropi efektif**: estimasi yang paling realistis, karena pola lemah dihitung jauh lebih murah:
  - kata umum (termasuk versi leet, misalnya `p@ssw0rd`)
  - tahun (1900-2099)
  - karakter berulang (`aaaa`, `1111`)
  - blok berulang (`abcabc`)
  - urutan naik/turun (`abc`, `321`)
  - pola keyboard (`qwerty`, `asdf`)
- **Estimasi waktu tebak** untuk tiga skenario: serangan online, offline dengan hash lambat, dan offline dengan hash cepat.
- **Penilaian** dari SANGAT LEMAH sampai SANGAT KUAT.
- **Pilihan tampil/sembunyi** saat mengetik password, ditanyakan di awal.

## Kebutuhan

Python 3.8 atau lebih baru. Tidak perlu menginstal paket tambahan.

## Cara pakai

```bash
python entropi_password.py
```

Program akan bertanya apakah password ditampilkan saat diketik:

```
Tampilkan password saat mengetik? [y/N]:
```

- `y` : input terlihat, berguna untuk memastikan tidak ada typo.
- `n` atau Enter : input tersembunyi.

Untuk langsung memakai mode terlihat tanpa pertanyaan:

```bash
python entropi_password.py --show
```

Kosongkan input lalu tekan Enter untuk keluar.

## Contoh output

```
Password: P@ssw0rd2024

  Panjang                  : 12 karakter
  Ukuran charset           : 95
  Entropi charset (teoritis): 78.8 bit
  Entropi Shannon          : 37.0 bit
  Entropi efektif (estimasi): 13.5 bit
  Penilaian                : SANGAT LEMAH

  Perkiraan waktu rata-rata untuk ditebak:
    Serangan online (100 tebakan/detik)     : 56.3 detik
    Offline, hash lambat (10 ribu/detik)    : kurang dari 1 detik
    Offline, hash cepat (10 miliar/detik)   : kurang dari 1 detik

  Pola lemah terdeteksi:
    - kata umum 'password'
    - tahun '2024'
```

Password ini terlihat rumit (ada huruf besar, angka, simbol), tetapi hanya berupa kata
"password" dengan substitusi umum ditambah tahun, sehingga entropi efektifnya rendah.

## Cara kerja singkat

1. Menentukan ukuran kumpulan karakter yang dipakai (huruf kecil, huruf besar, angka, simbol, non-ASCII).
2. Mencari pola lemah, lalu memilih pola terpanjang tanpa tumpang tindih.
3. Karakter di luar pola dihitung dengan log2(ukuran charset) per karakter, sedangkan setiap pola dihitung dengan biaya bit yang jauh lebih kecil.
4. Waktu tebak rata-rata dihitung sebagai separuh dari ruang kemungkinan (2^(entropi - 1)) dibagi kecepatan tebakan.

## Keterbatasan

- Hasilnya **estimasi**, bukan jaminan keamanan.
- Daftar kata umum (`KATA_UMUM` di dalam kode) hanya berisi sekitar 45 kata, sehingga password populer di luar daftar tidak akan terdeteksi. Kamu bisa menambah katanya sendiri.
- Program tidak mengetahui bagaimana password dibuat. Password yang dihasilkan generator acak atau passphrase acak (misalnya dari dadu) selalu lebih kuat daripada password buatan manusia yang hanya terlihat rumit.
- Kecepatan tebakan pada estimasi waktu adalah asumsi kasar, dan kenyataannya bergantung pada algoritma hash serta perangkat keras penyerang.

## Lisensi

Dirilis di bawah [Lisensi MIT](LICENSE).
