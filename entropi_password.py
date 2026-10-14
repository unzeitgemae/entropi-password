#!/usr/bin/env python3
"""
entropi_password.py - Pengukur entropi password 100% lokal.

- Hanya memakai library bawaan Python (tidak ada import jaringan).
- Tidak mengirim, menyimpan, atau menulis password ke mana pun.
- Password dibaca lewat getpass (tidak tampil di layar) kecuali pakai --show.

Cara pakai:
    python entropi_password.py            # mode interaktif (input tersembunyi)
    python entropi_password.py --show     # input terlihat di layar

Catatan: hasilnya ESTIMASI. Entropi sejati bergantung pada cara password dibuat,
bukan hanya tampilannya. Password yang dibuat acak oleh generator selalu lebih
kuat daripada password yang "terlihat rumit" tapi dibuat manusia.
"""

import argparse
import getpass
import math
import re
from collections import Counter

# Daftar kecil kata/password umum (Indonesia + Inggris). Silakan tambah sendiri.
KATA_UMUM = {
    "password", "passw0rd", "admin", "administrator", "qwerty", "welcome",
    "login", "letmein", "monkey", "dragon", "master", "sunshine", "iloveyou",
    "football", "princess", "superman", "batman", "shadow", "michael",
    "indonesia", "sayang", "rahasia", "bismillah", "garuda", "jember",
    "kucing", "cinta", "bandung", "jakarta", "merdeka", "surabaya",
    "bangsa", "kamu", "aku", "pancasila", "universitas", "mahasiswa",
    "abc123", "test", "user", "root", "guest", "default", "secret",
}

# Substitusi "leet" yang umum: p@ssw0rd -> password
LEET = {"4": "a", "@": "a", "3": "e", "1": "i", "!": "i", "0": "o",
        "$": "s", "5": "s", "7": "t"}

BARIS_KEYBOARD = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
BARIS_KEYBOARD += [b[::-1] for b in BARIS_KEYBOARD]


def ukuran_charset(pw: str) -> int:
    """Perkiraan ukuran kumpulan karakter yang dipakai."""
    ukuran = 0
    if re.search(r"[a-z]", pw):
        ukuran += 26
    if re.search(r"[A-Z]", pw):
        ukuran += 26
    if re.search(r"\d", pw):
        ukuran += 10
    if re.search(r"[ -/:-@\[-`{-~]", pw):  # simbol ASCII
        ukuran += 33
    if re.search(r"[^\x00-\x7f]", pw):  # karakter non-ASCII
        ukuran += 100
    return max(ukuran, 1)


def entropi_shannon(pw: str) -> float:
    """Entropi Shannon (bit) dari distribusi karakter, dikali panjang."""
    if not pw:
        return 0.0
    n = len(pw)
    hitung = Counter(pw)
    per_char = -sum((c / n) * math.log2(c / n) for c in hitung.values())
    return per_char * n


def cari_pola(pw: str, bit_char: float):
    """Cari pola lemah. Return list (mulai, akhir, label, biaya_bit)."""
    low = pw.lower()
    deleet = "".join(LEET.get(c, c) for c in low)
    hasil = []

    # 1. Kata umum (juga versi leet)
    for kata in KATA_UMUM:
        if len(kata) < 4:
            continue
        for sumber in {low, deleet}:
            for m in re.finditer(re.escape(kata), sumber):
                hasil.append((m.start(), m.end(), f"kata umum '{kata}'",
                              math.log2(len(KATA_UMUM)) + 1))

    # 2. Tahun (1900-2099)
    for m in re.finditer(r"(?:19|20)\d{2}", pw):
        hasil.append((m.start(), m.end(), f"tahun '{m.group()}'", 7.0))

    # 3. Karakter berulang (aaa, 1111)
    for m in re.finditer(r"(.)\1{2,}", pw):
        panjang = m.end() - m.start()
        hasil.append((m.start(), m.end(), f"pengulangan '{m.group()}'",
                      bit_char + math.log2(panjang)))

    # 4. Blok berulang (abcabc, 1212)
    for m in re.finditer(r"(.{2,}?)\1+", pw):
        blok = m.group(1)
        ulang = (m.end() - m.start()) // len(blok)
        hasil.append((m.start(), m.end(), f"blok berulang '{blok}' x{ulang}",
                      len(blok) * bit_char + math.log2(ulang)))

    # 5. Urutan naik/turun (abc, 321)
    i = 0
    while i < len(pw) - 2:
        selisih = ord(pw[i + 1]) - ord(pw[i])
        if selisih in (1, -1):
            j = i + 1
            while j + 1 < len(pw) and ord(pw[j + 1]) - ord(pw[j]) == selisih:
                j += 1
            if j - i + 1 >= 3:
                hasil.append((i, j + 1, f"urutan '{pw[i:j + 1]}'",
                              bit_char + math.log2(j - i + 1) + 1))
            i = j
        else:
            i += 1

    # 6. Pola keyboard (qwerty, asdf)
    for i in range(len(low) - 2):
        for baris in BARIS_KEYBOARD:
            k = 3
            if low[i:i + 3] in baris:
                while i + k < len(low) and low[i:i + k + 1] in baris:
                    k += 1
                hasil.append((i, i + k, f"pola keyboard '{pw[i:i + k]}'",
                              bit_char + math.log2(k) + 2))
    return hasil


def hitung_entropi(pw: str):
    """Return (entropi_efektif, entropi_charset, entropi_shannon, pola_terpakai)."""
    if not pw:
        return 0.0, 0.0, 0.0, []

    pool = ukuran_charset(pw)
    bit_char = math.log2(pool)
    naif = len(pw) * bit_char

    # Pilih pola terpanjang dulu, tanpa tumpang tindih
    pola = sorted(cari_pola(pw, bit_char), key=lambda p: -(p[1] - p[0]))
    terpakai = [False] * len(pw)
    dipilih = []
    for mulai, akhir, label, biaya in pola:
        if not any(terpakai[mulai:akhir]):
            for k in range(mulai, akhir):
                terpakai[k] = True
            dipilih.append((mulai, akhir, label, biaya))

    bebas = terpakai.count(False)
    efektif = bebas * bit_char + sum(p[3] for p in dipilih)
    efektif = min(efektif, naif)

    # Password yang persis sama dengan kata umum
    if pw.lower() in KATA_UMUM or "".join(LEET.get(c, c) for c in pw.lower()) in KATA_UMUM:
        efektif = min(efektif, math.log2(len(KATA_UMUM)))

    return efektif, naif, entropi_shannon(pw), dipilih


def format_durasi(detik: float) -> str:
    if detik < 1:
        return "kurang dari 1 detik"
    satuan = [("tahun", 365 * 24 * 3600), ("hari", 24 * 3600),
              ("jam", 3600), ("menit", 60), ("detik", 1)]
    tahun = detik / (365 * 24 * 3600)
    if tahun >= 1e9:
        return "lebih dari satu miliar tahun"
    if tahun >= 1e6:
        return f"{tahun / 1e6:.1f} juta tahun"
    if tahun >= 1000:
        return f"{tahun:,.0f} tahun".replace(",", ".")
    for nama, nilai in satuan:
        if detik >= nilai:
            return f"{detik / nilai:.1f} {nama}"
    return f"{detik:.1f} detik"


def penilaian(bit: float) -> str:
    if bit < 28:
        return "SANGAT LEMAH"
    if bit < 36:
        return "LEMAH"
    if bit < 60:
        return "SEDANG"
    if bit < 80:
        return "KUAT"
    return "SANGAT KUAT"


def laporan(pw: str) -> None:
    efektif, naif, shannon, pola = hitung_entropi(pw)
    rata_tebak = 2 ** max(efektif - 1, 0)  # rata-rata butuh separuh ruang

    print()
    print(f"  Panjang                  : {len(pw)} karakter")
    print(f"  Ukuran charset           : {ukuran_charset(pw)}")
    print(f"  Entropi charset (teoritis): {naif:.1f} bit")
    print(f"  Entropi Shannon          : {shannon:.1f} bit")
    print(f"  Entropi efektif (estimasi): {efektif:.1f} bit")
    print(f"  Penilaian                : {penilaian(efektif)}")
    print()
    print("  Perkiraan waktu rata-rata untuk ditebak:")
    print(f"    Serangan online (100 tebakan/detik)     : {format_durasi(rata_tebak / 1e2)}")
    print(f"    Offline, hash lambat (10 ribu/detik)    : {format_durasi(rata_tebak / 1e4)}")
    print(f"    Offline, hash cepat (10 miliar/detik)   : {format_durasi(rata_tebak / 1e10)}")

    if pola:
        print()
        print("  Pola lemah terdeteksi:")
        for _, _, label, _ in sorted(pola):
            print(f"    - {label}")

    print()


def pilih_mode(paksa_tampil: bool) -> bool:
    """Tanya di awal: tampilkan password saat mengetik atau tidak."""
    if paksa_tampil:
        return True
    while True:
        jawab = input("Tampilkan password saat mengetik? [y/N]: ").strip().lower()
        if jawab in ("", "n", "t", "tidak"):
            return False
        if jawab in ("y", "ya"):
            return True
        print("  Jawab dengan y atau n.")


def main() -> None:
    ap = argparse.ArgumentParser(description="Ukur entropi password (offline).")
    ap.add_argument("--show", action="store_true",
                    help="langsung tampilkan input tanpa bertanya di awal")
    args = ap.parse_args()

    print("Pengukur Entropi Password (lokal, tanpa internet)")
    tampil = pilih_mode(args.show)
    status = "TERLIHAT" if tampil else "TERSEMBUNYI"
    print(f"Input password: {status}. Kosongkan input lalu Enter untuk keluar.\n")
    baca = input if tampil else getpass.getpass
    while True:
        try:
            pw = baca("Password: ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not pw:
            break
        laporan(pw)


if __name__ == "__main__":
    main()
