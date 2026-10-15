#!/usr/bin/env python3
"""
entropi_password.py - Pengukur entropi password 100% lokal (v2).

- Hanya memakai library bawaan Python (tidak ada import jaringan).
- Tidak mengirim, menyimpan, atau menulis password ke mana pun.
- Password dibaca lewat getpass (tidak tampil di layar) kecuali pakai --show.
- Baru: opsi --mode untuk menghitung ENTROPI GENERATOR SEBENARNYA.

Cara pakai:
    python entropi_password.py                    # mode interaktif (input tersembunyi)
    python entropi_password.py --show             # input terlihat di layar
    python entropi_password.py --mode random-chars --length 16 --charset-size 95
    python entropi_password.py --mode diceware --words 6
    python entropi_password.py --validate         # jalankan validasi heuristik

Catatan: hasilnya ESTIMASI. Entropi sejati bergantung pada cara password dibuat,
bukan hanya tampilannya. Password yang dibuat acak oleh generator selalu lebih
kuat daripada password yang "terlihat rumit" tapi dibuat manusia.
"""

import argparse
import getpass
import sys
from typing import Optional

from entropi import (
    EntropyAnalyzer,
    GenerationMode,
    HeuristicScorer,
    TimeEstimator,
    HeuristicValidator,
    SyntheticDataset,
)


def parse_mode(mode_str: str) -> GenerationMode:
    """Parse generation mode string."""
    mode_map = {
        "random-chars": GenerationMode.RANDOM_CHARS,
        "diceware": GenerationMode.DICEWARE,
        "passphrase": GenerationMode.PASSPHRASE,
        "custom-charset": GenerationMode.CUSTOM_CHARSET,
        "unknown": GenerationMode.UNKNOWN,
    }
    if mode_str not in mode_map:
        raise ValueError(f"Mode tidak dikenal: {mode_str}. Pilihan: {', '.join(mode_map.keys())}")
    return mode_map[mode_str]


def get_generator_params(args) -> dict:
    """Extract generator parameters from args."""
    params = {}
    if args.length:
        params["length"] = args.length
    if args.charset_size:
        params["charset_size"] = args.charset_size
    if args.words:
        params["word_count"] = args.words
    if args.wordlist_size:
        params["wordlist_size"] = args.wordlist_size
    if args.separator:
        params["separator"] = args.separator
    if args.add_digits:
        params["add_digits"] = args.add_digits
    if args.capitalization:
        params["capitalization"] = args.capitalization
    if args.charset:
        params["charset"] = args.charset
    return params


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
    ap = argparse.ArgumentParser(
        description="Ukur entropi password (offline, educational).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python entropi_password.py                          # Interaktif, input tersembunyi
  python entropi_password.py --show                   # Input terlihat
  python entropi_password.py --mode random-chars -l 16 -c 95  # Entropi generator acak
  python entropi_password.py --mode diceware -w 6     # Diceware 6 kata
  python entropi_password.py --mode passphrase -w 4 --wordlist-size 10000
  python entropi_password.py --validate               # Jalankan validasi heuristik
  python entropi_password.py --test                   # Jalankan unit test
        """
    )

    # Input mode
    ap.add_argument("--show", action="store_true",
                    help="langsung tampilkan input tanpa bertanya di awal")

    # Generator mode (NEW)
    ap.add_argument("--mode", type=str, default="unknown",
                    choices=["random-chars", "diceware", "passphrase", "custom-charset", "unknown"],
                    help="Mode pembuatan password (untuk entropi generator SEBENARNYA)")

    # Generator parameters
    ap.add_argument("-l", "--length", type=int, help="Panjang password (random-chars, custom-charset)")
    ap.add_argument("-c", "--charset-size", type=int, default=95, help="Ukuran charset (random-chars)")
    ap.add_argument("-w", "--words", type=int, help="Jumlah kata (diceware, passphrase)")
    ap.add_argument("--wordlist-size", type=int, default=7776, help="Ukuran wordlist (diceware: 7776 default)")
    ap.add_argument("-s", "--separator", type=str, default=" ", help="Pemisah kata (diceware, passphrase)")
    ap.add_argument("--add-digits", type=int, default=0, help="Digit acak tambahan (diceware)")
    ap.add_argument("--capitalization", type=str, choices=["none", "first", "random", "all"],
                    default="none", help="Kapitalisasi (passphrase)")
    ap.add_argument("--charset", type=str, help="Charset kustom (custom-charset)")

    # Validation & testing
    ap.add_argument("--validate", action="store_true",
                    help="Jalankan validasi heuristik terhadap dataset sintetis")
    ap.add_argument("--test", action="store_true",
                    help="Jalankan unit test")
    ap.add_argument("--validate-samples", type=int, default=500,
                    help="Jumlah sampel untuk validasi (default: 500)")

    # Output options
    ap.add_argument("--legacy-only", action="store_true",
                    help="Hanya tampilkan output legacy (kompatibilitas mundur)")
    ap.add_argument("--new-only", action="store_true",
                    help="Hanya tampilkan output baru (tanpa legacy)")

    args = ap.parse_args()

    # Run unit tests
    if args.test:
        import unittest
        loader = unittest.TestLoader()
        suite = loader.discover("entropi/tests", pattern="test_*.py")
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        sys.exit(0 if result.wasSuccessful() else 1)

    # Run validation
    if args.validate:
        print("Menjalankan validasi heuristik...")
        print("=" * 60)
        validator = HeuristicValidator()
        results = validator.run_full_validation(n_samples=args.validate_samples)
        print("=" * 60)
        print("Validasi selesai.")
        sys.exit(0)

    # Interactive mode
    print("Pengukur Entropi Password v2 (lokal, tanpa internet)")
    tampil = pilih_mode(args.show)
    status = "TERLIHAT" if tampil else "TERSEMBUNYI"
    print(f"Input password: {status}. Kosongkan input lalu Enter untuk keluar.\n")

    # Parse generation mode
    gen_mode = parse_mode(args.mode)
    gen_params = get_generator_params(args)

    # Validate required params for mode
    if gen_mode == GenerationMode.RANDOM_CHARS and not args.length:
        print("Error: --mode random-chars memerlukan --length")
        sys.exit(1)
    if gen_mode == GenerationMode.DICEWARE and not args.words:
        print("Error: --mode diceware memerlukan --words")
        sys.exit(1)
    if gen_mode == GenerationMode.PASSPHRASE and not args.words:
        print("Error: --mode passphrase memerlukan --words")
        sys.exit(1)
    if gen_mode == GenerationMode.CUSTOM_CHARSET and not (args.length and args.charset):
        print("Error: --mode custom-charset memerlukan --length dan --charset")
        sys.exit(1)

    # Setup analyzer
    analyzer = EntropyAnalyzer(
        heuristic_scorer=HeuristicScorer(),
        time_estimator=TimeEstimator(),
    )

    show_legacy = not args.new_only
    show_new = not args.legacy_only

    baca = input if tampil else getpass.getpass
    while True:
        try:
            pw = baca("Password: ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not pw:
            break

        report = analyzer.analyze(pw, generation_mode=gen_mode, **gen_params)
        output = analyzer.format_report(report, show_legacy=show_legacy, show_new=show_new)
        print(output)


if __name__ == "__main__":
    main()