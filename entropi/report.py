"""
Main report generator - combines all analyses into a comprehensive report.
"""

from dataclasses import dataclass
from typing import List, Optional

from .charset import CharsetInfo
from .generators import GeneratorEntropy, GeneratorEntropyResult, GenerationMode
from .heuristic import HeuristicResult, HeuristicScorer
from .estimator import TimeEstimator, TimeEstimate, AttackScenario
from .detectors import Pattern


@dataclass
class EntropyReport:
    """Complete entropy analysis report."""
    password: str
    generator_result: GeneratorEntropyResult
    heuristic_result: HeuristicResult
    time_estimates: List[TimeEstimate]

    # Legacy fields for backward compatibility
    @property
    def length(self) -> int:
        return len(self.password)

    @property
    def charset_size(self) -> int:
        return self.heuristic_result.charset_info.size

    @property
    def naive_entropy(self) -> float:
        return self.heuristic_result.naive_entropy

    @property
    def shannon_entropy(self) -> float:
        return self.heuristic_result.shannon_entropy

    @property
    def effective_entropy(self) -> float:
        return self.heuristic_result.effective_entropy

    @property
    def patterns(self) -> List[Pattern]:
        return self.heuristic_result.patterns_used


class EntropyAnalyzer:
    """Main analyzer combining all components."""

    def __init__(self,
                 heuristic_scorer: HeuristicScorer = None,
                 time_estimator: TimeEstimator = None):
        self.heuristic_scorer = heuristic_scorer or HeuristicScorer()
        self.time_estimator = time_estimator or TimeEstimator()

    def analyze(self, password: str,
                generation_mode: GenerationMode = GenerationMode.UNKNOWN,
                **generator_params) -> EntropyReport:
        """Perform complete analysis of a password."""

        # 1. Generator entropy (TRUE entropy if mode known)
        generator_result = GeneratorEntropy.calculate(generation_mode, **generator_params)

        # If mode unknown, don't show fake generator entropy
        if not generator_result.is_valid:
            generator_result = GeneratorEntropyResult(
                mode=generation_mode,
                entropy_bits=0.0,
                assumptions=["Mode unknown - generator entropy not calculated"],
                parameters=generator_params,
                is_valid=False,
                warnings=["Specify --mode to calculate true generator entropy"],
            )

        # 2. Heuristic scoring (pattern-based estimation)
        heuristic_result = self.heuristic_scorer.score(password)

        # 3. Time estimates based on HEURISTIC entropy (labeled illustrative)
        time_estimates = self.time_estimator.estimate(heuristic_result.effective_entropy)

        return EntropyReport(
            password=password,
            generator_result=generator_result,
            heuristic_result=heuristic_result,
            time_estimates=time_estimates,
        )

    def format_report(self, report: EntropyReport, show_legacy: bool = True,
                      show_new: bool = True) -> str:
        """Format report as text (backward compatible + new sections)."""
        lines = []

        # === NEW: Clear section headers ===
        if show_new:
            lines.append("=" * 60)
            lines.append("ANALISIS ENTROPI PASSWORD (v2 - Educational)")
            lines.append("=" * 60)
            lines.append("")
            lines.append("⚠ CATATAN PENTING:")
            lines.append("  - Entropi Generator = entropi SEBENARNYA (jika mode diketahui)")
            lines.append("  - Skor Heuristik    = ESTIMASI berbasis pola (bukan entropi sebenarnya)")
            lines.append("  - Estimasi Waktu    = ILUSTRATIF SAJA, bukan prediksi")
            lines.append("")

        # === GENERATOR ENTROPY (NEW - true entropy) ===
        if show_new and report.generator_result.is_valid:
            lines.append("-" * 60)
            lines.append("ENTROPI GENERATOR (Entropi Sebenarnya)")
            lines.append("-" * 60)
            lines.append(f"  Mode Pembuatan : {report.generator_result.mode.value}")
            lines.append(f"  Entropi        : {report.generator_result.entropy_bits:.1f} bit")
            lines.append("")
            lines.append("  Asumsi:")
            for a in report.generator_result.assumptions:
                lines.append(f"    - {a}")
            lines.append("")
            lines.append("  Parameter:")
            for k, v in report.generator_result.parameters.items():
                lines.append(f"    - {k}: {v}")
            if report.generator_result.warnings:
                lines.append("")
                lines.append("  ⚠ Peringatan:")
                for w in report.generator_result.warnings:
                    lines.append(f"    - {w}")
            lines.append("")

        elif show_new and not report.generator_result.is_valid:
            lines.append("-" * 60)
            lines.append("ENTROPI GENERATOR")
            lines.append("-" * 60)
            lines.append("  Mode: TIDAK DIKETAHUI (gunakan --mode untuk menghitung)")
            lines.append("  Entropi generator TIDAK DAPAT dihitung tanpa mengetahui")
            lines.append("  cara password dibuat. Lihat opsi --mode.")
            lines.append("")

        # === HEURISTIC SCORING (was 'effective entropy') ===
        if show_new:
            lines.append("-" * 60)
            lines.append("SKOR HEURISTIK (Estimasi Berbasis Pola - BUKAN Entropi Sebenarnya)")
            lines.append("-" * 60)
            hr = report.heuristic_result
            lines.append(f"  Panjang password        : {len(report.password)} karakter")
            lines.append(f"  Ukuran charset          : {hr.charset_info.size}")
            lines.append(f"  Kategori charset        : {', '.join(sorted(hr.charset_info.categories))}")
            lines.append(f"  Entropi charset (naif)  : {hr.naive_entropy:.1f} bit")
            lines.append(f"  Entropi Shannon (freq)  : {hr.shannon_entropy:.1f} bit")
            lines.append(f"  Skor heuristik          : {hr.effective_entropy:.1f} bit")
            lines.append(f"  Karakter bebas pola     : {hr.free_chars}")
            lines.append(f"  Pola terdeteksi (dipakai): {len(hr.patterns_used)}")
            lines.append("")

        # === LEGACY OUTPUT (backward compatible) ===
        if show_legacy:
            lines.append("-" * 60)
            lines.append("OUTPUT LEGACY (Kompatibilitas Mundur)")
            lines.append("-" * 60)
            hr = report.heuristic_result
            lines.append(f"  Panjang                  : {len(report.password)} karakter")
            lines.append(f"  Ukuran charset           : {hr.charset_info.size}")
            lines.append(f"  Entropi charset (teoritis): {hr.naive_entropy:.1f} bit")
            lines.append(f"  Entropi Shannon          : {hr.shannon_entropy:.1f} bit")
            lines.append(f"  Entropi efektif (estimasi): {hr.effective_entropy:.1f} bit")
            lines.append(f"  Penilaian                : {self._rating(hr.effective_entropy)}")
            lines.append("")

        # === PATTERNS ===
        if show_new or show_legacy:
            lines.append("-" * 60)
            lines.append("POLA LEMAH TERDETEKSI")
            lines.append("-" * 60)
            if report.heuristic_result.patterns_used:
                for p in sorted(report.heuristic_result.patterns_used, key=lambda x: x.start):
                    lines.append(f"  - [{p.detector_name}] {p.label} (cost: {p.cost_bits:.1f} bit)")
            else:
                lines.append("  (tidak ada pola lemah terdeteksi)")
            lines.append("")

        # === TIME ESTIMATES ===
        if show_new:
            lines.append("-" * 60)
            lines.append("ESTIMASI WAKTU TEBAK (ILUSTRATIF SAJA)")
            lines.append("-" * 60)
            for te in report.time_estimates:
                lines.append(f"  {te.scenario.description:50s} : {te.time_formatted}")
            lines.append("")
            lines.append("  ⚠ Peringatan estimasi:")
            for w in self.time_estimator.get_warnings():
                lines.append(f"    - {w}")
            lines.append("")

        elif show_legacy:
            lines.append("  Perkiraan waktu rata-rata untuk ditebak:")
            for te in report.time_estimates:
                if te.scenario.name in ("online", "offline_slow", "offline_fast"):
                    label = {
                        "online": "Serangan online (100 tebakan/detik)",
                        "offline_slow": "Offline, hash lambat (10 ribu/detik)",
                        "offline_fast": "Offline, hash cepat (10 miliar/detik)",
                    }[te.scenario.name]
                    lines.append(f"    {label:40s} : {te.time_formatted}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _rating(bits: float) -> str:
        """Legacy rating."""
        if bits < 28:
            return "SANGAT LEMAH"
        if bits < 36:
            return "LEMAH"
        if bits < 60:
            return "SEDANG"
        if bits < 80:
            return "KUAT"
        return "SANGAT KUAT"