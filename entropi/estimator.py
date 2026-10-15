"""
Time estimation for password cracking.
Clearly labeled as ILLUSTRATIVE ONLY.
"""

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class AttackScenario:
    """A password cracking scenario."""
    name: str
    description: str
    guesses_per_second: float
    # Real-world context
    context: str = ""


# Standard attack scenarios (clearly labeled as assumptions)
DEFAULT_SCENARIOS = [
    AttackScenario(
        name="online",
        description="Online attack (rate limited)",
        guesses_per_second=100,
        context="Typical web login with rate limiting, no credential stuffing",
    ),
    AttackScenario(
        name="offline_slow",
        description="Offline attack, slow hash (bcrypt, scrypt, Argon2)",
        guesses_per_second=10_000,
        context="Single GPU, proper password hashing with cost factors",
    ),
    AttackScenario(
        name="offline_fast",
        description="Offline attack, fast hash (MD5, SHA1, SHA256)",
        guesses_per_second=10_000_000_000,  # 10 billion
        context="High-end GPU cluster, unsalted fast hash",
    ),
    AttackScenario(
        name="offline_very_fast",
        description="Offline attack, very fast (NTLM, raw SHA256)",
        guesses_per_second=100_000_000_000,  # 100 billion
        context="Specialized hardware (ASIC/FPGA), massive parallelism",
    ),
]


@dataclass(frozen=True)
class TimeEstimate:
    """Time estimate for a scenario."""
    scenario: AttackScenario
    entropy_bits: float
    avg_guesses: float
    time_seconds: float
    time_formatted: str
    is_illustrative: bool = True

    def __str__(self) -> str:
        return f"{self.scenario.name}: {self.time_formatted}"


class TimeEstimator:
    """
    Estimates cracking time for given entropy.
    WARNING: These are ILLUSTRATIVE ONLY and depend on many assumptions.
    """

    def __init__(self, scenarios: list[AttackScenario] = None):
        self.scenarios = scenarios or DEFAULT_SCENARIOS

    def estimate(self, entropy_bits: float) -> list[TimeEstimate]:
        """Estimate cracking time for all scenarios."""
        # Average guesses = half the keyspace
        # Guard: 2 ** x overflows float for x >= 1024; treat as unbounded.
        exponent = max(entropy_bits - 1, 0)
        avg_guesses = 2 ** exponent if exponent < 1000 else float("inf")

        results = []
        for scenario in self.scenarios:
            time_sec = avg_guesses / scenario.guesses_per_second
            results.append(TimeEstimate(
                scenario=scenario,
                entropy_bits=entropy_bits,
                avg_guesses=avg_guesses,
                time_seconds=time_sec,
                time_formatted=self._format_duration(time_sec),
            ))
        return results

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format duration in human-readable form."""
        if seconds < 1:
            return "kurang dari 1 detik"

        units = [
            ("tahun", 365 * 24 * 3600),
            ("hari", 24 * 3600),
            ("jam", 3600),
            ("menit", 60),
            ("detik", 1),
        ]

        years = seconds / (365 * 24 * 3600)
        if years >= 1e9:
            return "lebih dari 1 miliar tahun"
        if years >= 1e6:
            return f"{years / 1e6:.1f} juta tahun"
        if years >= 1000:
            return f"{years:,.0f} tahun".replace(",", ".")

        for name, value in units:
            if seconds >= value:
                return f"{seconds / value:.1f} {name}"

        return f"{seconds:.1f} detik"

    def get_warnings(self) -> list[str]:
        """Return important caveats about these estimates."""
        return [
            "PERINGATAN: Estimasi ini HANYA ILUSTRATIF, bukan prediksi akurat.",
            "Asumsi: penyerang menebak secara optimal sesuai entropi yang dihitung.",
            "Realita bergantung pada: algoritma hash, salt, hardware, paralelisme, dll.",
            "Serangan online dibatasi rate limiting, MFA, lockout - tidak hanya kecepatan tebak.",
            "Entropi heuristik ≠ entropi generator sebenarnya.",
        ]