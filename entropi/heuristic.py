"""
Heuristic scorer - combines pattern detection with charset entropy.
This is the 'effective entropy' calculation, clearly labeled as heuristic.
"""

import math
from dataclasses import dataclass
from typing import List, Optional

from .charset import CharsetAnalyzer, CharsetInfo
from .detectors import PatternDetector, Pattern, DEFAULT_DETECTORS, ALL_DETECTORS


@dataclass(frozen=True)
class HeuristicResult:
    """Result of heuristic scoring."""
    effective_entropy: float       # Heuristic entropy (bits)
    naive_entropy: float           # Theoretical max (charset * length)
    shannon_entropy: float         # Character frequency entropy
    patterns_used: List[Pattern]   # Non-overlapping patterns selected
    patterns_all: List[Pattern]    # All detected patterns
    charset_info: CharsetInfo
    free_chars: int                # Characters not covered by patterns

    @property
    def pattern_coverage(self) -> float:
        """Fraction of password covered by patterns."""
        if self.charset_info is None:
            return 0.0
        total = sum(p.length for p in self.patterns_used)
        return total / max(len(self.patterns_used) * 1.0, 1)  # Placeholder


class HeuristicScorer:
    """
    Calculates heuristic 'effective entropy' by:
    1. Starting with theoretical charset entropy
    2. Detecting patterns
    3. Selecting non-overlapping patterns (longest first)
    4. Free characters = full charset cost, pattern chars = pattern cost
    """

    def __init__(self, detectors: List[PatternDetector] = None, include_indonesian: bool = True):
        if detectors is not None:
            self.detectors = detectors
        elif include_indonesian:
            self.detectors = ALL_DETECTORS
        else:
            self.detectors = DEFAULT_DETECTORS
        self.charset_analyzer = CharsetAnalyzer()

    def score(self, password: str) -> HeuristicResult:
        """Calculate heuristic entropy for a password."""
        if not password:
            return HeuristicResult(
                effective_entropy=0.0,
                naive_entropy=0.0,
                shannon_entropy=0.0,
                patterns_used=[],
                patterns_all=[],
                charset_info=self.charset_analyzer.analyze(""),
                free_chars=0,
            )

        # 1. Charset analysis
        charset_info = self.charset_analyzer.analyze(password)
        bit_per_char = charset_info.bit_per_char()
        naive = charset_info.theoretical_entropy(len(password))

        # 2. Shannon entropy (character frequency)
        shannon = self._shannon_entropy(password)

        # 3. Detect all patterns
        all_patterns = []
        for detector in self.detectors:
            all_patterns.extend(detector.detect(password, bit_per_char))

        # 4. Select non-overlapping patterns (greedy: longest first)
        all_patterns.sort(key=lambda p: (-p.length, p.cost_bits))
        used = [False] * len(password)
        selected = []

        for pattern in all_patterns:
            if not any(used[pattern.start:pattern.end]):
                for k in range(pattern.start, pattern.end):
                    used[k] = True
                selected.append(pattern)

        # 5. Calculate effective entropy
        free_chars = used.count(False)
        pattern_cost = sum(p.cost_bits for p in selected)
        effective = free_chars * bit_per_char + pattern_cost

        # Cap at naive entropy
        effective = min(effective, naive)

        # 6. Special case: password IS a common word (entire password is pattern)
        from .detectors.common_words import DEFAULT_COMMON_WORDS
        from .detectors.leet import LEET_MAP

        low = password.lower()
        deleet = "".join(LEET_MAP.get(c, c) for c in low)

        if low in DEFAULT_COMMON_WORDS or deleet in DEFAULT_COMMON_WORDS:
            word_entropy = math.log2(len(DEFAULT_COMMON_WORDS))
            effective = min(effective, word_entropy)

        return HeuristicResult(
            effective_entropy=effective,
            naive_entropy=naive,
            shannon_entropy=shannon,
            patterns_used=selected,
            patterns_all=all_patterns,
            charset_info=charset_info,
            free_chars=free_chars,
        )

    @staticmethod
    def _shannon_entropy(password: str) -> float:
        """Calculate Shannon entropy of character distribution."""
        if not password:
            return 0.0
        from collections import Counter
        n = len(password)
        counts = Counter(password)
        per_char = -sum((c / n) * math.log2(c / n) for c in counts.values())
        return per_char * n