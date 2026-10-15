"""
Detector for leet speak substitutions.
"""

import re
from typing import Dict, List, Set
from .base import PatternDetector, Pattern
from .common_words import DEFAULT_COMMON_WORDS


# Common leet substitutions
LEET_MAP: Dict[str, str] = {
    "4": "a", "@": "a",
    "3": "e",
    "1": "i", "!": "i",
    "0": "o",
    "$": "s", "5": "s",
    "7": "t",
    "+": "t",
    "9": "g",
    "2": "z",
}


class LeetDetector(PatternDetector):
    """Detects leet speak versions of common words."""

    def __init__(self, wordlist: Set[str] = None, leet_map: Dict[str, str] = None,
                 min_length: int = 4):
        self._wordlist = wordlist or DEFAULT_COMMON_WORDS
        self._leet_map = leet_map or LEET_MAP
        self._min_length = min_length
        self._filtered_words = {w for w in self._wordlist if len(w) >= min_length}

    @property
    def name(self) -> str:
        return "leet"

    def _deleet(self, text: str) -> str:
        """Convert leet speak back to normal letters."""
        return "".join(self._leet_map.get(c, c) for c in text.lower())

    def detect(self, password: str, bit_per_char: float) -> List[Pattern]:
        results = []
        low = password.lower()
        deleet = self._deleet(low)

        # Build a mapping from deleet index to original index
        # Since leet_map is 1:1 char mapping, indices should align
        # But verify lengths match
        if len(low) != len(deleet):
            # Fallback: only search in original
            deleet = low

        for word in self._filtered_words:
            if len(word) < self._min_length:
                continue
            # Search in deleet version (where leet is normalized)
            for match in re.finditer(re.escape(word), deleet):
                start, end = match.start(), match.end()
                matched_text = password[start:end]  # Original text with leet

                cost = math.log2(len(self._filtered_words)) + 2  # Slightly higher for leet
                results.append(self._make_pattern(
                    start=start,
                    end=end,
                    label=f"leet word '{word}' -> '{matched_text}'",
                    cost_bits=cost,
                    confidence=0.8,
                    metadata={"word": word, "matched": matched_text, "source": "deleet"},
                ))

            # Also search in original for exact matches (non-leet)
            for match in re.finditer(re.escape(word), low):
                start, end = match.start(), match.end()
                matched_text = password[start:end]
                cost = math.log2(len(self._filtered_words)) + 1
                results.append(self._make_pattern(
                    start=start,
                    end=end,
                    label=f"common word '{word}'",
                    cost_bits=cost,
                    confidence=1.0,
                    metadata={"word": word, "matched": matched_text, "source": "original"},
                ))

        return results


import math