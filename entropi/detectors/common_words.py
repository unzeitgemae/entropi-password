"""
Detector for common words and passwords.
"""

import re
from typing import List, Set
from .base import PatternDetector, Pattern


# Default common words (Indonesian + English)
DEFAULT_COMMON_WORDS: Set[str] = {
    # English
    "password", "passw0rd", "admin", "administrator", "qwerty", "welcome",
    "login", "letmein", "monkey", "dragon", "master", "sunshine", "iloveyou",
    "football", "princess", "superman", "batman", "shadow", "michael",
    "abc123", "test", "user", "root", "guest", "default", "secret",
    "hello", "world", "money", "freedom", "whatever", "trustno1",
    # Indonesian
    "indonesia", "sayang", "rahasia", "bismillah", "garuda", "jember",
    "kucing", "cinta", "bandung", "jakarta", "merdeka", "surabaya",
    "bangsa", "kamu", "aku", "pancasila", "universitas", "mahasiswa",
    "bismillahirrohmanirrohim", "assalamualaikum",
}


class CommonWordsDetector(PatternDetector):
    """Detects common words and known weak passwords."""

    def __init__(self, wordlist: Set[str] = None, min_length: int = 4):
        self._wordlist = wordlist or DEFAULT_COMMON_WORDS
        self._min_length = min_length
        # Pre-filter words by minimum length
        self._filtered_words = {w for w in self._wordlist if len(w) >= min_length}

    @property
    def name(self) -> str:
        return "common_words"

    def detect(self, password: str, bit_per_char: float) -> List[Pattern]:
        results = []
        low = password.lower()

        for word in self._filtered_words:
            if len(word) < self._min_length:
                continue
            # Search for word (case insensitive)
            for match in re.finditer(re.escape(word), low):
                # Cost: log2(wordlist_size) + 1 bit for position
                cost = math.log2(len(self._filtered_words)) + 1
                results.append(self._make_pattern(
                    start=match.start(),
                    end=match.end(),
                    label=f"common word '{word}'",
                    cost_bits=cost,
                    metadata={"word": word, "wordlist_size": len(self._filtered_words)},
                ))

        return results


import math  # Moved here to avoid circular import