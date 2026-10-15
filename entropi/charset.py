"""
Character set analysis for password entropy estimation.
"""

import math
import re
from dataclasses import dataclass
from typing import Set


@dataclass(frozen=True)
class CharsetInfo:
    """Information about the character set used in a password."""
    size: int
    has_lower: bool
    has_upper: bool
    has_digit: bool
    has_symbol: bool
    has_nonascii: bool
    categories: Set[str]

    def bit_per_char(self) -> float:
        """Theoretical bits per character if chosen uniformly from this charset."""
        return math.log2(max(self.size, 1))

    def theoretical_entropy(self, length: int) -> float:
        """Theoretical entropy (naive) for given length."""
        return length * self.bit_per_char()


class CharsetAnalyzer:
    """Analyzes the character set used in a password."""

    SYMBOLS_ASCII = set(chr(i) for i in range(32, 127)
                        if not chr(i).isalnum() and chr(i) != ' ')

    def __init__(self):
        pass

    def analyze(self, password: str) -> CharsetInfo:
        """Analyze password and return charset information."""
        has_lower = bool(re.search(r"[a-z]", password))
        has_upper = bool(re.search(r"[A-Z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_symbol = bool(re.search(r"[ -/:-@\[-`{-~]", password))
        has_nonascii = bool(re.search(r"[^\x00-\x7f]", password))

        categories = set()
        size = 0
        if has_lower:
            categories.add("lowercase")
            size += 26
        if has_upper:
            categories.add("uppercase")
            size += 26
        if has_digit:
            categories.add("digits")
            size += 10
        if has_symbol:
            categories.add("symbols")
            size += 33  # printable ASCII symbols
        if has_nonascii:
            categories.add("non-ascii")
            size += 100  # conservative estimate for extended chars

        return CharsetInfo(
            size=max(size, 1),
            has_lower=has_lower,
            has_upper=has_upper,
            has_digit=has_digit,
            has_symbol=has_symbol,
            has_nonascii=has_nonascii,
            categories=categories,
        )