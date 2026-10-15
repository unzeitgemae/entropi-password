"""
Detector for keyboard patterns (qwerty, asdf, etc.).
"""

from typing import List
from .base import PatternDetector, Pattern


# Keyboard rows (QWERTY layout)
KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
    "!@#$%^&*()",  # Shifted numbers
]

# Add reversed versions
KEYBOARD_ROWS += [row[::-1] for row in KEYBOARD_ROWS]

# Also add common diagonal patterns
KEYBOARD_DIAGONALS = [
    "qaz", "wsx", "edc", "rfv", "tgb", "yhn", "ujm",  # Down-left
    "zaq", "xsw", "cde", "vfr", "bgt", "nhy", "mju",  # Up-right
]


class KeyboardDetector(PatternDetector):
    """Detects keyboard walking patterns."""

    def __init__(self, min_length: int = 3):
        self.min_length = min_length
        self._patterns = KEYBOARD_ROWS + KEYBOARD_DIAGONALS

    @property
    def name(self) -> str:
        return "keyboard"

    def detect(self, password: str, bit_per_char: float) -> List[Pattern]:
        results = []
        low = password.lower()

        for i in range(len(low) - self.min_length + 1):
            for pattern in self._patterns:
                # Find longest match starting at i
                max_len = 0
                for k in range(self.min_length, min(len(pattern), len(low) - i) + 1):
                    if low[i:i + k] in pattern:
                        max_len = k
                    else:
                        break

                if max_len >= self.min_length:
                    matched = password[i:i + max_len]
                    # Cost: bit_per_char for first char + log2(length) + 2 for pattern type
                    cost = bit_per_char + math.log2(max_len) + 2
                    results.append(self._make_pattern(
                        start=i,
                        end=i + max_len,
                        label=f"keyboard pattern '{matched}'",
                        cost_bits=cost,
                        metadata={"pattern": matched, "source": "keyboard_row"},
                    ))

        return results


import math