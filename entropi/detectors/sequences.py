"""
Detector for sequential patterns (abc, 123, 321, etc.).
"""

from typing import List
from .base import PatternDetector, Pattern


class SequenceDetector(PatternDetector):
    """Detects ascending/descending character sequences."""

    def __init__(self, min_length: int = 3):
        self.min_length = min_length

    @property
    def name(self) -> str:
        return "sequences"

    def detect(self, password: str, bit_per_char: float) -> List[Pattern]:
        results = []
        i = 0

        while i < len(password) - self.min_length + 1:
            # Check difference between consecutive characters
            diff = ord(password[i + 1]) - ord(password[i])
            if diff in (1, -1):  # Ascending or descending
                j = i + 1
                while (j + 1 < len(password) and
                       ord(password[j + 1]) - ord(password[j]) == diff):
                    j += 1

                length = j - i + 1
                if length >= self.min_length:
                    seq = password[i:j + 1]
                    direction = "ascending" if diff == 1 else "descending"
                    # Cost: bit_per_char for first char + log2(length) + 1 for direction
                    cost = bit_per_char + math.log2(length) + 1
                    results.append(self._make_pattern(
                        start=i,
                        end=j + 1,
                        label=f"sequence ({direction}) '{seq}'",
                        cost_bits=cost,
                        metadata={"sequence": seq, "direction": direction, "length": length},
                    ))
                    i = j  # Skip past this sequence
            i += 1

        return results


import math