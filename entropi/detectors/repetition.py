"""
Detector for character and block repetition patterns.
"""

import re
from typing import List
from .base import PatternDetector, Pattern


class RepetitionDetector(PatternDetector):
    """Detects repeated characters and repeated blocks."""

    def __init__(self, min_char_repeat: int = 3, min_block_length: int = 2):
        self.min_char_repeat = min_char_repeat
        self.min_block_length = min_block_length

    @property
    def name(self) -> str:
        return "repetition"

    def detect(self, password: str, bit_per_char: float) -> List[Pattern]:
        results = []

        # 1. Repeated characters: aaa, 1111, !!!!!
        char_repeat_pattern = re.compile(rf"(.)\1{{{self.min_char_repeat - 1},}}")
        for match in char_repeat_pattern.finditer(password):
            length = match.end() - match.start()
            char = match.group(1)
            # Cost: bit_per_char for first char + log2(length) for repeat count
            cost = bit_per_char + math.log2(length)
            results.append(self._make_pattern(
                start=match.start(),
                end=match.end(),
                label=f"repeated char '{char}' x{length}",
                cost_bits=cost,
                metadata={"char": char, "count": length, "type": "char_repeat"},
            ))

        # 2. Repeated blocks: abcabc, 1212, ababab
        # Use regex to find repeated substrings
        for i in range(len(password) - self.min_block_length * 2 + 1):
            for block_len in range(self.min_block_length,
                                   (len(password) - i) // 2 + 1):
                block = password[i:i + block_len]
                # Count how many times it repeats
                repeats = 1
                pos = i + block_len
                while pos + block_len <= len(password) and password[pos:pos + block_len] == block:
                    repeats += 1
                    pos += block_len

                if repeats >= 2:
                    end = i + block_len * repeats
                    # Cost: block_len * bit_per_char + log2(repeats)
                    cost = block_len * bit_per_char + math.log2(repeats)
                    results.append(self._make_pattern(
                        start=i,
                        end=end,
                        label=f"repeated block '{block}' x{repeats}",
                        cost_bits=cost,
                        metadata={"block": block, "count": repeats, "type": "block_repeat"},
                    ))

        return results


import math