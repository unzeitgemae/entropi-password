"""
Detector for date patterns (years, dates).
"""

import re
from typing import List
from .base import PatternDetector, Pattern


class DateDetector(PatternDetector):
    """Detects years and common date patterns."""

    def __init__(self, year_range: tuple = (1900, 2099)):
        self.year_start, self.year_end = year_range

    @property
    def name(self) -> str:
        return "dates"

    def detect(self, password: str, bit_per_char: float) -> List[Pattern]:
        results = []

        # Years (1900-2099)
        year_pattern = re.compile(r"(?:19|20)\d{2}")
        for match in year_pattern.finditer(password):
            year = int(match.group())
            if self.year_start <= year <= self.year_end:
                # ~7 bits for a year in 200-year range
                results.append(self._make_pattern(
                    start=match.start(),
                    end=match.end(),
                    label=f"year '{match.group()}'",
                    cost_bits=7.0,
                    metadata={"year": year, "type": "year"},
                ))

        # Full dates: DDMMYYYY, MMDDYYYY, YYYYMMDD, DD-MM-YYYY, etc.
        date_patterns = [
            (r"\d{2}[-/.]\d{2}[-/.]\d{4}", "DD/MM/YYYY", 14),  # ~14 bits for date
            (r"\d{4}[-/.]\d{2}[-/.]\d{2}", "YYYY/MM/DD", 14),
            (r"\d{8}", "DDMMYYYY or MMDDYYYY", 16),  # Ambiguous
        ]

        for pattern, label, cost in date_patterns:
            for match in re.finditer(pattern, password):
                # Avoid overlapping with year detection
                if not any(r.overlaps(Pattern(match.start(), match.end(), "", 0, "")) for r in results):
                    results.append(self._make_pattern(
                        start=match.start(),
                        end=match.end(),
                        label=f"date ({label})",
                        cost_bits=cost,
                        metadata={"date_str": match.group(), "format": label},
                    ))

        return results