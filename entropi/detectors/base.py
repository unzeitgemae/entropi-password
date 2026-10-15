"""
Base classes for pattern detectors.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class Pattern:
    """A detected pattern in a password."""
    start: int          # Inclusive start index
    end: int            # Exclusive end index
    label: str          # Human-readable description
    cost_bits: float    # Estimated bits to guess this pattern
    detector_name: str  # Name of detector that found it
    confidence: float = 1.0  # 0.0 to 1.0, how confident we are
    metadata: dict = None  # Additional info

    def __post_init__(self):
        if self.metadata is None:
            object.__setattr__(self, 'metadata', {})

    @property
    def length(self) -> int:
        return self.end - self.start

    def overlaps(self, other: 'Pattern') -> bool:
        return not (self.end <= other.start or other.end <= self.start)

    def __lt__(self, other: 'Pattern'):
        # Sort by length descending (longer patterns first)
        return self.length > other.length


class PatternDetector(ABC):
    """Abstract base class for pattern detectors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this detector."""
        pass

    @abstractmethod
    def detect(self, password: str, bit_per_char: float) -> List[Pattern]:
        """
        Detect patterns in password.
        
        Args:
            password: The password string
            bit_per_char: log2(charset_size) - cost of a random character
            
        Returns:
            List of detected patterns
        """
        pass

    def _make_pattern(self, start: int, end: int, label: str,
                      cost_bits: float, confidence: float = 1.0,
                      metadata: dict = None) -> Pattern:
        """Helper to create a pattern with this detector's name."""
        return Pattern(
            start=start,
            end=end,
            label=label,
            cost_bits=cost_bits,
            detector_name=self.name,
            confidence=confidence,
            metadata=metadata or {},
        )