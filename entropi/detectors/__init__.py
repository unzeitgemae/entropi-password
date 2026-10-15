"""
Pattern detectors for weak password patterns.
"""

from .base import Pattern, PatternDetector
from .common_words import CommonWordsDetector
from .leet import LeetDetector
from .dates import DateDetector
from .repetition import RepetitionDetector
from .sequences import SequenceDetector
from .keyboard import KeyboardDetector
from .names import NamesDetector
from .indonesian_geo import IndonesianGeoDetector
from .indonesian_id import IndonesianIDDetector, IndonesianPlateDetector

__all__ = [
    "Pattern",
    "PatternDetector",
    "CommonWordsDetector",
    "LeetDetector",
    "DateDetector",
    "RepetitionDetector",
    "SequenceDetector",
    "KeyboardDetector",
    "NamesDetector",
    "IndonesianGeoDetector",
    "IndonesianIDDetector",
    "IndonesianPlateDetector",
    "DEFAULT_DETECTORS",
    "INDONESIAN_DETECTORS",
]

# Default detector instances (generic)
DEFAULT_DETECTORS = [
    CommonWordsDetector(),
    LeetDetector(),
    DateDetector(),
    RepetitionDetector(),
    SequenceDetector(),
    KeyboardDetector(),
    NamesDetector(),
]

# Indonesian-specific detectors
INDONESIAN_DETECTORS = [
    IndonesianGeoDetector(),
    IndonesianIDDetector(),
    IndonesianPlateDetector(),
]

# All detectors combined
ALL_DETECTORS = DEFAULT_DETECTORS + INDONESIAN_DETECTORS