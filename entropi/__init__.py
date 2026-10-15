"""
entropi - Password entropy analyzer (offline, educational).
"""

from .charset import CharsetAnalyzer
from .generators import GeneratorEntropy, GenerationMode
from .detectors import PatternDetector, DEFAULT_DETECTORS
from .heuristic import HeuristicScorer
from .estimator import TimeEstimator
from .report import EntropyReport, EntropyAnalyzer
from .validators import SyntheticDataset, HeuristicValidator

__version__ = "2.0.0"
__all__ = [
    "CharsetAnalyzer",
    "GeneratorEntropy",
    "GenerationMode",
    "PatternDetector",
    "HeuristicScorer",
    "TimeEstimator",
    "EntropyReport",
    "EntropyAnalyzer",
    "SyntheticDataset",
    "HeuristicValidator",
    "DEFAULT_DETECTORS",
]