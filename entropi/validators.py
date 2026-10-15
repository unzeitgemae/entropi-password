"""
Validators for testing heuristic accuracy against synthetic datasets.
"""

import random
import math
from dataclasses import dataclass
from typing import List, Dict, Tuple, Callable
from collections import Counter

from .generators import GeneratorEntropy, GenerationMode
from .heuristic import HeuristicScorer
from .detectors import PatternDetector, Pattern


@dataclass
class ValidationResult:
    """Result of validating a detector or scorer."""
    detector_name: str
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float

    def __str__(self) -> str:
        return (f"{self.detector_name}: "
                f"P={self.precision:.2f} R={self.recall:.2f} F1={self.f1_score:.2f} "
                f"(TP={self.true_positives} FP={self.false_positives} "
                f"TN={self.true_negatives} FN={self.false_negatives})")


class SyntheticDataset:
    """Generates synthetic passwords for validation."""

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def random_password(self, length: int, charset: str) -> str:
        """Generate truly random password from charset."""
        return "".join(self.rng.choice(charset) for _ in range(length))

    def diceware_passphrase(self, word_count: int, wordlist: List[str],
                            separator: str = " ") -> str:
        """Generate diceware-style passphrase."""
        words = [self.rng.choice(wordlist) for _ in range(word_count)]
        return separator.join(words)

    def human_like_password(self) -> str:
        """Generate a password mimicking human patterns."""
        patterns = [
            # Word + year
            lambda: self.rng.choice(COMMON_WORDS) + str(self.rng.randint(1950, 2024)),
            # Word + symbol + digit
            lambda: self.rng.choice(COMMON_WORDS) + self.rng.choice("!@#$") + str(self.rng.randint(0, 99)),
            # Leet word
            lambda: self._leetify(self.rng.choice(COMMON_WORDS)),
            # Keyboard walk
            lambda: self._keyboard_walk(self.rng.randint(4, 8)),
            # Repeated pattern
            lambda: self._repeat_pattern(),
            # Name + numbers
            lambda: self.rng.choice(NAMES) + str(self.rng.randint(1, 9999)),
        ]
        return self.rng.choice(patterns)()

    def _leetify(self, word: str) -> str:
        """Apply random leet substitutions."""
        leet_map = {
            'a': ['a', '4', '@'], 'e': ['e', '3'], 'i': ['i', '1', '!'],
            'o': ['o', '0'], 's': ['s', '$', '5'], 't': ['t', '7', '+'],
        }
        result = []
        for c in word.lower():
            if c in leet_map and self.rng.random() < 0.4:
                result.append(self.rng.choice(leet_map[c]))
            else:
                result.append(c)
        # Maybe capitalize first
        if self.rng.random() < 0.3:
            result[0] = result[0].upper()
        return "".join(result)

    def _keyboard_walk(self, length: int) -> str:
        """Generate keyboard walk pattern."""
        rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
        # Filter rows that are long enough
        valid_rows = [r for r in rows if len(r) >= length]
        if not valid_rows:
            # Fallback: repeat a shorter row
            row = self.rng.choice(rows)
            return (row * (length // len(row) + 1))[:length]
        row = self.rng.choice(valid_rows)
        start = self.rng.randint(0, len(row) - length)
        direction = self.rng.choice([1, -1])
        if direction == 1:
            return row[start:start + length]
        else:
            return row[start:start - length:-1] if start >= length - 1 else row[start::-1]

    def _repeat_pattern(self) -> str:
        """Generate repeated pattern."""
        block_len = self.rng.randint(2, 4)
        charset = "abcdefghijklmnopqrstuvwxyz0123456789"
        block = "".join(self.rng.choice(charset) for _ in range(block_len))
        repeats = self.rng.randint(2, 4)
        return block * repeats

    def generate_dataset(self, n_random: int = 1000, n_human: int = 1000) -> Tuple[List[str], List[str]]:
        """Generate labeled dataset: (random_passwords, human_like_passwords)."""
        # Random passwords from full charset
        full_charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        random_pwds = [self.random_password(self.rng.randint(8, 20), full_charset)
                       for _ in range(n_random)]

        # Human-like passwords
        human_pwds = [self.human_like_password() for _ in range(n_human)]

        return random_pwds, human_pwds


# Test data
COMMON_WORDS = [
    "password", "admin", "welcome", "login", "monkey", "dragon", "master",
    "sunshine", "iloveyou", "football", "princess", "superman", "batman",
    "shadow", "michael", "indonesia", "sayang", "rahasia", "bismillah",
    "garuda", "kucing", "cinta", "bandung", "jakarta", "merdeka",
    "surabaya", "bangsa", "kamu", "aku", "pancasila", "universitas",
    "mahasiswa", "abc123", "test", "user", "root", "guest", "default",
    "secret", "hello", "world", "money", "freedom", "whatever",
]

NAMES = [
    "john", "jane", "alex", "sarah", "mike", "emma", "chris", "lisa",
    "david", "anna", "james", "maria", "robert", "susan", "william",
    "jennifer", "richard", "elizabeth", "thomas", "jessica",
]


class HeuristicValidator:
    """Validates heuristic scorer against known-ground-truth datasets."""

    def __init__(self, scorer: HeuristicScorer = None):
        self.scorer = scorer or HeuristicScorer()
        self.dataset = SyntheticDataset()

    def validate_detector(self, detector: PatternDetector,
                          random_pwds: List[str], human_pwds: List[str]) -> ValidationResult:
        """Validate a single detector."""
        tp = fp = tn = fn = 0

        # Random passwords should have FEW patterns (mostly false positives)
        for pwd in random_pwds:
            patterns = detector.detect(pwd, 6.0)  # ~6 bits/char
            if patterns:
                fp += 1
            else:
                tn += 1

        # Human passwords SHOULD have patterns (true positives)
        for pwd in human_pwds:
            patterns = detector.detect(pwd, 6.0)
            if patterns:
                tp += 1
            else:
                fn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        return ValidationResult(
            detector_name=detector.name,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
        )

    def validate_scorer(self, random_pwds: List[str], human_pwds: List[str]) -> Dict:
        """Validate overall heuristic scorer."""
        results = {
            "random_scores": [],
            "human_scores": [],
            "separation": 0.0,
        }

        for pwd in random_pwds:
            score = self.scorer.score(pwd).effective_entropy
            results["random_scores"].append(score)

        for pwd in human_pwds:
            score = self.scorer.score(pwd).effective_entropy
            results["human_scores"].append(score)

        # Calculate separation (higher = better discrimination)
        avg_random = sum(results["random_scores"]) / len(results["random_scores"])
        avg_human = sum(results["human_scores"]) / len(results["human_scores"])
        results["separation"] = avg_random - avg_human
        results["avg_random"] = avg_random
        results["avg_human"] = avg_human

        return results

    def run_full_validation(self, n_samples: int = 500) -> Dict:
        """Run complete validation suite."""
        print(f"Generating {n_samples} random + {n_samples} human-like passwords...")
        random_pwds, human_pwds = self.dataset.generate_dataset(n_samples, n_samples)

        print("Validating detectors...")
        detector_results = {}
        from .detectors import DEFAULT_DETECTORS
        for detector in DEFAULT_DETECTORS:
            result = self.validate_detector(detector, random_pwds, human_pwds)
            detector_results[detector.name] = result
            print(f"  {result}")

        print("Validating scorer...")
        scorer_results = self.validate_scorer(random_pwds, human_pwds)
        print(f"  Avg random entropy: {scorer_results['avg_random']:.1f} bit")
        print(f"  Avg human entropy:  {scorer_results['avg_human']:.1f} bit")
        print(f"  Separation:         {scorer_results['separation']:.1f} bit")

        return {
            "detectors": detector_results,
            "scorer": scorer_results,
        }