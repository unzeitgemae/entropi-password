"""
Generator-based entropy calculation.
Calculates TRUE entropy based on the generation process, not the output string.
"""

import math
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class GenerationMode(Enum):
    """Known password generation modes."""
    RANDOM_CHARS = "random-chars"      # Uniform random from charset
    DICEWARE = "diceware"              # Diceware/EFF wordlist
    PASSPHRASE = "passphrase"          # Random words from custom wordlist
    CUSTOM_CHARSET = "custom-charset"  # Uniform random from custom charset
    UNKNOWN = "unknown"                # Human-generated or unknown process


@dataclass(frozen=True)
class GeneratorEntropyResult:
    """Result of generator entropy calculation."""
    mode: GenerationMode
    entropy_bits: float
    assumptions: list[str]
    parameters: dict
    is_valid: bool
    warnings: list[str]


class Generator(ABC):
    """Abstract base class for password generators."""

    @abstractmethod
    def calculate_entropy(self) -> float:
        """Calculate entropy in bits."""
        pass

    @abstractmethod
    def get_assumptions(self) -> list[str]:
        """List assumptions made for this calculation."""
        pass

    @abstractmethod
    def get_parameters(self) -> dict:
        """Return parameters used for calculation."""
        pass


class RandomCharsGenerator(Generator):
    """Uniform random characters from a known charset."""

    def __init__(self, length: int, charset_size: int):
        self.length = length
        self.charset_size = charset_size

    def calculate_entropy(self) -> float:
        if self.length <= 0 or self.charset_size <= 1:
            return 0.0
        return self.length * math.log2(self.charset_size)

    def get_assumptions(self) -> list[str]:
        return [
            f"Each of {self.length} positions chosen independently",
            f"Uniform distribution over {self.charset_size} characters",
            "No character is more likely than another",
            "Attacker knows the charset and length",
        ]

    def get_parameters(self) -> dict:
        return {
            "length": self.length,
            "charset_size": self.charset_size,
        }


class DicewareGenerator(Generator):
    """Diceware-style passphrase: random words from a wordlist."""

    def __init__(self, word_count: int, wordlist_size: int = 7776,
                 separator: str = " ", add_digits: int = 0):
        self.word_count = word_count
        self.wordlist_size = wordlist_size
        self.separator = separator
        self.add_digits = add_digits  # random digits appended

    def calculate_entropy(self) -> float:
        entropy = self.word_count * math.log2(self.wordlist_size)
        if self.add_digits > 0:
            entropy += self.add_digits * math.log2(10)
        return entropy

    def get_assumptions(self) -> list[str]:
        assumptions = [
            f"{self.word_count} words chosen independently",
            f"Uniform distribution over {self.wordlist_size} words",
            "Attacker knows the wordlist and word count",
        ]
        if self.add_digits:
            assumptions.append(f"{self.add_digits} random digits appended")
        return assumptions

    def get_parameters(self) -> dict:
        return {
            "word_count": self.word_count,
            "wordlist_size": self.wordlist_size,
            "separator": self.separator,
            "added_digits": self.add_digits,
        }


class PassphraseGenerator(Generator):
    """Custom passphrase: random words from a custom wordlist."""

    def __init__(self, word_count: int, wordlist_size: int,
                 separator: str = " ", capitalization: str = "none"):
        """
        capitalization: "none", "first", "random", "all"
        """
        self.word_count = word_count
        self.wordlist_size = wordlist_size
        self.separator = separator
        self.capitalization = capitalization

    def calculate_entropy(self) -> float:
        entropy = self.word_count * math.log2(self.wordlist_size)
        # Capitalization adds entropy if random
        if self.capitalization == "random":
            entropy += self.word_count  # 1 bit per word (lower/upper)
        elif self.capitalization == "first":
            entropy += 1  # Only first word capitalized
        elif self.capitalization == "all":
            pass  # No additional entropy (deterministic)
        return entropy

    def get_assumptions(self) -> list[str]:
        assumptions = [
            f"{self.word_count} words chosen independently",
            f"Uniform distribution over {self.wordlist_size} words",
            "Attacker knows the wordlist and word count",
        ]
        if self.capitalization == "random":
            assumptions.append("Random capitalization per word (+1 bit/word)")
        elif self.capitalization == "first":
            assumptions.append("First word capitalized (+1 bit)")
        return assumptions

    def get_parameters(self) -> dict:
        return {
            "word_count": self.word_count,
            "wordlist_size": self.wordlist_size,
            "separator": self.separator,
            "capitalization": self.capitalization,
        }


class CustomCharsetGenerator(Generator):
    """Uniform random from a custom charset."""

    def __init__(self, length: int, charset: str):
        self.length = length
        self.charset = charset
        self.charset_size = len(set(charset))

    def calculate_entropy(self) -> float:
        if self.length <= 0 or self.charset_size <= 1:
            return 0.0
        return self.length * math.log2(self.charset_size)

    def get_assumptions(self) -> list[str]:
        return [
            f"Each of {self.length} positions chosen independently",
            f"Uniform distribution over {self.charset_size} unique characters",
            f"Charset: {repr(self.charset)}",
            "Attacker knows the charset and length",
        ]

    def get_parameters(self) -> dict:
        return {
            "length": self.length,
            "charset_size": self.charset_size,
            "charset": self.charset,
        }


class GeneratorEntropy:
    """Calculate entropy based on generation process."""

    @staticmethod
    def calculate(mode: GenerationMode, **kwargs) -> GeneratorEntropyResult:
        """Calculate entropy for a given generation mode."""
        generator: Optional[Generator] = None
        warnings = []

        if mode == GenerationMode.RANDOM_CHARS:
            length = kwargs.get("length", 0)
            charset_size = kwargs.get("charset_size", 95)
            generator = RandomCharsGenerator(length, charset_size)

        elif mode == GenerationMode.DICEWARE:
            word_count = kwargs.get("word_count", 0)
            wordlist_size = kwargs.get("wordlist_size", 7776)
            separator = kwargs.get("separator", " ")
            add_digits = kwargs.get("add_digits", 0)
            generator = DicewareGenerator(word_count, wordlist_size, separator, add_digits)

        elif mode == GenerationMode.PASSPHRASE:
            word_count = kwargs.get("word_count", 0)
            wordlist_size = kwargs.get("wordlist_size", 10000)
            separator = kwargs.get("separator", " ")
            capitalization = kwargs.get("capitalization", "none")
            generator = PassphraseGenerator(word_count, wordlist_size, separator, capitalization)

        elif mode == GenerationMode.CUSTOM_CHARSET:
            length = kwargs.get("length", 0)
            charset = kwargs.get("charset", "")
            generator = CustomCharsetGenerator(length, charset)

        else:  # UNKNOWN
            return GeneratorEntropyResult(
                mode=mode,
                entropy_bits=0.0,
                assumptions=["Generation process unknown - cannot calculate true entropy"],
                parameters={},
                is_valid=False,
                warnings=["Entropy calculation requires knowing HOW the password was generated"],
            )

        if generator:
            entropy = generator.calculate_entropy()
            assumptions = generator.get_assumptions()
            params = generator.get_parameters()
            is_valid = entropy > 0

            if entropy < 40:
                warnings.append("Entropy below 40 bits - vulnerable to offline attacks")
            elif entropy < 60:
                warnings.append("Entropy below 60 bits - may be vulnerable to determined offline attacks")

            return GeneratorEntropyResult(
                mode=mode,
                entropy_bits=entropy,
                assumptions=assumptions,
                parameters=params,
                is_valid=is_valid,
                warnings=warnings,
            )

        return GeneratorEntropyResult(
            mode=mode,
            entropy_bits=0.0,
            assumptions=["Invalid parameters"],
            parameters=kwargs,
            is_valid=False,
            warnings=["Invalid generator parameters"],
        )

    @staticmethod
    def estimate_from_password(password: str) -> GeneratorEntropyResult:
        """
        BEST EFFORT: Estimate generator entropy from password alone.
        THIS IS A GUESS - only valid if generation process matches assumptions.
        """
        # This is heuristic and should be clearly labeled as such
        from .charset import CharsetAnalyzer
        analyzer = CharsetAnalyzer()
        info = analyzer.analyze(password)

        # Guess mode based on password structure
        words = password.split()
        if len(words) >= 3 and all(w.isalpha() for w in words):
            # Looks like a passphrase
            return GeneratorEntropy.calculate(
                GenerationMode.PASSPHRASE,
                word_count=len(words),
                wordlist_size=10000,  # Conservative estimate
            )
        else:
            # Assume random chars
            return GeneratorEntropy.calculate(
                GenerationMode.RANDOM_CHARS,
                length=len(password),
                charset_size=info.size,
            )