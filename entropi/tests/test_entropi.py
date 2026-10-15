"""
Unit tests for entropi modules.
"""

import unittest
import math
from entropi.charset import CharsetAnalyzer, CharsetInfo
from entropi.generators import (
    GeneratorEntropy, GenerationMode,
    RandomCharsGenerator, DicewareGenerator, PassphraseGenerator,
)
from entropi.heuristic import HeuristicScorer
from entropi.detectors import (
    CommonWordsDetector, LeetDetector, DateDetector,
    RepetitionDetector, SequenceDetector, KeyboardDetector,
    Pattern,
)
from entropi.estimator import TimeEstimator, AttackScenario
from entropi.report import EntropyAnalyzer
from entropi.validators import SyntheticDataset, HeuristicValidator


class TestCharsetAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = CharsetAnalyzer()

    def test_lowercase_only(self):
        info = self.analyzer.analyze("password")
        self.assertTrue(info.has_lower)
        self.assertFalse(info.has_upper)
        self.assertFalse(info.has_digit)
        self.assertFalse(info.has_symbol)
        self.assertEqual(info.size, 26)

    def test_mixed_case(self):
        info = self.analyzer.analyze("Password")
        self.assertTrue(info.has_lower)
        self.assertTrue(info.has_upper)
        self.assertEqual(info.size, 52)

    def test_with_digits(self):
        info = self.analyzer.analyze("Pass123")
        self.assertTrue(info.has_digit)
        self.assertEqual(info.size, 62)

    def test_with_symbols(self):
        info = self.analyzer.analyze("Pass!@#")
        self.assertTrue(info.has_symbol)
        # Pass!@# has lower+upper+symbol = 26+26+33 = 85 (no digits)
        self.assertEqual(info.size, 85)

    def test_non_ascii(self):
        info = self.analyzer.analyze("Pässwörd")
        self.assertTrue(info.has_nonascii)
        self.assertGreater(info.size, 95)

    def test_empty(self):
        info = self.analyzer.analyze("")
        self.assertEqual(info.size, 1)
        self.assertEqual(info.bit_per_char(), 0.0)

    def test_theoretical_entropy(self):
        info = self.analyzer.analyze("Abc123!@#")
        # 95 charset, 9 chars
        expected = 9 * math.log2(95)
        self.assertAlmostEqual(info.theoretical_entropy(9), expected, places=1)


class TestGenerators(unittest.TestCase):
    def test_random_chars(self):
        gen = RandomCharsGenerator(length=16, charset_size=95)
        entropy = gen.calculate_entropy()
        expected = 16 * math.log2(95)
        self.assertAlmostEqual(entropy, expected, places=1)

    def test_diceware(self):
        gen = DicewareGenerator(word_count=6, wordlist_size=7776)
        entropy = gen.calculate_entropy()
        expected = 6 * math.log2(7776)
        self.assertAlmostEqual(entropy, expected, places=1)

    def test_diceware_with_digits(self):
        gen = DicewareGenerator(word_count=5, wordlist_size=7776, add_digits=4)
        entropy = gen.calculate_entropy()
        expected = 5 * math.log2(7776) + 4 * math.log2(10)
        self.assertAlmostEqual(entropy, expected, places=1)

    def test_passphrase(self):
        gen = PassphraseGenerator(word_count=4, wordlist_size=10000)
        entropy = gen.calculate_entropy()
        expected = 4 * math.log2(10000)
        self.assertAlmostEqual(entropy, expected, places=1)

    def test_passphrase_random_caps(self):
        gen = PassphraseGenerator(word_count=4, wordlist_size=10000, capitalization="random")
        entropy = gen.calculate_entropy()
        expected = 4 * math.log2(10000) + 4  # +1 bit per word
        self.assertAlmostEqual(entropy, expected, places=1)

    def test_generator_entropy_calculate(self):
        result = GeneratorEntropy.calculate(
            GenerationMode.RANDOM_CHARS, length=12, charset_size=62
        )
        self.assertTrue(result.is_valid)
        self.assertAlmostEqual(result.entropy_bits, 12 * math.log2(62), places=1)

    def test_generator_entropy_unknown(self):
        result = GeneratorEntropy.calculate(GenerationMode.UNKNOWN)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.entropy_bits, 0.0)


class TestDetectors(unittest.TestCase):
    def setUp(self):
        self.bit_per_char = 6.0  # ~62 charset

    def test_common_words(self):
        detector = CommonWordsDetector()
        patterns = detector.detect("password123", self.bit_per_char)
        self.assertEqual(len(patterns), 1)
        self.assertEqual(patterns[0].label, "common word 'password'")
        self.assertAlmostEqual(patterns[0].cost_bits, math.log2(len(detector._filtered_words)) + 1, places=1)

    def test_common_words_case_insensitive(self):
        detector = CommonWordsDetector()
        patterns = detector.detect("Password123", self.bit_per_char)
        self.assertEqual(len(patterns), 1)

    def test_leet(self):
        detector = LeetDetector()
        patterns = detector.detect("p@ssw0rd", self.bit_per_char)
        # Should find at least the leet version
        leet_patterns = [p for p in patterns if "leet word" in p.label]
        self.assertGreaterEqual(len(leet_patterns), 1)
        self.assertIn("leet word", leet_patterns[0].label)

    def test_years(self):
        detector = DateDetector()
        patterns = detector.detect("hello2024world", self.bit_per_char)
        self.assertEqual(len(patterns), 1)
        self.assertEqual(patterns[0].label, "year '2024'")
        self.assertAlmostEqual(patterns[0].cost_bits, 7.0, places=1)

    def test_year_out_of_range(self):
        detector = DateDetector(year_range=(2000, 2030))
        patterns = detector.detect("year1999", self.bit_per_char)
        self.assertEqual(len(patterns), 0)  # 1999 out of range

    def test_char_repetition(self):
        detector = RepetitionDetector()
        patterns = detector.detect("aaaabbbb", self.bit_per_char)
        # Should find at least the two char repetitions (may also find block repetitions)
        char_patterns = [p for p in patterns if "repeated char" in p.label]
        self.assertGreaterEqual(len(char_patterns), 2)
        for p in char_patterns:
            self.assertIn("repeated char", p.label)

    def test_block_repetition(self):
        detector = RepetitionDetector()
        patterns = detector.detect("abcabcabc", self.bit_per_char)
        self.assertGreaterEqual(len(patterns), 1)
        self.assertIn("repeated block", patterns[0].label)

    def test_ascending_sequence(self):
        detector = SequenceDetector()
        patterns = detector.detect("abcdefg", self.bit_per_char)
        self.assertEqual(len(patterns), 1)
        self.assertIn("ascending", patterns[0].label)

    def test_descending_sequence(self):
        detector = SequenceDetector()
        patterns = detector.detect("7654321", self.bit_per_char)
        self.assertEqual(len(patterns), 1)
        self.assertIn("descending", patterns[0].label)

    def test_keyboard_pattern(self):
        detector = KeyboardDetector()
        patterns = detector.detect("qwertyuiop", self.bit_per_char)
        self.assertGreaterEqual(len(patterns), 1)
        self.assertIn("keyboard", patterns[0].label)

    def test_no_patterns_in_random(self):
        detector = CommonWordsDetector()
        # Random string unlikely to match
        patterns = detector.detect("xK9#mP2$vL5", self.bit_per_char)
        self.assertEqual(len(patterns), 0)


class TestHeuristicScorer(unittest.TestCase):
    def setUp(self):
        self.scorer = HeuristicScorer()

    def test_random_password_high_entropy(self):
        # Random-ish password
        result = self.scorer.score("xK9#mP2$vL5!")
        self.assertGreater(result.effective_entropy, 50)
        self.assertEqual(len(result.patterns_used), 0)

    def test_common_password_low_entropy(self):
        result = self.scorer.score("password123")
        self.assertLess(result.effective_entropy, 20)
        self.assertGreater(len(result.patterns_used), 0)

    def test_leet_password(self):
        result = self.scorer.score("p@ssw0rd2024")
        self.assertLess(result.effective_entropy, 20)
        self.assertGreater(len(result.patterns_used), 0)

    def test_empty_password(self):
        result = self.scorer.score("")
        self.assertEqual(result.effective_entropy, 0.0)
        self.assertEqual(result.naive_entropy, 0.0)

    def test_shannon_entropy(self):
        # All same char
        result = self.scorer.score("aaaaaaaa")
        self.assertEqual(result.shannon_entropy, 0.0)

        # All different chars (8 unique) -> Shannon = 8 * log2(8) = 24
        result = self.scorer.score("abcdefgh")
        expected_shannon = 8 * math.log2(8)  # 24 bits
        self.assertAlmostEqual(result.shannon_entropy, expected_shannon, places=1)
        # Naive entropy uses charset size (26 for lowercase only)
        expected_naive = 8 * math.log2(26)
        self.assertAlmostEqual(result.naive_entropy, expected_naive, places=1)
        # Shannon <= Naive (equality only if all charset chars equally likely)
        self.assertLessEqual(result.shannon_entropy, result.naive_entropy)

    def test_effective_capped_at_naive(self):
        result = self.scorer.score("password")
        self.assertLessEqual(result.effective_entropy, result.naive_entropy)


class TestTimeEstimator(unittest.TestCase):
    def setUp(self):
        self.estimator = TimeEstimator()

    def test_online_attack(self):
        estimates = self.estimator.estimate(30)  # 30 bits
        online = next(e for e in estimates if e.scenario.name == "online")
        # 2^29 / 100 = ~5.3 million seconds = ~61 days
        self.assertGreater(online.time_seconds, 1e6)

    def test_offline_fast(self):
        estimates = self.estimator.estimate(40)
        fast = next(e for e in estimates if e.scenario.name == "offline_fast")
        # 2^39 / 1e10 = ~549 seconds = ~9 minutes
        self.assertLess(fast.time_seconds, 3600)

    def test_format_duration(self):
        self.assertEqual(TimeEstimator._format_duration(0.5), "kurang dari 1 detik")
        self.assertIn("menit", TimeEstimator._format_duration(120))
        self.assertIn("jam", TimeEstimator._format_duration(7200))
        self.assertIn("hari", TimeEstimator._format_duration(86400 * 2))
        self.assertIn("tahun", TimeEstimator._format_duration(86400 * 365 * 2))

    def test_very_high_entropy_does_not_overflow(self):
        # Regression: 2 ** 1024+ used to raise OverflowError (password >~157 chars).
        estimates = self.estimator.estimate(5000)
        for e in estimates:
            self.assertEqual(e.time_formatted, "lebih dari 1 miliar tahun")

    def test_warnings(self):
        warnings = self.estimator.get_warnings()
        self.assertGreater(len(warnings), 0)
        self.assertTrue(any("ILUSTRATIF" in w for w in warnings))


class TestEntropyAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = EntropyAnalyzer()

    def test_analyze_with_mode(self):
        report = self.analyzer.analyze(
            "xK9#mP2$vL5!",
            generation_mode=GenerationMode.RANDOM_CHARS,
            length=12,
            charset_size=95,
        )
        self.assertTrue(report.generator_result.is_valid)
        self.assertGreater(report.generator_result.entropy_bits, 70)

    def test_analyze_unknown_mode(self):
        report = self.analyzer.analyze("password123")
        self.assertFalse(report.generator_result.is_valid)

    def test_format_report_new(self):
        report = self.analyzer.analyze(
            "password123",
            generation_mode=GenerationMode.RANDOM_CHARS,
            length=11,
            charset_size=62,
        )
        output = self.analyzer.format_report(report, show_legacy=False, show_new=True)
        self.assertIn("ENTROPI GENERATOR", output)
        self.assertIn("SKOR HEURISTIK", output)
        self.assertIn("ILUSTRATIF SAJA", output)

    def test_format_report_legacy(self):
        report = self.analyzer.analyze("password123")
        output = self.analyzer.format_report(report, show_legacy=True, show_new=False)
        self.assertIn("Entropi charset (teoritis)", output)
        self.assertIn("Entropi efektif (estimasi)", output)
        self.assertIn("SANGAT LEMAH", output)


class TestSyntheticDataset(unittest.TestCase):
    def setUp(self):
        self.dataset = SyntheticDataset(seed=123)

    def test_random_password(self):
        pwd = self.dataset.random_password(16, "abcdef0123456789")
        self.assertEqual(len(pwd), 16)
        self.assertTrue(all(c in "abcdef0123456789" for c in pwd))

    def test_diceware(self):
        wordlist = ["apple", "banana", "cherry", "date", "elderberry"]
        pwd = self.dataset.diceware_passphrase(4, wordlist)
        words = pwd.split(" ")
        self.assertEqual(len(words), 4)
        self.assertTrue(all(w in wordlist for w in words))

    def test_human_like(self):
        pwd = self.dataset.human_like_password()
        self.assertGreater(len(pwd), 0)

    def test_generate_dataset(self):
        random_pwds, human_pwds = self.dataset.generate_dataset(10, 10)
        self.assertEqual(len(random_pwds), 10)
        self.assertEqual(len(human_pwds), 10)


class TestValidators(unittest.TestCase):
    def test_validator_runs(self):
        validator = HeuristicValidator()
        # Small sample for quick test
        results = validator.run_full_validation(n_samples=50)
        self.assertIn("detectors", results)
        self.assertIn("scorer", results)
        # Separation should be positive (random > human)
        self.assertGreater(results["scorer"]["separation"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)