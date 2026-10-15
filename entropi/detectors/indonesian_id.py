"""
Detector for Indonesian identity patterns (phone, NIK, NPWP, etc.).
"""

import re
from typing import List
from .base import PatternDetector, Pattern


class IndonesianIDDetector(PatternDetector):
    """Detects Indonesian identity number patterns."""

    @property
    def name(self) -> str:
        return "indonesian_id"

    def detect(self, password: str, bit_per_char: float) -> List[Pattern]:
        results = []

        # Phone numbers (Indonesian format)
        phone_patterns = [
            (r"(\+62|62|0)8\d{8,11}", "nomor HP Indonesia", 20),  # ~20 bits for phone
            (r"(\+62|62|0)2\d{8,9}", "nomor telepon rumah", 18),
        ]

        for pattern, label, cost in phone_patterns:
            for match in re.finditer(pattern, password):
                results.append(self._make_pattern(
                    start=match.start(),
                    end=match.end(),
                    label=label,
                    cost_bits=cost,
                    metadata={"matched": match.group(), "type": "phone"},
                ))

        # NIK (Nomor Induk Kependudukan) - 16 digits
        # Format: PPDDKKDDMMYYXXXX
        nik_pattern = r"\d{16}"
        for match in re.finditer(nik_pattern, password):
            # Validate it could be a NIK (basic check)
            nik = match.group()
            if self._could_be_nik(nik):
                results.append(self._make_pattern(
                    start=match.start(),
                    end=match.end(),
                    label="NIK (Nomor Induk Kependudukan)",
                    cost_bits=30,  # NIK has structure, not fully random
                    metadata={"matched": nik, "type": "nik"},
                ))

        # NPWP (Nomor Pokok Wajib Pajak) - 15 digits with format
        npwp_pattern = r"\d{2}\.\d{3}\.\d{3}\.\d{1}-\d{3}\.\d{3}"
        for match in re.finditer(npwp_pattern, password):
            results.append(self._make_pattern(
                start=match.start(),
                end=match.end(),
                label="NPWP (Nomor Pokok Wajib Pajak)",
                cost_bits=25,
                metadata={"matched": match.group(), "type": "npwp"},
            ))

        # SIM (Surat Izin Mengemudi) - old format 12 digits
        sim_pattern = r"\d{12}"
        for match in re.finditer(sim_pattern, password):
            # Avoid overlapping with NIK
            if not any(r.overlaps(Pattern(match.start(), match.end(), "", 0, "")) for r in results):
                results.append(self._make_pattern(
                    start=match.start(),
                    end=match.end(),
                    label="SIM (Nomor Surat Izin Mengemudi)",
                    cost_bits=20,
                    metadata={"matched": match.group(), "type": "sim"},
                ))

        return results

    def _could_be_nik(self, nik: str) -> bool:
        """Basic NIK validation."""
        if len(nik) != 16 or not nik.isdigit():
            return False
        # Check province code (first 2 digits) - valid range 11-94
        try:
            prov = int(nik[:2])
            if prov < 11 or prov > 94:
                return False
            # Check date of birth (digits 7-12: DDMMYY)
            dd = int(nik[6:8])
            mm = int(nik[8:10])
            yy = int(nik[10:12])
            if dd < 1 or dd > 31 or mm < 1 or mm > 12:
                return False
        except ValueError:
            return False
        return True


# Indonesian vehicle plates
class IndonesianPlateDetector(PatternDetector):
    """Detects Indonesian vehicle license plates."""

    @property
    def name(self) -> str:
        return "indonesian_plate"

    def detect(self, password: str, bit_per_char: float) -> List[Pattern]:
        results = []
        # Indonesian plate format (strict):
        # Must have valid region code + 1-4 digits + 1-3 letters
        # With spaces: B 1234 ABC or BB 1234 AB
        # Without: B1234ABC or BB1234AB
        
        # Check with spaces first
        spaced_pattern = r"([A-Z]{1,2})\s(\d{1,4})\s([A-Z]{1,3})"
        for match in re.finditer(spaced_pattern, password, re.IGNORECASE):
            region, digits, series = match.group(1), match.group(2), match.group(3)
            if self._valid_region_code(region):
                plate = region + digits + series
                if 7 <= len(plate) <= 9:
                    results.append(self._make_pattern(
                        start=match.start(),
                        end=match.end(),
                        label=f"plat nomor Indonesia '{match.group()}'",
                        cost_bits=18,
                        metadata={"plate": plate, "type": "vehicle_plate"},
                    ))

        # Check without spaces - more strict
        # Must match at word boundaries or string boundaries
        nospace_pattern = r"(?<![A-Z0-9])([A-Z]{1,2})(\d{1,4})([A-Z]{1,3})(?![A-Z0-9])"
        for match in re.finditer(nospace_pattern, password, re.IGNORECASE):
            region, digits, series = match.group(1), match.group(2), match.group(3)
            if self._valid_region_code(region):
                plate = region + digits + series
                if 7 <= len(plate) <= 9:
                    # Check if this overlaps with a spaced match
                    overlaps = False
                    for r in results:
                        if not (match.end() <= r.start or r.end <= match.start()):
                            overlaps = True
                            break
                    if not overlaps:
                        results.append(self._make_pattern(
                            start=match.start(),
                            end=match.end(),
                            label=f"plat nomor Indonesia '{match.group()}'",
                            cost_bits=18,
                            metadata={"plate": plate, "type": "vehicle_plate"},
                        ))
        return results

    def _valid_region_code(self, code: str) -> bool:
        """Check if exact code is a valid region code."""
        region_codes = {
            "B", "BB", "BD", "BE", "BG", "BH", "BK", "BL", "BM", "BN", "BP", "BR",
            "D", "DA", "DB", "DC", "DD", "DE", "DG", "DH", "DK", "DL", "DM", "DN",
            "DR", "DT", "E", "EA", "EB", "ED", "F", "G", "H", "K", "KB", "KC", "KD",
            "KH", "KL", "KM", "KN", "KR", "KS", "KT", "KU", "KW", "L", "LB", "LD",
            "M", "MA", "MB", "MC", "MD", "MH", "ML", "MM", "MN", "MR", "MS", "MT",
            "N", "NB", "NC", "ND", "NE", "NF", "NG", "NH", "NK", "NL", "NM", "NR",
            "P", "PA", "PB", "PC", "PD", "PE", "PK", "PL", "PM", "PN", "PR", "PT",
            "R", "S", "SA", "SB", "SC", "SE", "SF", "SG", "SH", "SI", "SK", "SL",
            "SM", "SN", "SR", "SS", "ST", "T", "TA", "TB", "TC", "TD", "TE", "TF",
            "W", "WA", "WB", "WC", "WD", "WE", "WF", "WG", "WH", "Z",
        }
        return code.upper() in region_codes


# Combined detector
class IndonesianPatternsDetector(PatternDetector):
    """Combined detector for all Indonesian-specific patterns."""

    def __init__(self):
        self.id_detector = IndonesianIDDetector()
        self.plate_detector = IndonesianPlateDetector()
        self.geo_detector = None  # Will be set from outside

    @property
    def name(self) -> str:
        return "indonesian_patterns"

    def detect(self, password: str, bit_per_char: float) -> List[Pattern]:
        results = []
        results.extend(self.id_detector.detect(password, bit_per_char))
        results.extend(self.plate_detector.detect(password, bit_per_char))
        return results