"""
Detector for common names (Indonesian + international).
"""

import re
from typing import List, Set
from .base import PatternDetector, Pattern


# Common Indonesian names (top 100+)
INDONESIAN_NAMES: Set[str] = {
    # Male
    "muhammad", "ahmad", "budi", "siti", "agus", "sutrisno", "wahyu", "eko",
    "joko", "herman", "hendra", "adi", "dwi", "tri", "yudi", "rudi", "andi",
    "bambang", "slamet", "sumanto", "suranto", "parno", "kasno", "paino",
    "sukirno", "sumarno", "wasis", "yanto", "sugeng", "supri", "mulyono",
    "hartono", "gunawan", "haryanto", "susilo", "prabowo", "jokowi", "anies",
    "ganjar", "ridwan", "kamil", "erick", "thohir", "sandiaga", "gibran",
    # Female
    "sri", "dewi", "tri", "dwi", "yuni", "yuli", "lestari", "wati", "sari",
    "ayu", "putri", "ratna", "indah", "fitri", "novi", "ratih", "susanti",
    "yuliana", "novita", "eka", "maya", "rita", "nina", "lina", "tina",
    "dina", "rina", "yani", "susi", "yanti", "wulan", "sinta", "desi",
    " Novi", "Siti", "Fatma", "Aisyah", "Khadijah", "Zahra", "Aulia",
    # Unisex/Common
    "putra", "putri", "adi", "dwi", "tri", "eko", "wahyu", "bayu", "candra",
    "dewa", "gusti", "nyoman", "ketut", "made", "wayan", "komang",
}

# International common names
INTERNATIONAL_NAMES: Set[str] = {
    "john", "jane", "michael", "mary", "david", "sarah", "james", "jennifer",
    "robert", "lisa", "william", "karen", "richard", "nancy", "joseph", "betty",
    "thomas", "dorothy", "charles", "sandra", "christopher", "ashley", "daniel",
    "kimberly", "matthew", "donna", "anthony", "emily", "mark", "michelle",
    "donald", "carol", "steven", "amanda", "paul", "melissa", "andrew", "deborah",
    "joshua", "stephanie", "kenneth", "laura", "kevin", "rebecca", "brian", "sharon",
    "george", "cynthia", "edward", "kathleen", "ronald", "amy", "timothy", "angela",
    "jason", "shirley", "jeffrey", "anna", "ryan", "brenda", "jacob", "pamela",
    "gary", "nicole", "nicholas", "emma", "eric", "helen", "jonathan", "samantha",
    "stephen", "katherine", "larry", "christine", "justin", "debra", "scott", "rachel",
    "brandon", "catherine", "benjamin", "virginia", "samuel", "ruth", "gregory", "kathryn",
    "alexander", "laura", "patrick", "sarah", "frank", "hannah", "raymond", "ashley",
    "jack", "megan", "dennis", "kelly", "jerry", "ashley", "tyler", "amber",
    "aaron", "emily", "jose", "ashley", "henry", "ashley", "douglas", "ashley",
    "peter", "ashley", "adam", "ashley", "zachary", "ashley", "nathan", "ashley",
    "walter", "ashley", "kyle", "ashley", "harold", "ashley", "carl", "ashley",
    "jeremy", "ashley", "keith", "ashley", "roger", "ashley", "gerald", "ashley",
    "ethan", "ashley", "arthur", "ashley", "sean", "ashley", "christian", "ashley",
    "austin", "ashley", "noah", "ashley", "lawrence", "ashley", "jordan", "ashley",
    "dylan", "ashley", "caleb", "ashley", "connor", "ashley", "isaac", "ashley",
    "oliver", "ashley", "cameron", "ashley", "luke", "ashley", "owen", "ashley",
    "liam", "ashley", "mason", "ashley", "gavin", "ashley", "chase", "ashley",
    "logan", "ashley", "alex", "ashley", "blake", "ashley", "jaxon", "ashley",
    "julian", "ashley", "ryder", "ashley", "hunter", "ashley", "chase", "ashley",
    "landon", "ashley", "tyler", "ashley", "colton", "ashley", "austin", "ashley",
    "brody", "ashley", "hayden", "ashley", "tristan", "ashley", "jonah", "ashley",
    "damian", "ashley", "nolan", "ashley", "bryson", "ashley", "austin", "ashley",
}

# Combine all names
ALL_NAMES = INDONESIAN_NAMES | INTERNATIONAL_NAMES


class NamesDetector(PatternDetector):
    """Detects common names in passwords."""

    def __init__(self, name_set: Set[str] = None, min_length: int = 3):
        self._names = name_set or ALL_NAMES
        self._min_length = min_length
        self._filtered = {n for n in self._names if len(n) >= min_length}

    @property
    def name(self) -> str:
        return "names"

    def detect(self, password: str, bit_per_char: float) -> List[Pattern]:
        results = []
        low = password.lower()

        for name in self._filtered:
            if len(name) < self._min_length:
                continue
            for match in re.finditer(re.escape(name), low):
                # Cost: log2(name_count) + 1 for position
                cost = math.log2(len(self._filtered)) + 1
                results.append(self._make_pattern(
                    start=match.start(),
                    end=match.end(),
                    label=f"name '{name}'",
                    cost_bits=cost,
                    metadata={"name": name, "nameset_size": len(self._filtered)},
                ))

        return results


import math