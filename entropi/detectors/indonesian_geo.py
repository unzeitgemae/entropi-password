"""
Detector for Indonesian geographic locations (cities, provinces, islands).
"""

import re
from typing import List, Set
from .base import PatternDetector, Pattern


# Indonesian provinces
INDONESIAN_PROVINCES: Set[str] = {
    "aceh", "sumatera utara", "sumatera barat", "riau", "jambi", "sumatera selatan",
    "bengkulu", "lampung", "kepulauan bangka belitung", "kepulauan riau",
    "dk jakarta", "jawa barat", "jawa tengah", "di yogyakarta", "jawa timur",
    "banten", "bali", "nusa tenggara barat", "nusa tenggara timur",
    "kalimantan barat", "kalimantan tengah", "kalimantan selatan", "kalimantan timur",
    "kalimantan utara", "sulawesi utara", "sulawesi tengah", "sulawesi selatan",
    "sulawesi tenggara", "gorontalo", "sulawesi barat", "maluku", "maluku utara",
    "papua barat", "papua", "papua selatan", "papua tengah", "papua pegunungan",
}

# Major Indonesian cities
INDONESIAN_CITIES: Set[str] = {
    "jakarta", "surabaya", "bandung", "bekasi", "medan", "tangerang", "depok",
    "semarang", "palembang", "makassar", "south tangerang", "batam", "pekanbaru",
    "bogor", "bandar lampung", "malang", "padang", "denpasar", "samarinda",
    "tasikmalaya", "serang", "cilegon", "cimahi", "mataram", "kupang", "pontianak",
    "balikpapan", "manado", "jambi", "ambon", "banda aceh", "palu", "kendari",
    "gorontalo", "mamuju", "mamor", "sofifi", "jayapura", "sorong", "manokwari",
    "yogyakarta", "solo", "salatiga", "magelang", "tegal", "pekalongan", "cirebon",
    "sukabumi", "cianjur", "garut", "tasikmalaya", "ciamis", "kuningan", "indramayu",
    "majalengka", "sumedang", "purwakarta", "subang", "karawang", "bekasi",
}

# Indonesian islands
INDONESIAN_ISLANDS: Set[str] = {
    "sumatera", "jawa", "kalimantan", "sulawesi", "papua", "bali", "lombok",
    "sumbawa", "flores", "timor", "ceram", "buru", "halmahera", "seram",
    "batam", "bintan", "batam", "belitung", "bangka", "nanggala", "weh",
}

# Combine all
INDONESIAN_GEO = INDONESIAN_PROVINCES | INDONESIAN_CITIES | INDONESIAN_ISLANDS


class IndonesianGeoDetector(PatternDetector):
    """Detects Indonesian geographic names in passwords."""

    def __init__(self, geo_set: Set[str] = None, min_length: int = 4):
        self._geo = geo_set or INDONESIAN_GEO
        self._min_length = min_length
        self._filtered = {g for g in self._geo if len(g) >= min_length}

    @property
    def name(self) -> str:
        return "indonesian_geo"

    def detect(self, password: str, bit_per_char: float) -> List[Pattern]:
        results = []
        low = password.lower()
        low_no_space = low.replace(" ", "")

        # Search in both versions, but avoid duplicates
        seen = set()
        for geo in self._filtered:
            if len(geo) < self._min_length:
                continue
            geo_no_space = geo.replace(" ", "")
            for search_text in [low, low_no_space]:
                for match in re.finditer(re.escape(geo_no_space), search_text):
                    key = (match.start(), match.end(), geo)
                    if key in seen:
                        continue
                    seen.add(key)
                    cost = math.log2(len(self._filtered)) + 1
                    results.append(self._make_pattern(
                        start=match.start(),
                        end=match.end(),
                        label=f"lokasi Indonesia '{geo}'",
                        cost_bits=cost,
                        metadata={"location": geo, "geo_size": len(self._filtered)},
                    ))

        return results


import math