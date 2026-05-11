from __future__ import annotations

import re
import unicodedata


def normalize_for_matching(text: str) -> str:
    """
    Normalize Unicode and whitespace to reduce text-filter evasion:
    - NFKC collapses full-width and visually similar Unicode forms.
    - Zero-width characters are stripped.
    - Internal whitespace/newlines collapse to single spaces.
    """
    out = unicodedata.normalize("NFKC", text)
    out = re.sub(r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]", "", out)
    return re.sub(r"\s+", " ", out)
