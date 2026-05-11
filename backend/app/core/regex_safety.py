from __future__ import annotations

import re
import threading

_RE_PROBE = "a" * 50 + "!" + "a" * 50


def regex_safety_error(
    pattern: str, *, max_length: int = 300, max_alternations: int | None = None
) -> str | None:
    if not isinstance(pattern, str) or len(pattern) > max_length:
        return "invalid/too-long regex"
    try:
        compiled = re.compile(pattern)
    except re.error:
        return "invalid regex"

    raw = compiled.pattern
    if re.search(r"\([^)]*[+*][^)]*\)[+*]", raw):
        return "unsafe regex (nested quantifiers)"
    if max_alternations is not None and raw.count("|") > max_alternations:
        return f"regex has excessive alternation (>{max_alternations} branches)"
    if not regex_probe_timed(pattern):
        return "regex causes excessive backtracking (ReDoS risk)"
    return None


def is_safe_regex(pattern: str, **kwargs) -> bool:
    return regex_safety_error(pattern, **kwargs) is None


def regex_probe_timed(pattern: str) -> bool:
    ok: list[bool] = [True]

    def _run() -> None:
        try:
            re.search(pattern, _RE_PROBE, flags=re.IGNORECASE)
        except Exception:
            ok[0] = False

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=0.5)
    return not t.is_alive() and ok[0]
