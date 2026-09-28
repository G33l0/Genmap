"""Validation of Nmap time specifications such as 30s, 5m, 1500ms, or 2h."""

from __future__ import annotations

import re

from genmap.errors import ConfigurationError

_TIME = re.compile(r"^(?P<value>\d+(?:\.\d+)?)(?P<unit>ms|s|m|h)?$", re.IGNORECASE)
_UNIT_SECONDS = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0, None: 1.0}


def parse_time_spec(text: str, *, option: str = "value") -> float:
    """Return the duration in seconds, raising ConfigurationError if invalid.

    Nmap treats a bare number as seconds when it is below a threshold and
    as milliseconds otherwise, which trips people up. Genmap accepts the same
    syntax but reports the interpretation Nmap itself documents.
    """
    candidate = text.strip()
    match = _TIME.match(candidate)
    if not match:
        raise ConfigurationError(
            f"'{text}' is not a valid time for {option}.",
            remedy="Use a number with a unit, for example 500ms, 30s, 5m, or 1h.",
        )
    value = float(match.group("value"))
    unit = match.group("unit")
    unit = unit.lower() if unit else None
    if unit is None and value >= 10000:
        # Nmap interprets large unitless numbers as milliseconds.
        return value / 1000.0
    return value * _UNIT_SECONDS[unit]


def normalize_time_spec(text: str, *, option: str = "value") -> str:
    parse_time_spec(text, option=option)
    return text.strip()
