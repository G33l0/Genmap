import pytest

from genmap.core.timespec import normalize_time_spec, parse_time_spec
from genmap.errors import ConfigurationError


@pytest.mark.parametrize(
    "text, seconds",
    [("500ms", 0.5), ("30s", 30), ("5m", 300), ("2h", 7200), ("1.5s", 1.5), ("15", 15), ("20000", 20)],
)
def test_parse(text, seconds):
    assert parse_time_spec(text) == pytest.approx(seconds)


@pytest.mark.parametrize("text", ["", "fast", "10d", "-5s", "5 s"])
def test_invalid(text):
    with pytest.raises(ConfigurationError):
        parse_time_spec(text)


def test_normalize_trims():
    assert normalize_time_spec(" 5m ") == "5m"
