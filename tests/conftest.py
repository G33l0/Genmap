import os
import shutil
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def genmap_home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "genmap-home"
    monkeypatch.setenv("GENMAP_HOME", str(home))
    return home


@pytest.fixture
def app_paths(genmap_home):
    from genmap.paths import default_paths

    return default_paths().ensure()


def nmap_path():
    return shutil.which("nmap")


requires_nmap = pytest.mark.skipif(nmap_path() is None, reason="Nmap is not installed")
