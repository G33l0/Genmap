"""Locating and checking the data files Nmap reads at run time.

Nmap looks for each data file separately, in this order (nmap.cc,
nmap_fetchfile): --datadir, the NMAPDIR environment variable, the user's
Nmap folder (%APPDATA%\\nmap on Windows, ~/.nmap elsewhere), the folder of
the nmap executable, then on other systems <exe>/../share/nmap and the
compiled in NMAPDATADIR. Genmap follows the same order so it reports the
files Nmap will really use. NMAPDATADIR is not visible from outside, so the
usual install prefixes stand in for it and are marked as assumed.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from genmap.nmap.version import NmapVersion

_ASSUMED_PREFIXES = ("/usr/share/nmap", "/usr/local/share/nmap", "/opt/homebrew/share/nmap")


@dataclass(frozen=True)
class SearchDirectory:
    path: Path
    origin: str
    assumed: bool = False


@dataclass(frozen=True)
class DataFileSpec:
    name: str
    purpose: str
    needed_for: str
    missing_level: str  # "error", "warning", or "info"
    counter: Optional[Callable[[str], str]] = None
    until_version: Optional[tuple[int, int]] = None  # no longer read from this version on


@dataclass(frozen=True)
class DataFileStatus:
    spec: DataFileSpec
    path: Optional[Path]
    origin: Optional[str] = None
    assumed_location: bool = False
    summary: str = ""
    problem: Optional[str] = None

    @property
    def found(self) -> bool:
        return self.path is not None and self.problem is None


def _amount(total: int, singular: str, plural: str) -> str:
    return f"{total:,} {singular if total == 1 else plural}"


def _count_lines(prefixes: tuple[str, ...], singular: str, plural: str) -> Callable[[str], str]:
    def count(text: str) -> str:
        return _amount(sum(1 for line in text.splitlines() if line.startswith(prefixes)), singular, plural)
    return count


def _count_entries(singular: str, plural: str) -> Callable[[str], str]:
    def count(text: str) -> str:
        total = sum(1 for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#"))
        return _amount(total, singular, plural)
    return count


def _count_probes(text: str) -> str:
    lines = text.splitlines()
    probes = sum(1 for line in lines if line.startswith("Probe "))
    matches = sum(1 for line in lines if line.startswith(("match ", "softmatch ")))
    return f"{_amount(probes, 'probe', 'probes')}, {_amount(matches, 'match rule', 'match rules')}"


DATA_FILES: tuple[DataFileSpec, ...] = (
    DataFileSpec("nmap-services", "Port names and how often each port is open",
                 "Named ports, --top-ports, and fast scans (-F)", "warning", _count_entries("entry", "entries")),
    DataFileSpec("nmap-service-probes", "Probes and match rules for version detection",
                 "Version detection (-sV); since Nmap 7.94 also UDP scan payloads", "warning", _count_probes),
    DataFileSpec("nmap-os-db", "Operating system fingerprints", "OS detection (-O)", "warning",
                 _count_lines(("Fingerprint ",), "fingerprint", "fingerprints")),
    DataFileSpec("nmap-payloads", "Protocol specific UDP payloads", "UDP scans before Nmap 7.94", "info",
                 _count_lines(("udp ",), "payload", "payloads"), until_version=(7, 94)),
    DataFileSpec("nmap-protocols", "IP protocol names", "IP protocol scans (-sO)", "info", _count_entries("protocol", "protocols")),
    DataFileSpec("nmap-mac-prefixes", "Hardware vendor names for MAC addresses", "Vendor names next to MAC addresses", "info",
                 _count_entries("vendor prefix", "vendor prefixes")),
    DataFileSpec("nmap-rpc", "RPC program numbers", "RPC identification during version detection", "info",
                 _count_entries("program", "programs")),
    DataFileSpec("nse_main.lua", "The Nmap Scripting Engine runtime", "Every NSE script (-sC, --script)", "warning"),
    DataFileSpec("scripts/script.db", "Index of installed NSE scripts and their categories",
                 "Selecting scripts by category, and Genmap's script browser", "warning", _count_lines(("Entry",), "script", "scripts")),
)


def search_directories(
    executable: Optional[Path],
    datadir: Optional[Path] = None,
    *,
    environ: Optional[dict[str, str]] = None,
    windows: Optional[bool] = None,
) -> list[SearchDirectory]:
    environ = os.environ if environ is None else environ
    windows = sys.platform.startswith("win") if windows is None else windows
    directories: list[SearchDirectory] = []
    if datadir is not None:
        directories.append(SearchDirectory(datadir, "the data directory setting (--datadir)"))
    if environ.get("NMAPDIR"):
        directories.append(SearchDirectory(Path(environ["NMAPDIR"]), "NMAPDIR environment variable"))
    if windows:
        if environ.get("APPDATA"):
            directories.append(SearchDirectory(Path(environ["APPDATA"]) / "nmap", "your Nmap application data folder"))
    else:
        directories.append(SearchDirectory(Path.home() / ".nmap", "your ~/.nmap folder"))
    if executable is not None:
        directories.append(SearchDirectory(executable.parent, "the Nmap program folder"))
        if not windows:
            directories.append(SearchDirectory(executable.parent / ".." / "share" / "nmap", "the share folder next to Nmap"))
    if not windows:
        directories.extend(SearchDirectory(Path(p), "a standard install location", assumed=True) for p in _ASSUMED_PREFIXES)
    return directories


def _readable(path: Path) -> bool:
    try:
        return path.is_file() and os.access(path, os.R_OK)
    except OSError:
        return False


def resolve_data_file(name: str, directories: list[SearchDirectory]) -> tuple[Optional[Path], Optional[SearchDirectory]]:
    for directory in directories:
        candidate = directory.path / name
        if _readable(candidate):
            return Path(os.path.normpath(candidate)), directory
    return None, None


def check_data_files(
    executable: Optional[Path],
    datadir: Optional[Path] = None,
    version: Optional[NmapVersion] = None,
    *,
    directories: Optional[list[SearchDirectory]] = None,
) -> list[DataFileStatus]:
    directories = directories if directories is not None else search_directories(executable, datadir)
    statuses: list[DataFileStatus] = []
    for spec in DATA_FILES:
        if spec.until_version and version is not None and version.at_least(*spec.until_version):
            continue
        path, origin = resolve_data_file(spec.name, directories)
        if path is None:
            statuses.append(DataFileStatus(spec, None, problem="Not found in any folder Nmap searches."))
            continue
        summary = ""
        problem = None
        if spec.counter is not None:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                problem = f"Could not be read: {exc}"
            else:
                if not text.strip():
                    problem = "The file is empty."
                else:
                    summary = spec.counter(text)
        statuses.append(DataFileStatus(spec, path, origin.origin if origin else None, origin.assumed if origin else False, summary, problem))
    return statuses


def status_for(statuses: list[DataFileStatus], name: str) -> Optional[DataFileStatus]:
    return next((s for s in statuses if s.spec.name == name), None)
