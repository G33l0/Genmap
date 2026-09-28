"""Locating the Nmap executable on the current system."""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

EXECUTABLE_NAME = "nmap.exe" if sys.platform.startswith("win") else "nmap"


@dataclass(frozen=True)
class LocatedNmap:
    path: Path
    source: str  # "configured", "path", "registry", "default_location"


def _windows_registry_candidates() -> Iterator[Path]:
    if not sys.platform.startswith("win"):
        return
    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        return

    keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Nmap"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Nmap"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Nmap"),
    ]
    for root, key_path in keys:
        try:
            with winreg.OpenKey(root, key_path) as key:
                for value_name in ("InstallLocation", "UninstallString", "DisplayIcon"):
                    try:
                        value, _ = winreg.QueryValueEx(key, value_name)
                    except OSError:
                        continue
                    if not isinstance(value, str) or not value:
                        continue
                    cleaned = value.strip().strip('"')
                    candidate = Path(cleaned)
                    if candidate.is_dir():
                        yield candidate / EXECUTABLE_NAME
                    else:
                        yield candidate.parent / EXECUTABLE_NAME
        except OSError:
            continue


def _default_location_candidates() -> Iterator[Path]:
    if sys.platform.startswith("win"):
        for env_name in ("ProgramFiles(x86)", "ProgramFiles", "ProgramW6432"):
            base = os.environ.get(env_name)
            if base:
                yield Path(base) / "Nmap" / EXECUTABLE_NAME
        yield Path(r"C:\Program Files (x86)\Nmap") / EXECUTABLE_NAME
        yield Path(r"C:\Program Files\Nmap") / EXECUTABLE_NAME
        return
    for directory in ("/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/usr/sbin", "/opt/local/bin"):
        yield Path(directory) / EXECUTABLE_NAME


def validate_executable_path(path: Path) -> Optional[str]:
    """Return a human readable problem with the path or None when it is usable."""
    if not path.exists():
        return f"{path} does not exist."
    if path.is_dir():
        candidate = path / EXECUTABLE_NAME
        if candidate.is_file():
            return f"{path} is a folder. Select {candidate.name} inside it."
        return f"{path} is a folder, not the Nmap executable."
    if not path.is_file():
        return f"{path} is not a regular file."
    if not os.access(path, os.X_OK) and not sys.platform.startswith("win"):
        return f"{path} is not executable."
    return None


def locate_nmap(configured_path: Optional[str] = None) -> Optional[LocatedNmap]:
    """Find Nmap, preferring an explicitly configured path.

    A configured path that does not point at a usable file is treated as
    missing so the caller can report the misconfiguration; the automatic
    search is not attempted in that case because silently scanning with a
    different binary than the one the user chose would be surprising.
    """
    if configured_path:
        candidate = Path(configured_path).expanduser()
        if candidate.is_dir():
            candidate = candidate / EXECUTABLE_NAME
        if validate_executable_path(candidate) is None:
            return LocatedNmap(candidate.resolve(), "configured")
        return None

    found = shutil.which(EXECUTABLE_NAME)
    if found:
        return LocatedNmap(Path(found).resolve(), "path")

    for candidate in _windows_registry_candidates():
        if validate_executable_path(candidate) is None:
            return LocatedNmap(candidate.resolve(), "registry")

    for candidate in _default_location_candidates():
        if validate_executable_path(candidate) is None:
            return LocatedNmap(candidate.resolve(), "default_location")

    return None


def data_directory_candidates(executable: Path) -> list[Path]:
    """Directories where the Nmap data files (scripts, nmap-services) may live."""
    candidates: list[Path] = []
    env_dir = os.environ.get("NMAPDIR")
    if env_dir:
        candidates.append(Path(env_dir))
    exe_dir = executable.parent
    candidates.append(exe_dir)
    candidates.append(exe_dir.parent / "share" / "nmap")
    if not sys.platform.startswith("win"):
        candidates.extend(
            Path(p) for p in ("/usr/share/nmap", "/usr/local/share/nmap", "/opt/homebrew/share/nmap")
        )
    return candidates


def find_data_directory(executable: Path) -> Optional[Path]:
    for candidate in data_directory_candidates(executable):
        if (candidate / "scripts" / "script.db").is_file() or (candidate / "nmap-services").is_file():
            return candidate
    return None
