"""Filesystem locations used by the application.

Windows keeps everything under %LOCALAPPDATA%\\Genmap. Other platforms follow
the XDG base directory convention. Setting GENMAP_HOME forces a single
self-contained directory, which is handy for portable installs and tests.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from genmap import APP_NAME


@dataclass(frozen=True)
class AppPaths:
    config_dir: Path
    data_dir: Path
    log_dir: Path
    cache_dir: Path

    @property
    def settings_file(self) -> Path:
        return self.config_dir / "settings.json"

    @property
    def scans_dir(self) -> Path:
        return self.data_dir / "scans"

    @property
    def profiles_dir(self) -> Path:
        return self.data_dir / "profiles"

    @property
    def database_file(self) -> Path:
        return self.data_dir / "genmap.sqlite3"

    def ensure(self) -> "AppPaths":
        for directory in (
            self.config_dir,
            self.data_dir,
            self.log_dir,
            self.cache_dir,
            self.scans_dir,
            self.profiles_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        return self


def _from_single_root(root: Path) -> AppPaths:
    return AppPaths(
        config_dir=root / "config",
        data_dir=root / "data",
        log_dir=root / "logs",
        cache_dir=root / "cache",
    )


def default_paths() -> AppPaths:
    override = os.environ.get("GENMAP_HOME")
    if override:
        return _from_single_root(Path(override).expanduser())

    if sys.platform.startswith("win"):
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            local = str(Path.home() / "AppData" / "Local")
        return _from_single_root(Path(local) / APP_NAME)

    if sys.platform == "darwin":
        support = Path.home() / "Library" / "Application Support" / APP_NAME
        return AppPaths(
            config_dir=support / "config",
            data_dir=support / "data",
            log_dir=Path.home() / "Library" / "Logs" / APP_NAME,
            cache_dir=Path.home() / "Library" / "Caches" / APP_NAME,
        )

    home = Path.home()
    config_home = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
    data_home = Path(os.environ.get("XDG_DATA_HOME", home / ".local" / "share"))
    state_home = Path(os.environ.get("XDG_STATE_HOME", home / ".local" / "state"))
    cache_home = Path(os.environ.get("XDG_CACHE_HOME", home / ".cache"))
    name = APP_NAME.lower()
    return AppPaths(
        config_dir=config_home / name,
        data_dir=data_home / name,
        log_dir=state_home / name / "logs",
        cache_dir=cache_home / name,
    )
