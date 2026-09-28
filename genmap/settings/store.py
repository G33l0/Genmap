"""Loading and saving settings as JSON with tolerant recovery."""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from pydantic import ValidationError

from genmap.errors import SettingsError
from genmap.settings.schema import AppSettings

log = logging.getLogger(__name__)


class SettingsStore:
    """Owns the AppSettings instance and persists it atomically."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.settings = AppSettings()
        self.load_problem: Optional[SettingsError] = None
        self._listeners: list[Callable[[AppSettings], None]] = []

    def subscribe(self, listener: Callable[[AppSettings], None]) -> None:
        self._listeners.append(listener)

    def notify(self) -> None:
        for listener in list(self._listeners):
            try:
                listener(self.settings)
            except Exception:
                log.exception("Settings listener failed")

    def load(self) -> AppSettings:
        self.load_problem = None
        if not self.path.exists():
            self.settings = AppSettings()
            return self.settings
        try:
            raw = self.path.read_text(encoding="utf-8")
            data = json.loads(raw) if raw.strip() else {}
            self.settings = AppSettings.model_validate(data)
        except (OSError, json.JSONDecodeError, ValidationError) as exc:
            backup = self._back_up_corrupt_file()
            self.settings = AppSettings()
            self.load_problem = SettingsError(
                "The settings file could not be read, so default settings are in use.",
                remedy=f"The unreadable file was kept as {backup.name}." if backup else None,
                details=str(exc),
            )
            log.warning("Settings file unreadable: %s", exc)
        return self.settings

    def _back_up_corrupt_file(self) -> Optional[Path]:
        try:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            backup = self.path.with_name(f"{self.path.stem}.corrupt-{stamp}{self.path.suffix}")
            shutil.copy2(self.path, backup)
            return backup
        except OSError:
            return None

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = self.settings.model_dump_json(indent=2)
        try:
            fd, temp_name = tempfile.mkstemp(dir=self.path.parent, prefix=".settings-", suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.replace(temp_name, self.path)
        except OSError as exc:
            raise SettingsError(
                "Settings could not be saved.",
                remedy=f"Check that {self.path.parent} is writable.",
                details=str(exc),
            ) from exc
        self.notify()

    def replace(self, settings: AppSettings) -> None:
        self.settings = settings
        self.save()
