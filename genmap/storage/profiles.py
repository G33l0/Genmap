"""Scan profiles: named, reusable ScanConfiguration objects.

A profile describes how to scan, not what to scan, so targets are removed
before a configuration is stored. Built in starting points are copied into
the table once so they can be edited like any other profile; the
``builtin_key`` column remembers where they came from so they can be reset.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional

from pydantic import ValidationError
from sqlalchemy import func, select

from genmap.core.presets import PRESETS, preset_by_key
from genmap.core.scan_config import ScanConfiguration, TargetSpecification, issues_from_validation_error
from genmap.errors import GenmapError
from genmap.storage.database import Database
from genmap.storage.models import Profile

PROFILE_FILE_FORMAT = "genmap.profile"
PROFILE_FILE_VERSION = 1
MAX_NAME_LENGTH = 120


class ProfileError(GenmapError):
    default_message = "The profile could not be saved."


@dataclass(frozen=True)
class ProfileInfo:
    id: int
    name: str
    description: str
    configuration: ScanConfiguration
    builtin_key: Optional[str]
    created_at: datetime
    updated_at: datetime


def strip_targets(config: ScanConfiguration) -> ScanConfiguration:
    clone = config.model_copy(deep=True)
    clone.targets = TargetSpecification()
    clone.name = ""
    clone.description = ""
    return clone


def _clean_name(name: str) -> str:
    cleaned = " ".join(name.split())
    if not cleaned:
        raise ProfileError("A profile needs a name.")
    if len(cleaned) > MAX_NAME_LENGTH:
        raise ProfileError(f"Profile names can be at most {MAX_NAME_LENGTH} characters.")
    return cleaned


def _info(row: Profile) -> ProfileInfo:
    return ProfileInfo(
        id=row.id,
        name=row.name,
        description=row.description,
        configuration=ScanConfiguration.model_validate(row.configuration),
        builtin_key=row.builtin_key,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


class ProfileRepository:
    def __init__(self, database: Database) -> None:
        self.db = database

    def _name_taken(self, session, name: str, exclude_id: Optional[int] = None) -> bool:
        query = select(Profile.id).where(func.lower(Profile.name) == name.lower())
        if exclude_id is not None:
            query = query.where(Profile.id != exclude_id)
        return session.scalar(query) is not None

    def _unique_name(self, session, base: str) -> str:
        candidate = base[:MAX_NAME_LENGTH]
        counter = 2
        while self._name_taken(session, candidate):
            suffix = f" ({counter})"
            candidate = base[: MAX_NAME_LENGTH - len(suffix)] + suffix
            counter += 1
        return candidate

    def seed_builtins(self, already_seeded: Iterable[str]) -> list[str]:
        """Add built in profiles that have never been seeded. Returns the keys added.

        Keys already seeded are skipped even if the user deleted the profile,
        so deletions stick.
        """
        done = set(already_seeded)
        added: list[str] = []
        with self.db.session() as session:
            for preset in PRESETS:
                if preset.key in done:
                    continue
                exists = session.scalar(select(Profile.id).where(Profile.builtin_key == preset.key))
                if exists is None:
                    config = strip_targets(preset.build())
                    session.add(
                        Profile(
                            name=self._unique_name(session, preset.name),
                            description=preset.description,
                            configuration=config.model_dump(mode="json"),
                            builtin_key=preset.key,
                        )
                    )
                added.append(preset.key)
        return added

    def list(self) -> list[ProfileInfo]:
        with self.db.session() as session:
            rows = session.scalars(select(Profile).order_by(Profile.builtin_key.is_(None), func.lower(Profile.name)))
            return [_info(row) for row in rows]

    def get(self, profile_id: int) -> ProfileInfo:
        with self.db.session() as session:
            row = session.get(Profile, profile_id)
            if row is None:
                raise ProfileError("That profile no longer exists.")
            return _info(row)

    def find_by_name(self, name: str) -> Optional[ProfileInfo]:
        with self.db.session() as session:
            row = session.scalar(select(Profile).where(func.lower(Profile.name) == name.strip().lower()))
            return _info(row) if row else None

    def create(self, name: str, config: ScanConfiguration, description: str = "") -> ProfileInfo:
        cleaned = _clean_name(name)
        with self.db.session() as session:
            if self._name_taken(session, cleaned):
                raise ProfileError(f"A profile named \"{cleaned}\" already exists.", remedy="Choose another name or update the existing profile.")
            row = Profile(name=cleaned, description=description.strip(), configuration=strip_targets(config).model_dump(mode="json"))
            session.add(row)
            session.flush()
            return _info(row)

    def update(
        self,
        profile_id: int,
        *,
        name: Optional[str] = None,
        description: Optional[str] = None,
        config: Optional[ScanConfiguration] = None,
    ) -> ProfileInfo:
        with self.db.session() as session:
            row = session.get(Profile, profile_id)
            if row is None:
                raise ProfileError("That profile no longer exists.")
            if name is not None:
                cleaned = _clean_name(name)
                if self._name_taken(session, cleaned, exclude_id=profile_id):
                    raise ProfileError(f"A profile named \"{cleaned}\" already exists.")
                row.name = cleaned
            if description is not None:
                row.description = description.strip()
            if config is not None:
                row.configuration = strip_targets(config).model_dump(mode="json")
            session.flush()
            return _info(row)

    def duplicate(self, profile_id: int) -> ProfileInfo:
        with self.db.session() as session:
            row = session.get(Profile, profile_id)
            if row is None:
                raise ProfileError("That profile no longer exists.")
            copy = Profile(
                name=self._unique_name(session, f"{row.name} copy"),
                description=row.description,
                configuration=dict(row.configuration),
            )
            session.add(copy)
            session.flush()
            return _info(copy)

    def delete(self, profile_id: int) -> None:
        with self.db.session() as session:
            row = session.get(Profile, profile_id)
            if row is not None:
                session.delete(row)

    def reset_builtin(self, profile_id: int) -> ProfileInfo:
        with self.db.session() as session:
            row = session.get(Profile, profile_id)
            if row is None or row.builtin_key is None:
                raise ProfileError("Only built in profiles can be reset.")
            preset = preset_by_key(row.builtin_key)
            row.configuration = strip_targets(preset.build()).model_dump(mode="json")
            row.description = preset.description
            session.flush()
            return _info(row)

    # Files ---------------------------------------------------------------------

    def export_data(self, profile_id: int) -> dict[str, Any]:
        info = self.get(profile_id)
        return {
            "format": PROFILE_FILE_FORMAT,
            "version": PROFILE_FILE_VERSION,
            "name": info.name,
            "description": info.description,
            "configuration": info.configuration.model_dump(mode="json"),
        }

    def export_file(self, profile_id: int, path: Path) -> None:
        try:
            path.write_text(json.dumps(self.export_data(profile_id), indent=2), encoding="utf-8")
        except OSError as exc:
            raise ProfileError("The profile file could not be written.", details=str(exc)) from exc

    def import_data(self, data: Any) -> ProfileInfo:
        if not isinstance(data, dict) or data.get("format") != PROFILE_FILE_FORMAT:
            raise ProfileError("This is not a Genmap profile file.")
        version = data.get("version")
        if not isinstance(version, int) or version > PROFILE_FILE_VERSION:
            raise ProfileError(
                "The profile was saved by a newer version of Genmap.",
                remedy="Update Genmap to import it.",
            )
        try:
            config = ScanConfiguration.model_validate(data.get("configuration", {}))
        except ValidationError as exc:
            problems = "; ".join(i.message for i in issues_from_validation_error(exc)[:5])
            raise ProfileError("The profile contains settings Genmap cannot accept.", details=problems) from exc
        name = _clean_name(str(data.get("name") or "Imported profile"))
        with self.db.session() as session:
            unique = self._unique_name(session, name)
            row = Profile(name=unique, description=str(data.get("description") or "").strip(), configuration=strip_targets(config).model_dump(mode="json"))
            session.add(row)
            session.flush()
            return _info(row)

    def import_file(self, path: Path) -> ProfileInfo:
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ProfileError("The profile file could not be read.", details=str(exc)) from exc
        if len(raw) > 2_000_000:
            raise ProfileError("The file is too large to be a Genmap profile.")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProfileError("The profile file is not valid JSON.", details=str(exc)) from exc
        return self.import_data(data)
