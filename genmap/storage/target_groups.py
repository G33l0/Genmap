"""Saved target groups."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional

from sqlalchemy import func, select

from genmap.core.targets import parse_target, split_target_text
from genmap.errors import GenmapError, TargetError
from genmap.storage.database import Database
from genmap.storage.models import TargetGroup, TargetGroupEntry

GROUP_FILE_FORMAT = "genmap.targets"
GROUP_FILE_VERSION = 1


class TargetGroupError(GenmapError):
    default_message = "The target group could not be saved."


@dataclass(frozen=True)
class TargetGroupInfo:
    id: int
    name: str
    description: str
    targets: list[str]
    exclusions: list[str]
    created_at: datetime
    updated_at: datetime


def _validated(expressions: Iterable[str]) -> list[str]:
    cleaned: list[str] = []
    for expression in expressions:
        value = expression.strip()
        if not value:
            continue
        try:
            parse_target(value)
        except TargetError as exc:
            raise TargetGroupError(exc.message, remedy=exc.remedy) from exc
        if value not in cleaned:
            cleaned.append(value)
    return cleaned


def _info(row: TargetGroup) -> TargetGroupInfo:
    return TargetGroupInfo(
        id=row.id,
        name=row.name,
        description=row.description,
        targets=[e.expression for e in row.entries if not e.excluded],
        exclusions=[e.expression for e in row.entries if e.excluded],
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def parse_target_file_text(text: str) -> tuple[list[str], list[str]]:
    """Read an Nmap style target list: one or more targets per line, # comments.

    Lines starting with ! are exclusions, a Genmap extension that keeps an
    exported group round trippable.
    """
    targets: list[str] = []
    exclusions: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("!"):
            exclusions.extend(split_target_text(line[1:]))
        else:
            targets.extend(split_target_text(line))
    return _validated(targets), _validated(exclusions)


class TargetGroupRepository:
    def __init__(self, database: Database) -> None:
        self.db = database

    def _name(self, session, name: str, exclude_id: Optional[int] = None) -> str:
        cleaned = " ".join(name.split())
        if not cleaned:
            raise TargetGroupError("A target group needs a name.")
        if len(cleaned) > 120:
            raise TargetGroupError("Target group names can be at most 120 characters.")
        query = select(TargetGroup.id).where(func.lower(TargetGroup.name) == cleaned.lower())
        if exclude_id is not None:
            query = query.where(TargetGroup.id != exclude_id)
        if session.scalar(query) is not None:
            raise TargetGroupError(f"A target group named \"{cleaned}\" already exists.")
        return cleaned

    @staticmethod
    def _entries(targets: list[str], exclusions: list[str]) -> list[TargetGroupEntry]:
        rows = [TargetGroupEntry(expression=t, excluded=False, position=i) for i, t in enumerate(targets)]
        rows += [TargetGroupEntry(expression=t, excluded=True, position=len(targets) + i) for i, t in enumerate(exclusions)]
        return rows

    def list(self) -> list[TargetGroupInfo]:
        with self.db.session() as session:
            return [_info(r) for r in session.scalars(select(TargetGroup).order_by(func.lower(TargetGroup.name)))]

    def get(self, group_id: int) -> TargetGroupInfo:
        with self.db.session() as session:
            row = session.get(TargetGroup, group_id)
            if row is None:
                raise TargetGroupError("That target group no longer exists.")
            return _info(row)

    def create(self, name: str, targets: Iterable[str], exclusions: Iterable[str] = (), description: str = "") -> TargetGroupInfo:
        valid_targets = _validated(targets)
        if not valid_targets:
            raise TargetGroupError("A target group needs at least one target.")
        valid_exclusions = _validated(exclusions)
        with self.db.session() as session:
            row = TargetGroup(name=self._name(session, name), description=description.strip())
            row.entries = self._entries(valid_targets, valid_exclusions)
            session.add(row)
            session.flush()
            return _info(row)

    def update(
        self,
        group_id: int,
        *,
        name: Optional[str] = None,
        targets: Optional[Iterable[str]] = None,
        exclusions: Optional[Iterable[str]] = None,
        description: Optional[str] = None,
    ) -> TargetGroupInfo:
        with self.db.session() as session:
            row = session.get(TargetGroup, group_id)
            if row is None:
                raise TargetGroupError("That target group no longer exists.")
            if name is not None:
                row.name = self._name(session, name, exclude_id=group_id)
            if description is not None:
                row.description = description.strip()
            if targets is not None or exclusions is not None:
                current = _info(row)
                new_targets = _validated(targets) if targets is not None else current.targets
                new_exclusions = _validated(exclusions) if exclusions is not None else current.exclusions
                if not new_targets:
                    raise TargetGroupError("A target group needs at least one target.")
                row.entries = self._entries(new_targets, new_exclusions)
            session.flush()
            return _info(row)

    def delete(self, group_id: int) -> None:
        with self.db.session() as session:
            row = session.get(TargetGroup, group_id)
            if row is not None:
                session.delete(row)

    def export_text(self, group_id: int) -> str:
        info = self.get(group_id)
        lines = [f"# Genmap target group: {info.name}"]
        if info.description:
            lines += [f"# {line}" for line in info.description.splitlines()]
        lines += info.targets
        lines += [f"!{e}" for e in info.exclusions]
        return "\n".join(lines) + "\n"

    def export_data(self, group_id: int) -> dict[str, Any]:
        info = self.get(group_id)
        return {
            "format": GROUP_FILE_FORMAT,
            "version": GROUP_FILE_VERSION,
            "name": info.name,
            "description": info.description,
            "targets": info.targets,
            "exclusions": info.exclusions,
        }

    def import_file(self, path: Path, name: Optional[str] = None) -> TargetGroupInfo:
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise TargetGroupError("The file could not be read.", details=str(exc)) from exc
        if len(raw) > 5_000_000:
            raise TargetGroupError("The file is too large to import as a target group.")
        description = f"Imported from {path.name}"
        if raw.lstrip().startswith("{"):
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise TargetGroupError("The file is not valid JSON.", details=str(exc)) from exc
            if not isinstance(data, dict) or data.get("format") != GROUP_FILE_FORMAT:
                raise TargetGroupError("This JSON file is not a Genmap target group.")
            targets = [str(t) for t in data.get("targets", [])]
            exclusions = [str(t) for t in data.get("exclusions", [])]
            name = name or str(data.get("name") or path.stem)
            description = str(data.get("description") or description)
        else:
            targets, exclusions = parse_target_file_text(raw)
            name = name or path.stem
        with self.db.session() as session:
            base = " ".join(name.split()) or "Imported targets"
            candidate, counter = base, 2
            while session.scalar(select(TargetGroup.id).where(func.lower(TargetGroup.name) == candidate.lower())) is not None:
                candidate = f"{base} ({counter})"
                counter += 1
        return self.create(candidate, targets, exclusions, description)
