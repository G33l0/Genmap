"""Records of generated reports."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import select

from genmap.storage.database import Database
from genmap.storage.models import Report, Scan


@dataclass(frozen=True)
class ReportInfo:
    id: int
    run_id: Optional[str]
    title: str
    format: str
    path: Path
    options: dict[str, Any]
    created_at: datetime

    @property
    def exists(self) -> bool:
        return self.path.is_file()


def _info(row: Report) -> ReportInfo:
    return ReportInfo(row.id, row.run_id, row.title, row.format, Path(row.path), dict(row.options or {}), row.created_at)


class ReportRepository:
    def __init__(self, database: Database) -> None:
        self.db = database

    def add(self, run_id: Optional[str], title: str, fmt: str, path: Path, options: dict[str, Any]) -> ReportInfo:
        with self.db.session() as session:
            scan_id = session.scalar(select(Scan.id).where(Scan.run_id == run_id)) if run_id else None
            row = Report(scan_id=scan_id, run_id=run_id, title=title[:300], format=fmt, path=str(path), options=options)
            session.add(row)
            session.flush()
            return _info(row)

    def list(self, run_id: Optional[str] = None) -> list[ReportInfo]:
        query = select(Report).order_by(Report.created_at.desc())
        if run_id:
            query = query.where(Report.run_id == run_id)
        with self.db.session() as session:
            return [_info(r) for r in session.scalars(query)]

    def remove(self, report_id: int, *, delete_file: bool = False) -> None:
        with self.db.session() as session:
            row = session.get(Report, report_id)
            if row is None:
                return
            if delete_file:
                Path(row.path).unlink(missing_ok=True)
            session.delete(row)
