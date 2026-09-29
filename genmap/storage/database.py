"""Database connection, migrations, and recovery."""

from __future__ import annotations

import logging
import shutil
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DatabaseError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from genmap.errors import StorageError

log = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def _configure_sqlite(dbapi_connection, _record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


class Database:
    """Owns the SQLAlchemy engine and hands out sessions.

    ``path=None`` gives an in memory database for tests.
    """

    def __init__(self, path: Optional[Path]) -> None:
        self.path = path
        self.recovered_from: Optional[Path] = None
        self.engine = self._create_engine()
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    def _create_engine(self) -> Engine:
        if self.path is None:
            engine = create_engine(
                "sqlite://",
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
            )
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            engine = create_engine(
                f"sqlite:///{self.path.as_posix()}",
                connect_args={"check_same_thread": False, "timeout": 10},
            )
        event.listen(engine, "connect", _configure_sqlite)
        if self.path is not None:
            try:
                with engine.connect() as connection:
                    connection.exec_driver_sql("PRAGMA journal_mode=WAL")
            except Exception:
                # The pool would otherwise keep the file open, and Windows
                # refuses to move or delete an open file during recovery.
                engine.dispose()
                raise
        return engine

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self._sessions()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def current_revision(self) -> Optional[str]:
        with self.engine.connect() as connection:
            if not inspect(connection).has_table("alembic_version"):
                return None
            return connection.execute(text("SELECT version_num FROM alembic_version")).scalar()

    def migrate(self) -> list[str]:
        """Bring the schema up to date. Returns the revisions that were applied."""
        from alembic import command
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        config = Config()
        config.set_main_option("script_location", str(MIGRATIONS_DIR))
        script = ScriptDirectory.from_config(config)
        head = script.get_current_head()
        current = self.current_revision()
        if current == head:
            return []
        if current is not None and self.path is not None and self.path.exists():
            backup = self.path.with_name(f"{self.path.stem}.before-{head}{self.path.suffix}")
            self.checkpoint()
            shutil.copy2(self.path, backup)
            log.info("Backed up database to %s before migrating", backup)
        applied = [rev.revision for rev in script.iterate_revisions(head, current or "base")]
        with self.engine.begin() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
        log.info("Database migrated from %s to %s", current or "empty", head)
        return list(reversed(applied))

    def checkpoint(self) -> None:
        if self.path is not None:
            with self.engine.connect() as connection:
                connection.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")

    def integrity_ok(self) -> bool:
        with self.engine.connect() as connection:
            return connection.exec_driver_sql("PRAGMA quick_check").scalar() == "ok"

    def size_bytes(self) -> int:
        if self.path is None:
            return 0
        total = 0
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.path) + suffix)
            if candidate.exists():
                total += candidate.stat().st_size
        return total

    def dispose(self) -> None:
        self.engine.dispose()


def open_database(path: Path) -> Database:
    """Open and migrate the database, setting a damaged file aside if needed.

    Scan results can always be rebuilt from the run folders, so a database
    that cannot be opened is moved out of the way and recreated rather than
    blocking the application. ``Database.recovered_from`` tells the caller
    where the damaged file went so the user can be informed.
    """
    database: Optional[Database] = None
    try:
        database = Database(path)
        if path.exists() and path.stat().st_size and not database.integrity_ok():
            raise DatabaseError("PRAGMA quick_check", None, sqlite3.DatabaseError("integrity check failed"))
        database.migrate()
        return database
    except (DatabaseError, sqlite3.DatabaseError) as exc:
        log.error("Database %s is unusable: %s", path, exc)
        if database is not None:
            database.dispose()
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        damaged = path.with_name(f"{path.stem}.damaged-{stamp}{path.suffix}")
        try:
            for suffix in ("", "-wal", "-shm"):
                source = Path(str(path) + suffix)
                if source.exists():
                    shutil.move(str(source), str(damaged) + suffix)
        except OSError as move_error:
            raise StorageError(
                "The Genmap database is damaged and could not be moved aside.",
                remedy=f"Close Genmap and rename or delete {path}.",
                details=str(move_error),
            ) from exc
        database = Database(path)
        database.migrate()
        database.recovered_from = damaged
        return database
