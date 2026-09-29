"""Application wide services shared by pages and controllers."""

from __future__ import annotations

import logging
from typing import Optional

from PyQt6.QtCore import QObject, QRunnable, QThreadPool, pyqtSignal
from PyQt6.QtWidgets import QApplication

from genmap.engine.run_store import RunStore
from genmap.storage import Database, open_database
from genmap.storage.profiles import ProfileRepository
from genmap.storage.reports import ReportRepository
from genmap.storage.scans import ScanIndex
from genmap.storage.target_groups import TargetGroupRepository
from genmap.engine.scan_engine import ScanEngine
from genmap.modules import ModuleContext, ModuleRegistry
from genmap.modules.nmap import NmapModule
from genmap.nmap.environment import NmapEnvironment
from genmap.paths import AppPaths
from genmap.settings import AppSettings, SettingsStore
from genmap.ui.tasks import run_in_background
from genmap.ui.theme import ThemeManager

log = logging.getLogger(__name__)


class _ProbeSignals(QObject):
    finished = pyqtSignal(object)
    failed = pyqtSignal(object)


class _ProbeTask(QRunnable):
    def __init__(self, module: NmapModule, signals: _ProbeSignals) -> None:
        super().__init__()
        self._module = module
        self._signals = signals
        self.setAutoDelete(True)

    def run(self) -> None:
        try:
            env = self._module.refresh_environment()
        except Exception as exc:  # pragma: no cover
            log.exception("Environment probe crashed")
            self._signals.failed.emit(exc)
            return
        self._signals.finished.emit(env)


class AppContext(QObject):
    """Owns settings, modules, the engine, and the theme for the whole app."""

    environment_changed = pyqtSignal(object)  # NmapEnvironment
    environment_probe_started = pyqtSignal()
    settings_changed = pyqtSignal(object)  # AppSettings
    index_changed = pyqtSignal()  # scans added, updated, or indexed
    profiles_changed = pyqtSignal()
    target_groups_changed = pyqtSignal()
    reports_changed = pyqtSignal()

    def __init__(
        self,
        app: QApplication,
        paths: AppPaths,
        settings_store: SettingsStore,
        database: Optional[Database] = None,
    ) -> None:
        super().__init__()
        self.app = app
        self.paths = paths
        self.settings_store = settings_store
        self.theme = ThemeManager(app, self, asset_dir=paths.cache_dir / "theme")
        self.registry = ModuleRegistry()
        self.nmap_module = NmapModule()
        self.registry.register(self.nmap_module)
        self.registry.initialize_all(ModuleContext(paths=paths, settings=settings_store.settings, logger=logging.getLogger("genmap.modules")))
        self.run_store = RunStore(paths.scans_dir)
        recovered = self.run_store.recover_interrupted()
        if recovered:
            log.info("Marked %d unfinished scan(s) from a previous session as interrupted", len(recovered))
        self.engine = ScanEngine(self.run_store, executable_provider=self.nmap_module.executable, parent=self)
        self.database = database or open_database(paths.database_file)
        self.scan_index = ScanIndex(self.database)
        self.profiles = ProfileRepository(self.database)
        self.target_groups = TargetGroupRepository(self.database)
        self.reports = ReportRepository(self.database)
        self._seed_profiles()
        self.engine.job_started.connect(self._on_job_started)
        self.engine.job_finished.connect(self._on_job_finished)
        self._reconciling = False
        self._probe_signals = _ProbeSignals()
        self._probe_signals.finished.connect(self._on_probe_finished)
        self._probe_signals.failed.connect(self._on_probe_failed)
        self._probing = False
        settings_store.subscribe(self._on_settings_saved)
        self.apply_settings(settings_store.settings)

    @property
    def settings(self) -> AppSettings:
        return self.settings_store.settings

    @property
    def environment(self) -> Optional[NmapEnvironment]:
        return self.nmap_module.environment

    @property
    def probing(self) -> bool:
        return self._probing

    def apply_settings(self, settings: AppSettings) -> None:
        self.theme.apply(
            settings.appearance.theme,
            base_font_pt=settings.appearance.base_font_size,
            mono_family=settings.appearance.monospace_font_family,
        )
        scanning = settings.scanning
        self.engine.max_concurrent = scanning.max_concurrent_scans if settings.advanced.allow_multiple_scans else 1
        self.engine.stats_interval = scanning.stats_interval if scanning.inject_stats_interval else None
        self.engine.timeout_seconds = scanning.scan_timeout_minutes * 60
        self.engine.keep_console_logs = scanning.keep_stdout_log
        from genmap.logging_setup import set_level

        set_level(settings.logging.level)

    def _on_settings_saved(self, settings: AppSettings) -> None:
        self.apply_settings(settings)
        self.settings_changed.emit(settings)

    def refresh_environment(self) -> None:
        if self._probing:
            return
        self._probing = True
        self.environment_probe_started.emit()
        QThreadPool.globalInstance().start(_ProbeTask(self.nmap_module, self._probe_signals))

    def _on_probe_finished(self, env: NmapEnvironment) -> None:
        self._probing = False
        log.info(
            "Nmap environment: %s",
            f"{env.version} at {env.executable}" if env.usable else "not usable",
        )
        self.environment_changed.emit(env)

    def _on_probe_failed(self, exc: BaseException) -> None:
        self._probing = False
        log.error("Environment probe failed: %s", exc)
        self.environment_changed.emit(self.nmap_module.environment or NmapEnvironment())

    # Database ---------------------------------------------------------------

    def _seed_profiles(self) -> None:
        storage = self.settings.storage
        try:
            added = self.profiles.seed_builtins(storage.seeded_profiles)
        except Exception:
            log.exception("Built in profiles could not be seeded")
            return
        if added:
            storage.seeded_profiles = sorted(set(storage.seeded_profiles) | set(added))
            try:
                self.settings_store.save()
            except Exception:
                log.warning("Could not record seeded profiles", exc_info=True)

    def reconcile_index(self) -> None:
        """Sync the database with the run folders without blocking the UI."""
        if self._reconciling:
            return
        self._reconciling = True
        active = [job.run_id for job in self.engine.active_jobs]

        def done(report) -> None:
            self._reconciling = False
            if report.added or report.updated or report.indexed or report.missing:
                log.info("Scan index reconciled: %s", report)
            self.index_changed.emit()

        def failed(exc: BaseException) -> None:
            self._reconciling = False
            log.error("Scan index reconciliation failed: %s", exc, exc_info=exc)

        run_in_background(lambda: self.scan_index.reconcile(self.run_store, active_run_ids=active), done, failed)

    def _on_job_started(self, job) -> None:
        try:
            self.scan_index.record_run(job.record, profile_id=job.profile_id)
        except Exception:
            log.exception("Could not record scan %s in the index", job.run_id)
        self.index_changed.emit()

    def _on_job_finished(self, job) -> None:
        record = job.record
        run_in_background(
            lambda: self.scan_index.index_finished_run(self.run_store, record),
            lambda _indexed: self.index_changed.emit(),
            lambda exc: log.error("Could not index scan %s: %s", record.run_id, exc, exc_info=exc),
        )

    def delete_scan(self, run_id: str) -> None:
        """Remove a scan's folder and its index entry."""
        self.run_store.delete(run_id)
        self.scan_index.delete(run_id)
        self.index_changed.emit()

    def remember_targets(self, targets: list[str]) -> None:
        general = self.settings.general
        recent = [t for t in targets if t] + [t for t in general.recent_targets if t not in targets]
        general.recent_targets = recent[:20]
        try:
            self.settings_store.save()
        except Exception:
            log.warning("Could not save recent targets", exc_info=True)

    def shutdown(self) -> None:
        self.engine.cancel_all()
        self.registry.shutdown_all()
        try:
            self.database.checkpoint()
        except Exception:
            log.debug("Database checkpoint on shutdown failed", exc_info=True)
