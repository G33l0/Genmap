"""Application wide services shared by pages and controllers."""

from __future__ import annotations

import logging
from typing import Optional

from PyQt6.QtCore import QObject, QRunnable, QThreadPool, pyqtSignal
from PyQt6.QtWidgets import QApplication

from genmap.engine.run_store import RunStore
from genmap.engine.scan_engine import ScanEngine
from genmap.modules import ModuleContext, ModuleRegistry
from genmap.modules.nmap import NmapModule
from genmap.nmap.environment import NmapEnvironment
from genmap.paths import AppPaths
from genmap.settings import AppSettings, SettingsStore
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
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("Environment probe crashed")
            self._signals.failed.emit(exc)
            return
        self._signals.finished.emit(env)


class AppContext(QObject):
    """Owns settings, modules, the engine, and the theme for the whole app."""

    environment_changed = pyqtSignal(object)  # NmapEnvironment
    environment_probe_started = pyqtSignal()
    settings_changed = pyqtSignal(object)  # AppSettings

    def __init__(self, app: QApplication, paths: AppPaths, settings_store: SettingsStore) -> None:
        super().__init__()
        self.app = app
        self.paths = paths
        self.settings_store = settings_store
        self.theme = ThemeManager(app, self)
        self.registry = ModuleRegistry()
        self.nmap_module = NmapModule()
        self.registry.register(self.nmap_module)
        self.registry.initialize_all(ModuleContext(paths=paths, settings=settings_store.settings, logger=logging.getLogger("genmap.modules")))
        self.run_store = RunStore(paths.scans_dir)
        recovered = self.run_store.recover_interrupted()
        if recovered:
            log.info("Marked %d unfinished scan(s) from a previous session as interrupted", len(recovered))
        self.engine = ScanEngine(self.run_store, executable_provider=self.nmap_module.executable, parent=self)
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
