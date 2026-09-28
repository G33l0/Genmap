"""Application entry point."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Optional, Sequence

from genmap import APP_NAME, ORGANIZATION, __version__

log = logging.getLogger("genmap")


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="genmap", description="Desktop workbench for Nmap.")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    parser.add_argument("--open", metavar="XML", type=Path, help="open an Nmap XML file on startup")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="override the configured log level")
    parser.add_argument("--diagnose", action="store_true", help="print Nmap environment diagnostics and exit")
    args, _unknown = parser.parse_known_args(list(argv))
    return args


def _diagnose() -> int:
    from genmap.nmap.environment import probe_environment

    env = probe_environment()
    print(f"{APP_NAME} {__version__}")
    for diagnostic in env.diagnostics:
        print(f"[{diagnostic.level.value.upper():7}] {diagnostic.title}")
        if diagnostic.detail:
            print(f"          {diagnostic.detail}")
        if diagnostic.remedy:
            print(f"          {diagnostic.remedy}")
    for capability in env.capabilities:
        state = {True: "yes", False: "no", None: "unknown"}[capability.available]
        print(f"  {capability.label}: {state}")
    return 0 if env.usable else 1


def _set_windows_app_id() -> None:
    if not sys.platform.startswith("win"):
        return
    try:
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(f"{ORGANIZATION}.{APP_NAME}.{__version__}")
    except Exception:
        pass


def _install_exception_hook() -> None:
    """Log unexpected exceptions and show them without a raw traceback."""

    def show(exc_type, exc_value, exc_tb) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        log.critical("Unhandled exception", exc_info=(exc_type, exc_value, exc_tb))
        try:
            from PyQt6.QtWidgets import QApplication

            from genmap.ui.widgets.error_dialog import show_exception

            if QApplication.instance() is not None and threading.current_thread() is threading.main_thread():
                exc_value.__traceback__ = exc_tb
                show_exception(QApplication.activeWindow(), exc_value, "Unexpected error")
        except Exception:
            pass

    sys.excepthook = show

    def thread_hook(args: threading.ExceptHookArgs) -> None:
        log.critical("Unhandled exception in thread %s", args.thread.name if args.thread else "?", exc_info=(args.exc_type, args.exc_value, args.exc_traceback))

    threading.excepthook = thread_hook


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    if args.diagnose:
        return _diagnose()

    from genmap.logging_setup import configure_logging
    from genmap.paths import default_paths
    from genmap.settings import SettingsStore

    paths = default_paths().ensure()
    store = SettingsStore(paths.settings_file)
    settings = store.load()
    level = args.log_level or settings.logging.level
    console = settings.logging.log_to_console or bool(os.environ.get("GENMAP_DEBUG"))
    log_file = configure_logging(paths.log_dir, level, console=console)
    log.info("%s %s starting (Python %s, %s)", APP_NAME, __version__, sys.version.split()[0], sys.platform)
    log.info("Log file: %s", log_file)

    _set_windows_app_id()
    _install_exception_hook()

    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QGuiApplication
    from PyQt6.QtWidgets import QApplication

    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_NAME)
    app.setOrganizationName(ORGANIZATION)
    app.setApplicationVersion(__version__)
    # Fusion renders style sheets consistently; the native Windows styles ignore parts of them.
    app.setStyle("Fusion")

    from genmap.resources import app_icon
    from genmap.ui.app_context import AppContext
    from genmap.ui.main_window import MainWindow
    from genmap.ui.widgets.error_dialog import show_error

    app.setWindowIcon(app_icon())
    context = AppContext(app, paths, store)
    window = MainWindow(context)
    window.show()
    window.start()
    if store.load_problem is not None:
        problem = store.load_problem
        show_error(window, "Settings reset", problem.message, problem.remedy, problem.details)
    context.refresh_environment()
    if args.open:
        window.open_xml_file(args.open)
    exit_code = app.exec()
    log.info("%s exiting with code %s", APP_NAME, exit_code)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
