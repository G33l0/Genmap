"""Registration and lifecycle management for modules."""

from __future__ import annotations

import logging
import sys
from typing import Iterator, Optional

from genmap import MODULE_API_VERSION
from genmap.core.diagnostics import Diagnostic, DiagnosticLevel
from genmap.errors import ModuleError
from genmap.modules.base import Module, ModuleContext, ModuleState

log = logging.getLogger(__name__)


def _current_platform() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "darwin"
    return "linux"


class ModuleRegistry:
    def __init__(self) -> None:
        self._modules: dict[str, Module] = {}
        self._disabled: set[str] = set()

    def register(self, module: Module) -> None:
        manifest = module.manifest
        if manifest.id in self._modules:
            raise ModuleError(f"A module with id '{manifest.id}' is already registered.")
        if not manifest.is_api_compatible(MODULE_API_VERSION):
            module.state = ModuleState.INCOMPATIBLE
            module.last_error = (
                f"Module API {manifest.api_version} is not compatible with host API {MODULE_API_VERSION}."
            )
        elif _current_platform() not in manifest.platforms:
            module.state = ModuleState.UNAVAILABLE
            module.last_error = f"Not supported on {_current_platform()}."
        self._modules[manifest.id] = module
        log.debug("Registered module %s", module)

    def get(self, module_id: str) -> Optional[Module]:
        return self._modules.get(module_id)

    def require(self, module_id: str) -> Module:
        module = self.get(module_id)
        if module is None:
            raise ModuleError(f"Module '{module_id}' is not registered.")
        return module

    def __iter__(self) -> Iterator[Module]:
        return iter(self._modules.values())

    def __len__(self) -> int:
        return len(self._modules)

    def is_enabled(self, module_id: str) -> bool:
        return module_id not in self._disabled

    def set_enabled(self, module_id: str, enabled: bool) -> None:
        module = self.require(module_id)
        if enabled:
            self._disabled.discard(module_id)
            if module.state == ModuleState.DISABLED:
                module.state = ModuleState.READY if module.context is not None else ModuleState.REGISTERED
        else:
            self._disabled.add(module_id)
            module.state = ModuleState.DISABLED

    def initialize_all(self, context: ModuleContext) -> None:
        # Turned off modules are initialised too, so turning one back on needs no restart.
        for module in self._modules.values():
            if module.state in (ModuleState.INCOMPATIBLE, ModuleState.UNAVAILABLE):
                continue
            try:
                module.initialize(context)
                if module.state != ModuleState.DISABLED:
                    module.state = ModuleState.READY
            except Exception as exc:
                module.state = ModuleState.ERROR
                module.last_error = str(exc)
                log.exception("Module %s failed to initialise", module.manifest.id)

    def check_all(self) -> dict[str, list[Diagnostic]]:
        report: dict[str, list[Diagnostic]] = {}
        for module in self._modules.values():
            if module.state in (ModuleState.INCOMPATIBLE, ModuleState.DISABLED, ModuleState.ERROR):
                continue
            if _current_platform() not in module.manifest.platforms:
                continue
            # A module left unavailable by a failed check is checked again; the tool may have been installed since.
            report[module.manifest.id] = self.check(module.manifest.id)
        return report

    def check(self, module_id: str) -> list[Diagnostic]:
        module = self.require(module_id)
        try:
            diagnostics = module.check_environment()
        except Exception as exc:
            diagnostics = [Diagnostic(DiagnosticLevel.ERROR, "Environment check failed", str(exc))]
            log.exception("Module %s environment check failed", module_id)
        module.record_diagnostics(diagnostics)
        return diagnostics

    def shutdown_all(self) -> None:
        for module in self._modules.values():
            try:
                module.shutdown()
            except Exception:
                log.exception("Module %s failed to shut down", module.manifest.id)
