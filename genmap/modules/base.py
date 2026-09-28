"""The contract every Genmap module implements.

Nmap is the first module. Future tools (DNS, WHOIS, screenshots, Domain
Atlas) plug in through the same interface, so the core only ever talks to
``Module`` and the data types declared here. Modules may wrap external
processes; nothing here assumes the work happens in Python.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from genmap import MODULE_API_VERSION
from genmap.core.diagnostics import Diagnostic
from genmap.core.scan_config import ValidationIssue
from genmap.paths import AppPaths


class ExternalToolRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    minimum_version: Optional[str] = None
    optional: bool = False
    purpose: str = ""


class ModuleManifest(BaseModel):
    """Static description of a module, used for compatibility checks and display."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    name: str
    version: str
    description: str = ""
    author: str = ""
    homepage: Optional[str] = None
    api_version: str = MODULE_API_VERSION
    capabilities: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=lambda: ["windows", "linux", "darwin"])
    external_tools: list[ExternalToolRequirement] = Field(default_factory=list)
    configuration_schema: Optional[dict[str, Any]] = None
    result_schema: Optional[dict[str, Any]] = None
    tags: list[str] = Field(default_factory=list)

    def is_api_compatible(self, host_api_version: str = MODULE_API_VERSION) -> bool:
        return self.api_version.split(".")[0] == host_api_version.split(".")[0]


class ModuleState(str, Enum):
    REGISTERED = "registered"
    READY = "ready"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    DISABLED = "disabled"
    INCOMPATIBLE = "incompatible"
    ERROR = "error"


@dataclass
class ModuleContext:
    """Services the host makes available to modules during initialisation."""

    paths: AppPaths
    settings: Any
    logger: logging.Logger

    def module_data_dir(self, module_id: str) -> Path:
        directory = self.paths.data_dir / "modules" / module_id
        directory.mkdir(parents=True, exist_ok=True)
        return directory


class Module(abc.ABC):
    """Base class for modules.

    Lifecycle: ``initialize`` once at startup, ``check_environment`` whenever
    diagnostics are refreshed, ``shutdown`` at exit. Configuration objects
    are pydantic models created by ``default_configuration`` and checked by
    ``validate``. Execution and result handling are added to this contract
    in the module system phase; the Nmap module exposes them through its own
    engine until then.
    """

    def __init__(self) -> None:
        self.context: Optional[ModuleContext] = None
        self.state: ModuleState = ModuleState.REGISTERED
        self.last_error: Optional[str] = None

    @property
    @abc.abstractmethod
    def manifest(self) -> ModuleManifest: ...

    def initialize(self, context: ModuleContext) -> None:
        self.context = context

    @abc.abstractmethod
    def check_environment(self) -> list[Diagnostic]: ...

    @abc.abstractmethod
    def default_configuration(self) -> BaseModel: ...

    @abc.abstractmethod
    def validate(self, configuration: BaseModel) -> list[ValidationIssue]: ...

    def shutdown(self) -> None:
        return None

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.manifest.id} {self.manifest.version} {self.state.value}>"
