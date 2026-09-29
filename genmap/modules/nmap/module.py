"""The Nmap module: wires the Nmap adapter into the module contract."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, ValidationError

from genmap import __version__
from genmap.core.diagnostics import Diagnostic
from genmap.core.scan_config import ScanConfiguration, ValidationIssue, issues_from_validation_error, validate_configuration
from genmap.modules.base import ExternalToolRequirement, Module, ModuleManifest
from genmap.nmap.environment import NmapEnvironment, probe_environment


class NmapModule(Module):
    MANIFEST = ModuleManifest(
        id="nmap",
        name="Nmap",
        version=__version__,
        description="Port scanning, host discovery, service and OS detection, and NSE scripting through the installed Nmap engine.",
        author="Genmap",
        homepage="https://nmap.org",
        capabilities=[
            "host-discovery",
            "port-scan",
            "service-detection",
            "os-detection",
            "scripting",
            "traceroute",
        ],
        external_tools=[
            ExternalToolRequirement(name="nmap", minimum_version="7.0", purpose="Scanning engine"),
            ExternalToolRequirement(name="npcap", optional=True, purpose="Raw packet access on Windows"),
        ],
        configuration_schema=ScanConfiguration.model_json_schema(),
        tags=["network", "scanner"],
    )

    def __init__(self) -> None:
        super().__init__()
        self._environment: Optional[NmapEnvironment] = None
        self._lock = threading.Lock()

    @property
    def manifest(self) -> ModuleManifest:
        return self.MANIFEST

    @property
    def environment(self) -> Optional[NmapEnvironment]:
        return self._environment

    def configured_path(self) -> Optional[str]:
        if self.context is None:
            return None
        settings = getattr(self.context, "settings", None)
        return getattr(getattr(settings, "nmap", None), "executable_path", None)

    def probe_timeout(self) -> float:
        if self.context is None:
            return 20.0
        settings = getattr(self.context, "settings", None)
        return float(getattr(getattr(settings, "nmap", None), "probe_timeout_seconds", 20))

    def configured_data_directory(self) -> Optional[str]:
        if self.context is None:
            return None
        settings = getattr(self.context, "settings", None)
        return getattr(getattr(settings, "nmap", None), "data_directory", None)

    def refresh_environment(self, *, include_interfaces: bool = True) -> NmapEnvironment:
        env = probe_environment(
            self.configured_path(),
            timeout=self.probe_timeout(),
            include_interfaces=include_interfaces,
            data_directory=self.configured_data_directory(),
        )
        with self._lock:
            self._environment = env
        return env

    def executable(self) -> Optional[Path]:
        env = self._environment
        return env.executable if env and env.usable else None

    def check_environment(self) -> list[Diagnostic]:
        return self.refresh_environment().diagnostics

    def default_configuration(self) -> BaseModel:
        return ScanConfiguration()

    def validate(self, configuration: BaseModel) -> list[ValidationIssue]:
        if not isinstance(configuration, ScanConfiguration):
            try:
                configuration = ScanConfiguration.model_validate(configuration.model_dump())
            except ValidationError as exc:
                return issues_from_validation_error(exc)
        return validate_configuration(configuration)
