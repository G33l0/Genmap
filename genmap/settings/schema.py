"""Application settings model.

Settings are grouped by the page that edits them. Everything has a sensible
default so a missing or partially written settings file still yields a
working configuration.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from genmap.core.timespec import normalize_time_spec


class SettingsSection(BaseModel):
    model_config = ConfigDict(extra="ignore", validate_assignment=True)


class GeneralSettings(SettingsSection):
    confirm_intrusive_scans: bool = True
    confirm_scan_cancel: bool = True
    restore_last_page: bool = True
    last_page: str = "dashboard"
    check_environment_on_startup: bool = True
    show_welcome_hints: bool = True
    recent_targets: list[str] = Field(default_factory=list)


class AppearanceSettings(SettingsSection):
    theme: Literal["system", "light", "dark", "hacker"] = "system"
    base_font_size: int = Field(default=10, ge=8, le=16)
    monospace_font_family: str = "Consolas, Cascadia Mono, Menlo, DejaVu Sans Mono, monospace"
    sidebar_compact: bool = False


class NmapSettings(SettingsSection):
    executable_path: Optional[str] = None
    data_directory: Optional[str] = None
    probe_timeout_seconds: int = Field(default=20, ge=5, le=120)


class NetworkSettings(SettingsSection):
    preferred_interface: Optional[str] = None
    warn_when_capture_driver_missing: bool = True


class ScanningSettings(SettingsSection):
    max_concurrent_scans: int = Field(default=1, ge=1, le=4)
    stats_interval: str = "2s"
    inject_stats_interval: bool = True
    scan_timeout_minutes: int = Field(default=0, ge=0, le=7 * 24 * 60)
    default_verbosity: int = Field(default=1, ge=0, le=4)
    keep_stdout_log: bool = True
    output_buffer_lines: int = Field(default=20000, ge=1000, le=500000)

    @field_validator("stats_interval")
    @classmethod
    def _validate_interval(cls, value: str) -> str:
        return normalize_time_spec(value, option="stats interval")


class NseSettings(SettingsSection):
    warn_on_intrusive_categories: bool = True
    default_script_timeout: Optional[str] = None
    intrusive_categories: list[str] = Field(
        default_factory=lambda: ["intrusive", "brute", "dos", "exploit", "fuzzer", "malware"]
    )

    @field_validator("default_script_timeout")
    @classmethod
    def _validate_timeout(cls, value: Optional[str]) -> Optional[str]:
        if value:
            return normalize_time_spec(value, option="script timeout")
        return None


class StorageSettings(SettingsSection):
    data_directory_override: Optional[str] = None
    seeded_profiles: list[str] = Field(default_factory=list)
    keep_raw_output: bool = True
    max_stored_scans: int = Field(default=0, ge=0)


class ReportSettings(SettingsSection):
    default_format: Literal["html", "json", "csv", "xml"] = "html"
    default_output_directory: Optional[str] = None
    include_raw_xml_in_html: bool = False


class LoggingSettings(SettingsSection):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_to_console: bool = False


class AdvancedSettings(SettingsSection):
    show_managed_arguments: bool = True
    allow_multiple_scans: bool = False
    developer_mode: bool = False


class AppSettings(BaseModel):
    model_config = ConfigDict(extra="ignore", validate_assignment=True)

    schema_version: int = 1
    general: GeneralSettings = Field(default_factory=GeneralSettings)
    appearance: AppearanceSettings = Field(default_factory=AppearanceSettings)
    nmap: NmapSettings = Field(default_factory=NmapSettings)
    network: NetworkSettings = Field(default_factory=NetworkSettings)
    scanning: ScanningSettings = Field(default_factory=ScanningSettings)
    nse: NseSettings = Field(default_factory=NseSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    reports: ReportSettings = Field(default_factory=ReportSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    advanced: AdvancedSettings = Field(default_factory=AdvancedSettings)
