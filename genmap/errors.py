"""Application error types.

Every error carries a message written for the person using the application,
an optional remedy, and optional technical details. The UI shows the message
and remedy up front and tucks the technical details into an expandable panel.
"""

from __future__ import annotations

import traceback
from typing import Optional


class GenmapError(Exception):
    default_message = "An unexpected error occurred."

    def __init__(
        self,
        message: Optional[str] = None,
        *,
        remedy: Optional[str] = None,
        details: Optional[str] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        self.message = message or self.default_message
        self.remedy = remedy
        self._details = details
        if cause is not None:
            self.__cause__ = cause
        super().__init__(self.message)

    @property
    def details(self) -> str:
        parts: list[str] = []
        if self._details:
            parts.append(self._details)
        if self.__cause__ is not None:
            parts.append(
                "".join(
                    traceback.format_exception(
                        type(self.__cause__), self.__cause__, self.__cause__.__traceback__
                    )
                ).strip()
            )
        return "\n\n".join(parts)

    def __str__(self) -> str:
        return self.message


class ConfigurationError(GenmapError, ValueError):
    """Also a ValueError so pydantic folds it into a ValidationError."""

    default_message = "The scan configuration is not valid."


class TargetError(ConfigurationError):
    default_message = "Invalid target."


class PortSpecificationError(ConfigurationError):
    default_message = "Invalid port specification."


class ArgumentError(ConfigurationError):
    default_message = "Invalid Nmap argument."


class NmapNotFoundError(GenmapError):
    default_message = "Nmap executable was not found."


class NmapProbeError(GenmapError):
    default_message = "Nmap was found but could not be queried."


class NmapExecutionError(GenmapError):
    default_message = "Nmap could not be started."


class ScanEngineBusyError(GenmapError):
    default_message = "Another scan is already running."


class XmlParseError(GenmapError):
    default_message = "Unable to parse Nmap XML output."


class StorageError(GenmapError):
    default_message = "Unable to read or write application data."


class SettingsError(GenmapError):
    default_message = "The settings file could not be loaded."


class ModuleError(GenmapError):
    default_message = "A module failed."


def describe_exception(exc: BaseException) -> tuple[str, Optional[str], str]:
    """Return (message, remedy, technical details) for any exception."""
    if isinstance(exc, GenmapError):
        return exc.message, exc.remedy, exc.details
    details = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)).strip()
    return f"{type(exc).__name__}: {exc}", None, details
