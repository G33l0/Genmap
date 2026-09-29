"""Detection of the privilege level Genmap itself is running with."""

from __future__ import annotations

import ctypes
import os
import sys
from enum import Enum


class PrivilegeLevel(str, Enum):
    ELEVATED = "elevated"
    STANDARD = "standard"
    UNKNOWN = "unknown"


def detect_privilege_level() -> PrivilegeLevel:
    if sys.platform.startswith("win"):
        try:
            return (
                PrivilegeLevel.ELEVATED
                if ctypes.windll.shell32.IsUserAnAdmin()  # type: ignore[attr-defined]
                else PrivilegeLevel.STANDARD
            )
        except Exception:
            return PrivilegeLevel.UNKNOWN
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return PrivilegeLevel.UNKNOWN
    return PrivilegeLevel.ELEVATED if geteuid() == 0 else PrivilegeLevel.STANDARD


def privilege_label(level: PrivilegeLevel) -> str:
    if sys.platform.startswith("win"):
        return {
            PrivilegeLevel.ELEVATED: "Administrator",
            PrivilegeLevel.STANDARD: "Standard user",
            PrivilegeLevel.UNKNOWN: "Unknown",
        }[level]
    return {
        PrivilegeLevel.ELEVATED: "root",
        PrivilegeLevel.STANDARD: "Unprivileged user",
        PrivilegeLevel.UNKNOWN: "Unknown",
    }[level]
