"""A process to run: program, argument list, and the reasons behind the
arguments the host adds itself. No shell is ever involved; ``display``
only renders the list for people to read or copy.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ManagedArgument:
    arguments: list[str]
    reason: str


@dataclass
class CommandPlan:
    program: Path
    user_arguments: list[str]
    managed_arguments: list[ManagedArgument]
    targets: list[str]
    warnings: list[str] = field(default_factory=list)
    working_directory: Optional[Path] = None

    @property
    def arguments(self) -> list[str]:
        managed = [arg for item in self.managed_arguments for arg in item.arguments]
        return self.user_arguments + managed + self.targets

    def display(self, *, program_name: Optional[str] = None) -> str:
        name = program_name or self.program.name
        return format_command([name] + self.arguments)

    def display_user_command(self) -> str:
        return format_command([self.program.name] + self.user_arguments + self.targets)


def format_command(parts: list[str]) -> str:
    """Render an argument list the way the current platform's shell would need it."""
    if sys.platform.startswith("win"):
        return subprocess.list2cmdline(parts)
    import shlex

    return shlex.join(parts)
