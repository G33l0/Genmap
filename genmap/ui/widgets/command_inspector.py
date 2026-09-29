"""Command Inspector: shows exactly what Genmap will run and why."""

from __future__ import annotations

import sys
from typing import Optional

from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from genmap.core.scan_config import ScanConfiguration
from genmap.nmap.command_builder import CommandPlan
from genmap.nmap.environment import NmapEnvironment
from genmap.nmap.privileges import privilege_label
from genmap.nmap.requirements import environment_warnings
from genmap.ui.widgets.common import KeyValueGrid, hint, label


def _mono_text(text: str, min_height: int = 80) -> QPlainTextEdit:
    widget = QPlainTextEdit(text)
    widget.setReadOnly(True)
    widget.setProperty("role", "mono")
    widget.setMinimumHeight(min_height)
    widget.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
    return widget


def environment_notes(env: Optional[NmapEnvironment], config: ScanConfiguration) -> list[str]:
    notes: list[str] = []
    if env is None or not env.usable:
        notes.append("Nmap is not available, so this command cannot run until it is installed or configured.")
        return notes
    notes.append(f"Runs as: {privilege_label(env.privileges)}. Nmap inherits Genmap's privileges.")
    if env.capture_driver is not None:
        notes.append(f"Packet capture: {env.capture_driver.name} ({env.capture_driver.status.value.replace('_', ' ')}).")
    raw = env.capabilities.get("raw_packets")
    if config.techniques.uses_raw_packets or config.os_detection.enabled or config.aggressive:
        if raw is not None and raw.available is None:
            notes.append("This configuration needs raw packet access, which Genmap could not confirm: " + raw.detail)
        elif raw is None or raw.available:
            notes.append("This configuration uses raw packets.")
    notes.extend(environment_warnings(config, env))
    if env.configured_data_directory is not None:
        notes.append(f"Nmap reads its data files from {env.configured_data_directory} first (Settings, Nmap).")
    notes.append("Nmap is launched directly with an argument list; no shell interprets the command.")
    if sys.platform.startswith("win"):
        notes.append("The displayed command uses Windows quoting and can be pasted into Command Prompt.")
    else:
        notes.append("The displayed command uses POSIX shell quoting and can be pasted into a terminal.")
    return notes


class CommandInspectorDialog(QDialog):
    def __init__(
        self,
        parent: Optional[QWidget],
        plan: CommandPlan,
        config: ScanConfiguration,
        env: Optional[NmapEnvironment],
        starting_point: str,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Command Inspector")
        self.resize(820, 600)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        layout.addWidget(label("Generated command", role="section"))
        command_text = plan.display(program_name=str(plan.program))
        command = _mono_text(command_text, 70)
        layout.addWidget(command)
        row = QHBoxLayout()
        copy_full = QPushButton("Copy command")
        copy_full.clicked.connect(lambda: QApplication.clipboard().setText(command_text))
        copy_user = QPushButton("Copy without Genmap managed options")
        user_text = plan.display_user_command()
        copy_user.clicked.connect(lambda: QApplication.clipboard().setText(user_text))
        copy_user.setToolTip(user_text)
        row.addWidget(copy_full)
        row.addWidget(copy_user)
        row.addStretch(1)
        layout.addLayout(row)

        tabs = QTabWidget()
        layout.addWidget(tabs, 1)

        overview = QWidget()
        ov_layout = QVBoxLayout(overview)
        grid = KeyValueGrid()
        grid.add_row("Executable", str(plan.program), mono=True)
        grid.add_row("Working directory", str(plan.working_directory) if plan.working_directory else "Scan result folder (created at launch)", mono=True)
        grid.add_row("Starting point", starting_point)
        grid.add_row("Targets", " ".join(plan.targets) or "(none)", mono=True)
        grid.add_row("Argument count", str(len(plan.arguments)))
        ov_layout.addWidget(grid)
        ov_layout.addWidget(label("Environment considerations", role="section"))
        for note in environment_notes(env, config):
            ov_layout.addWidget(hint("• " + note))
        if plan.warnings:
            ov_layout.addWidget(label("Warnings", role="section"))
            for warning in plan.warnings:
                ov_layout.addWidget(label(warning, status="warning", wrap=True))
        ov_layout.addStretch(1)
        tabs.addTab(overview, "Overview")

        table = QTableWidget(0, 3)
        table.setHorizontalHeaderLabels(["#", "Argument", "Source"])
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        rows: list[tuple[str, str]] = [(a, "Scan configuration") for a in plan.user_arguments]
        for managed in plan.managed_arguments:
            rows.extend((a, f"Genmap: {managed.reason}") for a in managed.arguments)
        rows.extend((a, "Target specification") for a in plan.targets)
        for index, (argument, source) in enumerate(rows):
            table.insertRow(index)
            table.setItem(index, 0, QTableWidgetItem(str(index + 1)))
            table.setItem(index, 1, QTableWidgetItem(argument))
            table.setItem(index, 2, QTableWidgetItem(source))
        table.resizeColumnToContents(0)
        tabs.addTab(table, "Arguments")

        tabs.addTab(_mono_text(config.to_json(), 200), "Configuration")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
