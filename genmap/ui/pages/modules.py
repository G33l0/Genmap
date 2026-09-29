"""Registered modules: state, diagnostics, manifest, and turning them on or off."""

from __future__ import annotations

import json
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from genmap import MODULE_API_VERSION
from genmap.modules.base import Module, ModuleState
from genmap.ui.app_context import AppContext
from genmap.ui.pages.base import BasePage
from genmap.ui.tasks import run_in_background
from genmap.ui.widgets.common import Card, KeyValueGrid, PageHeader, hint, label
from genmap.ui.widgets.diagnostics_view import DiagnosticsView
from genmap.ui.widgets.responsive import FlowLayout

ROLE_ID = Qt.ItemDataRole.UserRole

STATE_TEXT = {
    ModuleState.REGISTERED: ("Not checked yet", None),
    ModuleState.READY: ("Ready", "success"),
    ModuleState.DEGRADED: ("Ready with warnings", "warning"),
    ModuleState.UNAVAILABLE: ("Unavailable", "danger"),
    ModuleState.DISABLED: ("Turned off", "text_muted"),
    ModuleState.INCOMPATIBLE: ("Incompatible", "danger"),
    ModuleState.ERROR: ("Failed to load", "danger"),
}


class ModulesPage(BasePage):
    page_key = "modules"
    page_title = "Modules"

    def __init__(self, context: AppContext, parent: Optional[QWidget] = None) -> None:
        super().__init__(context, parent)
        self._checking: set[str] = set()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 22, 28, 18)
        outer.setSpacing(12)
        outer.addWidget(PageHeader(
            "Modules",
            f"Tools plug into Genmap through a versioned module contract (API {MODULE_API_VERSION}). "
            "A module that is turned off stays installed but cannot start scans.",
        ))
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Module", "State", "Version", "API", "Capabilities"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAccessibleName("Modules")
        self.table.itemSelectionChanged.connect(self._show_selected)
        splitter.addWidget(self.table)

        detail = QWidget()
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(12)
        actions = FlowLayout()
        self.toggle_button = QPushButton("Turn off")
        self.check_button = QPushButton("Check again")
        self.check_button.setToolTip("Run this module's environment check now")
        actions.addWidget(self.toggle_button)
        actions.addWidget(self.check_button)
        detail_layout.addLayout(actions)
        self.action_status = label("", role="small", wrap=True)
        self.action_status.hide()
        detail_layout.addWidget(self.action_status)

        diag_card = Card("Diagnostics")
        self.diagnostics = DiagnosticsView()
        diag_card.add_widget(self.diagnostics)
        detail_layout.addWidget(diag_card)

        card = Card("Manifest")
        self.grid = KeyValueGrid()
        for key in ("Name", "ID", "Description", "Author", "Homepage", "Platforms", "External tools", "Last error"):
            self.grid.add_row(key)
        card.add_widget(self.grid)
        card.add_widget(hint("The configuration schema below is what a module declares so Genmap can validate and store its settings."))
        self.schema = QPlainTextEdit()
        self.schema.setReadOnly(True)
        self.schema.setProperty("role", "mono")
        self.schema.setMinimumHeight(180)
        card.add_widget(self.schema)
        detail_layout.addWidget(card)
        detail_layout.addStretch(1)
        scroller = QScrollArea()
        scroller.setWidgetResizable(True)
        scroller.setFrameShape(QScrollArea.Shape.NoFrame)
        scroller.setWidget(detail)
        splitter.addWidget(scroller)
        splitter.setSizes([160, 480])
        outer.addWidget(splitter, 1)

        self.toggle_button.clicked.connect(self._toggle)
        self.check_button.clicked.connect(self._check)
        context.environment_changed.connect(lambda _env: self._reload_if_visible())
        context.environment_probe_started.connect(self._update_actions)
        context.modules_changed.connect(self.reload)

    def on_shown(self) -> None:
        self.reload()

    def _reload_if_visible(self) -> None:
        self._checking.discard("nmap")
        if self.isVisible():
            self.reload()

    def _selected(self) -> Optional[Module]:
        items = self.table.selectedItems()
        return self.context.registry.get(items[0].data(ROLE_ID)) if items else None

    def reload(self) -> None:
        selected = self._selected()
        selected_id = selected.manifest.id if selected else None
        modules = list(self.context.registry)
        palette = self.context.theme.palette
        self.table.blockSignals(True)
        self.table.setRowCount(len(modules))
        for row, module in enumerate(modules):
            manifest = module.manifest
            state_text, color = STATE_TEXT.get(module.state, (module.state.value, None))
            values = [manifest.name, state_text, manifest.version, manifest.api_version, ", ".join(manifest.capabilities)]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(ROLE_ID, manifest.id)
                self.table.setItem(row, column, item)
            if color:
                self.table.item(row, 1).setForeground(QColor(getattr(palette, color)))
        self.table.blockSignals(False)
        self.table.resizeColumnsToContents()
        target_row = next((r for r, m in enumerate(modules) if m.manifest.id == selected_id), 0 if modules else None)
        if target_row is not None:
            self.table.selectRow(target_row)
        self._show_selected()

    def _show_selected(self) -> None:
        module = self._selected()
        if module is None:
            return
        manifest = module.manifest
        self.grid.set_value("Name", manifest.name)
        self.grid.set_value("ID", manifest.id)
        self.grid.set_value("Description", manifest.description)
        self.grid.set_value("Author", manifest.author)
        self.grid.set_value("Homepage", manifest.homepage or "")
        self.grid.set_value("Platforms", ", ".join(manifest.platforms))
        tools = "; ".join(
            f"{t.name}{' >= ' + t.minimum_version if t.minimum_version else ''}{' (optional)' if t.optional else ''}: {t.purpose}"
            for t in manifest.external_tools
        )
        self.grid.set_value("External tools", tools or "None")
        self.grid.set_value("Last error", module.last_error or "None", status="error" if module.last_error else None)
        schema = manifest.configuration_schema
        self.schema.setPlainText(json.dumps(schema, indent=2) if schema else "This module does not declare a configuration schema.")
        self.diagnostics.set_diagnostics(module.last_diagnostics)
        self._update_actions()

    def _update_actions(self) -> None:
        module = self._selected()
        if module is None:
            self.toggle_button.setEnabled(False)
            self.check_button.setEnabled(False)
            return
        module_id = module.manifest.id
        enabled = self.context.registry.is_enabled(module_id)
        self.toggle_button.setText("Turn off" if enabled else "Turn on")
        self.toggle_button.setProperty("accent", not enabled)
        self.toggle_button.style().unpolish(self.toggle_button)
        self.toggle_button.style().polish(self.toggle_button)
        self.toggle_button.setEnabled(module.state not in (ModuleState.INCOMPATIBLE,))
        busy = module_id in self._checking or (module_id == "nmap" and self.context.probing)
        self.check_button.setEnabled(not busy and module.state not in (ModuleState.INCOMPATIBLE, ModuleState.ERROR))
        self.check_button.setText("Checking..." if busy else "Check again")

    def _toggle(self) -> None:
        module = self._selected()
        if module is None:
            return
        module_id = module.manifest.id
        enabled = self.context.registry.is_enabled(module_id)
        if enabled:
            running = [job for job in self.context.engine.active_jobs if job.record.module_id == module_id]
            if running:
                QMessageBox.information(self, "Module busy", f"A {module.manifest.name} scan is running. Turn the module off after it finishes.")
                return
            answer = QMessageBox.question(
                self,
                "Turn off module",
                f"Turn off the {module.manifest.name} module? Scans that use it cannot start until it is turned on again. "
                "Stored results stay available.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.context.set_module_enabled(module_id, not enabled)
        self._say(f"{module.manifest.name} is now {'off' if enabled else 'on'}.")

    def _say(self, text: str) -> None:
        self.action_status.setText(text)
        self.action_status.setVisible(bool(text))

    def _check(self) -> None:
        module = self._selected()
        if module is None:
            return
        module_id = module.manifest.id
        if module_id == "nmap":
            # The Nmap check also refreshes the environment every other page uses.
            self.context.refresh_environment()
            self._update_actions()
            return
        self._checking.add(module_id)
        self._update_actions()
        registry = self.context.registry

        def done(_diagnostics) -> None:
            self._checking.discard(module_id)
            self.reload()

        def failed(exc: BaseException) -> None:
            self._checking.discard(module_id)
            self._say(f"The check failed: {exc}")
            self.reload()

        run_in_background(lambda: registry.check(module_id), done, failed)
