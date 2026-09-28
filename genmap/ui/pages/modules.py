"""Registered modules and their manifests."""

from __future__ import annotations

import json
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QPlainTextEdit,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from genmap import MODULE_API_VERSION
from genmap.ui.app_context import AppContext
from genmap.ui.pages.base import BasePage
from genmap.ui.widgets.common import Card, KeyValueGrid, PageHeader, hint


class ModulesPage(BasePage):
    page_key = "modules"
    page_title = "Modules"

    def __init__(self, context: AppContext, parent: Optional[QWidget] = None) -> None:
        super().__init__(context, parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 22, 28, 18)
        outer.setSpacing(12)
        outer.addWidget(PageHeader(
            "Modules",
            f"Tools plug into Genmap through a versioned module contract (API {MODULE_API_VERSION}). Nmap is the first module.",
        ))
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Module", "ID", "Version", "State", "API", "Capabilities"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self._show_selected)
        splitter.addWidget(self.table)

        detail = QWidget()
        layout = QVBoxLayout(detail)
        layout.setContentsMargins(0, 8, 0, 0)
        card = Card("Manifest")
        self.grid = KeyValueGrid()
        for key in ("Name", "Description", "Author", "Homepage", "Platforms", "External tools", "Last error"):
            self.grid.add_row(key)
        card.add_widget(self.grid)
        card.add_widget(hint("The configuration schema below is what a module declares so Genmap can validate and store its settings."))
        self.schema = QPlainTextEdit()
        self.schema.setReadOnly(True)
        self.schema.setProperty("role", "mono")
        self.schema.setMinimumHeight(160)
        card.add_widget(self.schema, 1)
        layout.addWidget(card, 1)
        splitter.addWidget(detail)
        splitter.setSizes([180, 420])
        outer.addWidget(splitter, 1)
        context.environment_changed.connect(lambda _env: self.reload())

    def on_shown(self) -> None:
        self.reload()

    def reload(self) -> None:
        modules = list(self.context.registry)
        self.table.setRowCount(len(modules))
        for row, module in enumerate(modules):
            manifest = module.manifest
            values = [manifest.name, manifest.id, manifest.version, module.state.value, manifest.api_version, ", ".join(manifest.capabilities)]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, manifest.id)
                self.table.setItem(row, column, item)
        self.table.resizeColumnsToContents()
        if modules and not self.table.selectedItems():
            self.table.selectRow(0)
        self._show_selected()

    def _show_selected(self) -> None:
        items = self.table.selectedItems()
        if not items:
            return
        module = self.context.registry.get(items[0].data(Qt.ItemDataRole.UserRole))
        if module is None:
            return
        manifest = module.manifest
        self.grid.set_value("Name", manifest.name)
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
