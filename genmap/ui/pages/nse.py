"""NSE page: browse the scripts installed with Nmap."""

from __future__ import annotations

import html
from typing import Optional

from PyQt6.QtCore import QSortFilterProxyModel, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QStandardItem, QStandardItemModel
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QSplitter,
    QTableView,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from genmap.core.nse import CATEGORY_DESCRIPTIONS, ScriptCatalog, ScriptEntry
from genmap.nmap.environment import NmapEnvironment
from genmap.nmap.nse_docs import ScriptDocumentation, load_script_documentation
from genmap.ui.app_context import AppContext
from genmap.ui.pages.base import BasePage
from genmap.ui.tasks import run_in_background
from genmap.ui.widgets.common import PageHeader, label
from genmap.ui.widgets.inputs import EnumCombo, TextField

ROLE_NAME = Qt.ItemDataRole.UserRole + 1
ROLE_SEARCH = Qt.ItemDataRole.UserRole + 2
ROLE_CATEGORIES = Qt.ItemDataRole.UserRole + 3
ROLE_RISKY = Qt.ItemDataRole.UserRole + 4


def _description_html(text: str) -> str:
    """Prose paragraphs are reflowed; indented blocks (examples, lists of output) stay preformatted."""
    import textwrap

    out: list[str] = []
    for block in text.split("\n\n"):
        lines = [line for line in block.splitlines() if line.strip()]
        if not lines:
            continue
        if all(line.startswith((" ", "\t")) for line in lines) or any(line.lstrip().startswith("|") for line in lines):
            out.append(f"<pre>{html.escape(textwrap.dedent(chr(10).join(lines)))}</pre>")
        elif all(line.lstrip().startswith(("* ", "- ")) for line in lines):
            items = "".join(f"<li>{html.escape(line.lstrip()[2:].strip())}</li>" for line in lines)
            out.append(f"<ul>{items}</ul>")
        else:
            out.append(f"<p>{html.escape(' '.join(block.split()))}</p>")
    return "".join(out)


class ScriptFilterProxy(QSortFilterProxyModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.terms: list[str] = []
        self.category = ""
        self.hide_risky = False

    def filterAcceptsRow(self, source_row, source_parent) -> bool:
        index = self.sourceModel().index(source_row, 0, source_parent)
        if self.hide_risky and index.data(ROLE_RISKY):
            return False
        if self.category and self.category not in (index.data(ROLE_CATEGORIES) or ()):
            return False
        haystack = index.data(ROLE_SEARCH) or ""
        return all(term in haystack for term in self.terms)


class NsePage(BasePage):
    page_key = "nse"
    page_title = "NSE Scripts"

    add_script_requested = pyqtSignal(str)

    def __init__(self, context: AppContext, parent: Optional[QWidget] = None) -> None:
        super().__init__(context, parent)
        self._catalog: Optional[ScriptCatalog] = None
        self._docs: dict[str, ScriptDocumentation] = {}
        self._loaded_for: Optional[str] = None
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 22, 28, 18)
        outer.setSpacing(12)
        outer.addWidget(PageHeader(
            "NSE Scripts",
            "The scripts installed with your Nmap, read from its script database and script files. Categories are Nmap's own.",
        ))
        filters = QHBoxLayout()
        self.search = TextField("Search names, descriptions, and arguments, e.g. smb vuln, ssl cert, brute")
        self.category = EnumCombo([("All categories", "")])
        self.hide_risky = QCheckBox("Hide intrusive scripts")
        self.hide_risky.setToolTip("Hide scripts in the categories listed under Settings, NSE")
        filters.addWidget(self.search, 1)
        filters.addWidget(self.category)
        filters.addWidget(self.hide_risky)
        outer.addLayout(filters)
        self.count = label("", role="small")
        outer.addWidget(self.count)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        self.model = QStandardItemModel(0, 2)
        self.model.setHorizontalHeaderLabels(["Script", "Categories"])
        self.proxy = ScriptFilterProxy()
        self.proxy.setSourceModel(self.model)
        self.proxy.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 260)
        self.table.setAccessibleName("Installed NSE scripts")
        splitter.addWidget(self.table)

        detail = QWidget()
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(8, 0, 0, 0)
        actions = QHBoxLayout()
        self.add_button = QPushButton("Add to scan")
        self.add_button.setProperty("accent", True)
        self.add_button.setToolTip("Add this script to the New Scan script selection")
        self.copy_button = QPushButton("Copy name")
        actions.addWidget(self.add_button)
        actions.addWidget(self.copy_button)
        actions.addStretch(1)
        detail_layout.addLayout(actions)
        self.details = QTextBrowser()
        self.details.setOpenLinks(False)
        self.details.anchorClicked.connect(self._on_link)
        self.details.setAccessibleName("Script details")
        detail_layout.addWidget(self.details, 1)
        splitter.addWidget(detail)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        splitter.setSizes([420, 620])
        outer.addWidget(splitter, 1)

        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(200)
        self._search_timer.timeout.connect(self._apply_filter)
        self.search.textChanged.connect(self._search_timer.start)
        self.category.currentIndexChanged.connect(self._apply_filter)
        self.hide_risky.toggled.connect(self._apply_filter)
        self.table.selectionModel().currentRowChanged.connect(lambda *_: self._show_selected())
        self.table.doubleClicked.connect(lambda _i: self._add())
        self.add_button.clicked.connect(self._add)
        self.copy_button.clicked.connect(lambda: self._selected_name() and QApplication.clipboard().setText(self._selected_name()))
        context.environment_changed.connect(self._on_environment)

    def on_shown(self) -> None:
        self._on_environment(self.context.environment)

    def _intrusive(self) -> set[str]:
        return {c.lower() for c in self.context.settings.nse.intrusive_categories}

    def _on_environment(self, env: Optional[NmapEnvironment]) -> None:
        catalog = env.scripts if env is not None else None
        key = f"{env.data_directory}:{len(catalog.scripts)}" if env is not None and catalog else None
        if key == self._loaded_for and key is not None:
            return
        self._loaded_for = key
        self._catalog = catalog if catalog and catalog.scripts else None
        self._docs = {}
        self._populate(env)
        if self._catalog is not None and env is not None:
            data_directory = env.data_directory
            names = [s.name for s in self._catalog.scripts]
            run_in_background(
                lambda: {name: load_script_documentation(data_directory, name) for name in names},
                self._docs_loaded,
            )

    def _docs_loaded(self, docs: dict[str, ScriptDocumentation]) -> None:
        self._docs = docs
        for row in range(self.model.rowCount()):
            item = self.model.item(row, 0)
            doc = docs.get(item.data(ROLE_NAME))
            if doc is not None:
                extra = " ".join([doc.description, " ".join(a.name for a in doc.arguments)]).lower()
                item.setData(item.data(ROLE_SEARCH) + " " + extra, ROLE_SEARCH)
                item.setToolTip(doc.summary)
        self._apply_filter()
        self._show_selected()

    def _populate(self, env: Optional[NmapEnvironment]) -> None:
        self.model.removeRows(0, self.model.rowCount())
        current_category = self.category.current_value()
        self.category.blockSignals(True)
        self.category.clear()
        self.category.addItem("All categories", "")
        if self._catalog is None:
            self.category.blockSignals(False)
            reason = "Nmap has not been checked yet." if env is None else (
                "Nmap was not found." if not env.usable else "Nmap's script database (scripts/script.db) was not found."
            )
            self.count.setText(reason + " Script names can still be typed on the New Scan page.")
            self.details.setHtml("")
            self._update_buttons()
            return
        risky_categories = self._intrusive()
        for category in self._catalog.categories:
            suffix = "  (intrusive)" if category in risky_categories else ""
            self.category.addItem(category + suffix, category)
            self.category.setItemData(self.category.count() - 1, CATEGORY_DESCRIPTIONS.get(category, ""), Qt.ItemDataRole.ToolTipRole)
        self.category.set_current_value(current_category or "")
        self.category.blockSignals(False)
        warning = QColor(self.context.theme.palette.warning)
        for script in self._catalog.scripts:
            risky = any(c in risky_categories for c in script.categories)
            name_item = QStandardItem(script.name)
            name_item.setData(script.name, ROLE_NAME)
            name_item.setData(f"{script.name} {' '.join(script.categories)}".lower(), ROLE_SEARCH)
            name_item.setData(tuple(script.categories), ROLE_CATEGORIES)
            name_item.setData(risky, ROLE_RISKY)
            categories_item = QStandardItem(", ".join(script.categories))
            if risky:
                categories_item.setForeground(warning)
                categories_item.setToolTip("Includes a category Nmap describes as intrusive or disruptive.")
            for item in (name_item, categories_item):
                item.setEditable(False)
            self.model.appendRow([name_item, categories_item])
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self._apply_filter()
        if self.proxy.rowCount():
            self.table.selectRow(0)

    def _apply_filter(self) -> None:
        self._search_timer.stop()
        self.proxy.terms = self.search.text().lower().split()
        self.proxy.category = str(self.category.current_value() or "")
        self.proxy.hide_risky = self.hide_risky.isChecked()
        self.proxy.invalidateFilter()
        if self._catalog is not None:
            total = len(self._catalog.scripts)
            shown = self.proxy.rowCount()
            note = "" if self._docs else "  Loading descriptions..."
            self.count.setText(f"Showing {shown} of {total} installed scripts.{note}")
        if self.proxy.rowCount() and not self.table.selectionModel().hasSelection():
            self.table.selectRow(0)
        self._update_buttons()

    def _selected_name(self) -> Optional[str]:
        index = self.table.selectionModel().currentIndex()
        if not index.isValid():
            return None
        return self.proxy.mapToSource(index).siblingAtColumn(0).data(ROLE_NAME)

    def _entry(self, name: str) -> Optional[ScriptEntry]:
        if self._catalog is None:
            return None
        return next((s for s in self._catalog.scripts if s.name == name), None)

    def _update_buttons(self) -> None:
        has = self._selected_name() is not None
        self.add_button.setEnabled(has)
        self.copy_button.setEnabled(has)

    def _show_selected(self) -> None:
        self._update_buttons()
        name = self._selected_name()
        if name is None:
            self.details.setHtml("")
            return
        self.details.setHtml(self._render(name))

    def _render(self, name: str) -> str:
        palette = self.context.theme.palette
        e = html.escape
        entry = self._entry(name)
        doc = self._docs.get(name)
        risky_categories = self._intrusive()
        parts = [f"""<style>
            h2 {{ margin: 0 0 6px 0; }} h3 {{ margin: 14px 0 4px 0; }}
            .muted {{ color: {palette.text_muted}; }} .warn {{ color: {palette.warning}; font-weight: 600; }}
            pre {{ background: {palette.surface_alt}; padding: 8px; white-space: pre-wrap; font-family: Consolas, 'Cascadia Mono', Menlo, monospace; }}
            td {{ padding: 3px 12px 3px 0; vertical-align: top; }} a {{ color: {palette.accent}; }}
        </style>""", f"<h2>{e(name)}</h2>"]
        if entry is not None:
            chips = []
            for category in entry.categories:
                text = e(category)
                chips.append(f"<span class='warn'>{text}</span>" if category in risky_categories else text)
            parts.append(f"<p>Categories: {', '.join(chips)}</p>")
            risky = [c for c in entry.categories if c in risky_categories]
            if risky:
                parts.append(
                    "<p class='warn'>Nmap files this script under "
                    + e(", ".join(risky))
                    + ". It may disrupt services, lock accounts, or be treated as an attack. Run it only where you are authorized.</p>"
                )
        if doc is None:
            parts.append("<p class='muted'>Loading the script's documentation...</p>" if self._catalog else "")
            return "".join(parts)
        if not doc.readable:
            parts.append(f"<p class='muted'>The script file could not be read{': ' + e(str(doc.path)) if doc.path else ''}.</p>")
            return "".join(parts)
        if doc.description:
            parts.append(_description_html(doc.description))
        if doc.arguments:
            rows = "".join(f"<tr><td><b>{e(a.name)}</b></td><td>{e(a.description)}</td></tr>" for a in doc.arguments)
            parts.append(f"<h3>Arguments</h3><table>{rows}</table>")
            parts.append("<p class='muted'>Set arguments on the Scripts tab of New Scan under Script arguments.</p>")
        if doc.usage:
            parts.append("<h3>Usage</h3>" + "".join(f"<pre>{e(u)}</pre>" for u in doc.usage))
        if doc.output:
            parts.append(f"<h3>Example output</h3><pre>{e(doc.output)}</pre>")
            parts.append("<p class='muted'>Sample from the script's own documentation, not from your network.</p>")
        if doc.see_also:
            links = ", ".join(f"<a href='script:{e(s.removesuffix('.nse'))}'>{e(s.removesuffix('.nse'))}</a>" for s in doc.see_also)
            parts.append(f"<h3>See also</h3><p>{links}</p>")
        meta = []
        if doc.authors:
            meta.append("By " + e(", ".join(doc.authors)))
        if doc.path:
            meta.append(e(str(doc.path)))
        if meta:
            parts.append(f"<p class='muted'>{'<br>'.join(meta)}</p>")
        return "".join(parts)

    def _on_link(self, url) -> None:
        text = url.toString()
        if text.startswith("script:"):
            self.select_script(text[len("script:"):])

    def select_script(self, name: str) -> None:
        for row in range(self.proxy.rowCount()):
            if self.proxy.index(row, 0).data(ROLE_NAME) == name:
                self.table.selectRow(row)
                self.table.scrollTo(self.proxy.index(row, 0))
                return
        self.search.clear()
        self.category.set_current_value("")
        self.hide_risky.setChecked(False)
        self._apply_filter()
        for row in range(self.proxy.rowCount()):
            if self.proxy.index(row, 0).data(ROLE_NAME) == name:
                self.table.selectRow(row)
                self.table.scrollTo(self.proxy.index(row, 0))
                return

    def _add(self) -> None:
        name = self._selected_name()
        if name:
            self.add_script_requested.emit(name)
