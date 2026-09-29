"""Scan history backed by the run folders on disk."""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import QSortFilterProxyModel, Qt, QUrl, pyqtSignal
from PyQt6.QtGui import QColor, QDesktopServices, QStandardItem, QStandardItemModel
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QMenu,
    QMessageBox,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from genmap.engine.run_store import RunRecord, RunStatus
from genmap.errors import GenmapError
from genmap.ui.app_context import AppContext
from genmap.ui.pages.base import BasePage
from genmap.ui.pages.scan_monitor import format_duration
from genmap.ui.widgets.common import PageHeader, label
from genmap.ui.widgets.error_dialog import show_exception
from genmap.ui.widgets.inputs import TextField

ROLE_RUN_ID = Qt.ItemDataRole.UserRole + 1
ROLE_SORT = Qt.ItemDataRole.UserRole + 2

_STATUS_COLOR = {
    RunStatus.COMPLETED: "success",
    RunStatus.COMPLETED_WITH_WARNINGS: "warning",
    RunStatus.FAILED: "danger",
    RunStatus.CRASHED: "danger",
    RunStatus.CANCELLED: "text_muted",
    RunStatus.TIMED_OUT: "warning",
    RunStatus.RUNNING: "info",
    RunStatus.INTERRUPTED: "warning",
}


class HistoryPage(BasePage):
    page_key = "history"
    page_title = "Scan History"

    open_requested = pyqtSignal(str)
    duplicate_requested = pyqtSignal(object)  # ScanConfiguration
    rerun_requested = pyqtSignal(object)  # ScanConfiguration
    monitor_requested = pyqtSignal(str)

    HEADERS = ["Started", "Targets", "Starting point", "Status", "Duration", "Hosts up", "Open ports", "Nmap", "Command"]

    def __init__(self, context: AppContext, parent: Optional[QWidget] = None) -> None:
        super().__init__(context, parent)
        self._records: dict[str, RunRecord] = {}
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 22, 28, 18)
        outer.setSpacing(12)
        outer.addWidget(PageHeader("Scan History", "Every scan keeps its configuration, command, console output, and raw Nmap XML."))

        toolbar = QHBoxLayout()
        self.search = TextField("Search targets, status, commands...")
        toolbar.addWidget(self.search, 1)
        self.open_button = QPushButton("Open results")
        self.open_button.setProperty("accent", True)
        self.rerun_button = QPushButton("Rerun")
        self.rerun_button.setToolTip("Run the same configuration again after confirmation")
        self.duplicate_button = QPushButton("Edit copy")
        self.duplicate_button.setToolTip("Load this configuration into New Scan without starting it")
        self.folder_button = QPushButton("Show files")
        self.delete_button = QPushButton("Delete")
        self.delete_button.setProperty("danger", True)
        refresh = QPushButton("Refresh")
        for button in (self.open_button, self.rerun_button, self.duplicate_button, self.folder_button, self.delete_button, refresh):
            toolbar.addWidget(button)
        outer.addLayout(toolbar)

        self.model = QStandardItemModel(0, len(self.HEADERS))
        self.model.setHorizontalHeaderLabels(self.HEADERS)
        self.proxy = QSortFilterProxyModel()
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)
        self.proxy.setSortRole(ROLE_SORT)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.doubleClicked.connect(lambda _index: self._open())
        self.table.setAccessibleName("Scan history")
        outer.addWidget(self.table, 1)
        self.status = label("", role="small")
        outer.addWidget(self.status)

        self.search.textChanged.connect(self.proxy.setFilterFixedString)
        self.open_button.clicked.connect(self._open)
        self.rerun_button.clicked.connect(self._rerun)
        self.duplicate_button.clicked.connect(self._duplicate)
        self.folder_button.clicked.connect(self._show_folder)
        self.delete_button.clicked.connect(self._delete)
        refresh.clicked.connect(self.reload)
        self.table.selectionModel().selectionChanged.connect(lambda *_: self._update_buttons())
        context.engine.job_started.connect(lambda _job: self.reload())
        context.engine.job_finished.connect(lambda _job: self.reload())
        self._update_buttons()

    def on_shown(self) -> None:
        self.reload()

    def reload(self) -> None:
        selected = set(self._selected_ids())
        records = self.context.run_store.list_runs()
        self._records = {r.run_id: r for r in records}
        self.model.removeRows(0, self.model.rowCount())
        palette = self.context.theme.palette
        for record in records:
            summary = record.summary
            duration = record.duration_seconds
            values = [
                (record.created_at.strftime("%Y-%m-%d %H:%M:%S"), record.created_at.timestamp()),
                (record.target_summary, record.target_summary.lower()),
                (record.profile_name or "", (record.profile_name or "").lower()),
                (record.status.label, record.status.value),
                (format_duration(duration) if duration is not None else "", duration or 0),
                (str(summary.hosts_up) if summary else "", summary.hosts_up if summary else -1),
                (str(summary.open_ports) if summary else "", summary.open_ports if summary else -1),
                (record.nmap_version or "", record.nmap_version or ""),
                (record.command.display if record.command else "", ""),
            ]
            row = []
            for text, sort in values:
                item = QStandardItem(text)
                item.setEditable(False)
                item.setData(record.run_id, ROLE_RUN_ID)
                item.setData(sort, ROLE_SORT)
                row.append(item)
            color_name = _STATUS_COLOR.get(record.status)
            if color_name:
                row[3].setForeground(QColor(getattr(palette, color_name)))
            if record.error_message:
                row[3].setToolTip(record.error_message + (f"\n{record.error_remedy}" if record.error_remedy else ""))
            row[8].setToolTip(record.command.display if record.command else "")
            self.model.appendRow(row)
        self.table.sortByColumn(0, Qt.SortOrder.DescendingOrder)
        self.table.resizeColumnsToContents()
        for column, width in ((1, 260), (8, 400)):
            if self.table.columnWidth(column) > width:
                self.table.setColumnWidth(column, width)
        if selected:
            for row in range(self.proxy.rowCount()):
                if self.proxy.index(row, 0).data(ROLE_RUN_ID) in selected:
                    self.table.selectRow(row)
        elif self.proxy.rowCount():
            self.table.selectRow(0)
        size_mb = self.context.run_store.total_size_bytes() / 1_000_000
        self.status.setText(f"{len(records)} scan{'s' if len(records) != 1 else ''} stored, {size_mb:.1f} MB in {self.context.run_store.root}")
        self._update_buttons()

    def _selected_ids(self) -> list[str]:
        ids: list[str] = []
        selection = self.table.selectionModel()
        if selection is None:
            return ids
        for index in selection.selectedRows():
            run_id = index.data(ROLE_RUN_ID)
            if run_id and run_id not in ids:
                ids.append(run_id)
        return ids

    def _current(self) -> Optional[RunRecord]:
        ids = self._selected_ids()
        return self._records.get(ids[0]) if ids else None

    def _update_buttons(self) -> None:
        ids = self._selected_ids()
        single = len(ids) == 1
        record = self._current()
        running = record is not None and self.context.engine.job(record.run_id) is not None and self.context.engine.job(record.run_id).is_running
        self.open_button.setEnabled(single)
        self.open_button.setText("Show live scan" if running else "Open results")
        self.rerun_button.setEnabled(single and not running)
        self.duplicate_button.setEnabled(single)
        self.folder_button.setEnabled(single)
        any_running = any(self.context.engine.job(i) is not None and self.context.engine.job(i).is_running for i in ids)
        self.delete_button.setEnabled(bool(ids) and not any_running)

    def _open(self) -> None:
        record = self._current()
        if record is None:
            return
        job = self.context.engine.job(record.run_id)
        if job is not None and job.is_running:
            self.monitor_requested.emit(record.run_id)
        else:
            self.open_requested.emit(record.run_id)

    def _config_of(self, record: RunRecord):
        try:
            return record.scan_configuration()
        except Exception as exc:
            show_exception(self, exc, "Configuration could not be loaded")
            return None

    def _rerun(self) -> None:
        record = self._current()
        if record is None:
            return
        config = self._config_of(record)
        if config is not None:
            self.rerun_requested.emit(config)

    def _duplicate(self) -> None:
        record = self._current()
        if record is None:
            return
        config = self._config_of(record)
        if config is not None:
            self.duplicate_requested.emit(config)

    def _show_folder(self) -> None:
        record = self._current()
        if record is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.context.run_store.run_directory(record.run_id))))

    def _delete(self) -> None:
        ids = self._selected_ids()
        if not ids:
            return
        noun = "this scan" if len(ids) == 1 else f"these {len(ids)} scans"
        answer = QMessageBox.warning(
            self,
            "Delete scans",
            f"Permanently delete {noun}? The stored XML, console output, and configuration will be removed. This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        failures: list[str] = []
        for run_id in ids:
            try:
                self.context.run_store.delete(run_id)
            except GenmapError as exc:
                failures.append(f"{run_id}: {exc.details or exc.message}")
        self.reload()
        if failures:
            show_exception(self, GenmapError("Some scans could not be deleted.", details="\n".join(failures)), "Delete failed")

    def _context_menu(self, position) -> None:
        if not self._selected_ids():
            return
        menu = QMenu(self)
        for button in (self.open_button, self.rerun_button, self.duplicate_button, self.folder_button, self.delete_button):
            action = menu.addAction(button.text(), button.click)
            action.setEnabled(button.isEnabled())
        menu.exec(self.table.viewport().mapToGlobal(position))
