"""Reports page: create HTML, JSON, CSV, or XML reports from stored scans."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QStandardPaths, Qt, QUrl
from PyQt6.QtGui import QColor, QDesktopServices
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from genmap.engine.run_store import RunStatus
from genmap.errors import GenmapError
from genmap.reporting import REPORT_FORMATS, ReportOptions, ReportSource, generate_report
from genmap.storage.reports import ReportInfo
from genmap.ui.app_context import AppContext
from genmap.ui.pages.base import BasePage
from genmap.ui.pages.history import status_label
from genmap.ui.tasks import run_in_background
from genmap.ui.widgets.common import Card, PageHeader, form_layout, hint, label
from genmap.ui.widgets.error_dialog import show_exception
from genmap.ui.widgets.inputs import EnumCombo, TextField
from genmap.ui.widgets.responsive import FlowLayout

ROLE_ID = Qt.ItemDataRole.UserRole + 1


def default_report_directory(configured: Optional[str]) -> Path:
    if configured:
        return Path(configured).expanduser()
    documents = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DocumentsLocation)
    return Path(documents or Path.home()) / "Genmap Reports"


def report_file_name(target_summary: str, run_id: str, extension: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", target_summary).strip("_.")[:60] or "scan"
    return f"genmap-{slug}-{run_id}{extension}"


class ReportsPage(BasePage):
    page_key = "reports"
    page_title = "Reports"

    def __init__(self, context: AppContext, parent: Optional[QWidget] = None) -> None:
        super().__init__(context, parent)
        self._busy = False
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 22, 28, 18)
        outer.setSpacing(12)
        outer.addWidget(PageHeader(
            "Reports",
            "Turn a stored scan into a shareable file. Reports contain what Nmap reported and never add risk ratings of their own.",
        ))
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        form_card = Card("New report")
        form = form_layout()
        self.scan = EnumCombo([])
        self.scan.setMinimumWidth(320)
        self.scan.setToolTip("Only scans whose files are still on disk can be reported")
        form.addRow("Scan", self.scan)
        formats = QWidget()
        formats_layout = QVBoxLayout(formats)
        formats_layout.setContentsMargins(0, 0, 0, 0)
        self.format_group = QButtonGroup(self)
        self._format_buttons: dict[str, QRadioButton] = {}
        for key, (caption, extension) in REPORT_FORMATS.items():
            button = QRadioButton(f"{caption} ({extension})")
            self.format_group.addButton(button)
            self._format_buttons[key] = button
            formats_layout.addWidget(button)
        form.addRow("Format", formats)
        self.title = TextField("Default: Nmap scan of <targets>")
        form.addRow("Title", self.title)
        options = QWidget()
        options_layout = QVBoxLayout(options)
        options_layout.setContentsMargins(0, 0, 0, 0)
        self.opt_scripts = QCheckBox("Include NSE script output")
        self.opt_scripts.setChecked(True)
        self.opt_config = QCheckBox("Include the scan configuration")
        self.opt_config.setChecked(True)
        self.opt_closed = QCheckBox("Include closed and filtered ports")
        self.opt_down = QCheckBox("Include hosts reported as down")
        for box in (self.opt_scripts, self.opt_config, self.opt_closed, self.opt_down):
            options_layout.addWidget(box)
        form.addRow("Content", options)
        self.folder = TextField("Folder")
        folder_row = QWidget()
        folder_layout = QHBoxLayout(folder_row)
        folder_layout.setContentsMargins(0, 0, 0, 0)
        folder_layout.addWidget(self.folder, 1)
        browse = QPushButton("Browse...")
        browse.clicked.connect(self._browse)
        folder_layout.addWidget(browse)
        form.addRow("Save to", folder_row)
        form_card.add_layout(form)
        self.option_note = hint("")
        form_card.add_widget(self.option_note)
        buttons = QHBoxLayout()
        self.create_button = QPushButton("Create report")
        self.create_button.setProperty("accent", True)
        self.create_button.clicked.connect(self.create_report)
        buttons.addWidget(self.create_button)
        buttons.addStretch(1)
        form_card.add_layout(buttons)
        self.status = label("", wrap=True, selectable=True)
        form_card.add_widget(self.status)
        form_card.add_stretch()
        form_scroller = QScrollArea()
        form_scroller.setWidgetResizable(True)
        form_scroller.setFrameShape(QScrollArea.Shape.NoFrame)
        form_scroller.setWidget(form_card)
        splitter.addWidget(form_scroller)

        list_card = Card("Created reports")
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Created", "Title", "Format", "File"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.doubleClicked.connect(lambda _i: self._open_selected())
        self.table.itemSelectionChanged.connect(self._update_list_buttons)
        list_card.add_widget(self.table, 1)
        row = FlowLayout()
        self.open_button = QPushButton("Open")
        self.folder_button = QPushButton("Show in folder")
        self.forget_button = QPushButton("Remove from list")
        self.delete_button = QPushButton("Delete file")
        self.delete_button.setProperty("danger", True)
        for button in (self.open_button, self.folder_button, self.forget_button, self.delete_button):
            row.addWidget(button)
        list_card.add_layout(row)
        splitter.addWidget(list_card)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        splitter.setSizes([460, 640])
        outer.addWidget(splitter, 1)

        self._format_buttons[context.settings.reports.default_format].setChecked(True)
        self.format_group.buttonToggled.connect(lambda *_: self._update_form())
        self.scan.currentIndexChanged.connect(lambda *_: self._update_form())
        self.open_button.clicked.connect(self._open_selected)
        self.folder_button.clicked.connect(self._show_folder)
        self.forget_button.clicked.connect(lambda: self._remove(delete_file=False))
        self.delete_button.clicked.connect(lambda: self._remove(delete_file=True))
        context.index_changed.connect(self._reload_scans_if_visible)
        context.reports_changed.connect(self._reload_list)

    def on_shown(self) -> None:
        if not self.folder.text():
            self.folder.setText(str(default_report_directory(self.context.settings.reports.default_output_directory)))
        self._reload_scans()
        self._reload_list()

    def select_scan(self, run_id: str) -> None:
        self._reload_scans()
        self.scan.set_current_value(run_id)

    def _reload_scans_if_visible(self) -> None:
        if self.isVisible():
            self._reload_scans()

    def _reload_scans(self) -> None:
        current = self.scan.current_value()
        try:
            scans = [s for s in self.context.scan_index.list_scans(include_missing=False) if s.status != RunStatus.RUNNING.value]
        except Exception:
            scans = []
        self.scan.blockSignals(True)
        self.scan.clear()
        for scan in scans:
            when = scan.created_at.astimezone().strftime("%Y-%m-%d %H:%M")
            self.scan.addItem(f"{when}  {scan.target_summary}  ({status_label(scan.status)})", scan.run_id)
        if current:
            self.scan.set_current_value(current)
        self.scan.blockSignals(False)
        self._update_form()

    def _format(self) -> str:
        return next(key for key, button in self._format_buttons.items() if button.isChecked())

    def _update_form(self) -> None:
        fmt = self._format()
        has_scan = self.scan.count() > 0
        content_options = fmt != "xml"
        for box in (self.opt_scripts, self.opt_closed, self.opt_down, self.opt_config):
            box.setEnabled(content_options)
        self.opt_config.setEnabled(fmt in ("html", "json"))
        self.title.setEnabled(fmt == "html")
        notes = {
            "html": "A single self contained page that opens in any browser and prints cleanly.",
            "json": "Structured data for other tools: scan details, summary, warnings, and every host.",
            "csv": "One row per port, for spreadsheets. Host level details and OS guesses are not included.",
            "xml": "An exact copy of Nmap's own XML output, readable by any Nmap aware tool.",
        }
        self.option_note.setText(notes[fmt] if has_scan else "Run a scan first; reports are created from stored scans.")
        self.create_button.setEnabled(has_scan and not self._busy)

    def _browse(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Report folder", self.folder.text() or str(Path.home()))
        if path:
            self.folder.setText(path)

    def create_report(self) -> None:
        run_id = self.scan.current_value()
        if not run_id or self._busy:
            return
        fmt = self._format()
        options = ReportOptions(
            include_closed_ports=self.opt_closed.isChecked(),
            include_down_hosts=self.opt_down.isChecked(),
            include_script_output=self.opt_scripts.isChecked(),
            include_configuration=self.opt_config.isChecked(),
            title=self.title.text().strip(),
        )
        try:
            record = self.context.run_store.load(run_id)
        except GenmapError as exc:
            show_exception(self, exc, "Report not created")
            return
        folder = Path(self.folder.text().strip() or default_report_directory(None))
        path = folder / report_file_name(record.target_summary, run_id, REPORT_FORMATS[fmt][1])
        if path.exists():
            answer = QMessageBox.question(
                self,
                "Replace report",
                f"{path.name} already exists in that folder. Replace it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        store = self.context.run_store

        def work() -> Path:
            result = store.load_result(run_id)
            if result is None:
                raise GenmapError("This scan has no Nmap XML, so there is nothing to report.", remedy=record.error_message)
            source = ReportSource(result=result, xml_path=store.xml_path(run_id), record=record)
            return generate_report(source, fmt, path, options)

        def done(written: Path) -> None:
            self._set_busy(False)
            title = options.title or f"Nmap scan of {record.target_summary}"
            self.context.reports.add(run_id, title, fmt, written, options.as_dict())
            self.context.reports_changed.emit()
            self.status.setText(f"Saved {written}")
            self.status.setProperty("status", "ok")
            self.status.style().polish(self.status)

        def failed(exc: BaseException) -> None:
            self._set_busy(False)
            self.status.setText("")
            show_exception(self, exc, "Report not created")

        self._set_busy(True)
        self.status.setText("Creating report...")
        run_in_background(work, done, failed)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self._update_form()

    # List -------------------------------------------------------------------

    def _reload_list(self) -> None:
        try:
            reports = self.context.reports.list()
        except Exception:
            reports = []
        self._reports = {r.id: r for r in reports}
        muted = QColor(self.context.theme.palette.text_muted)
        self.table.setRowCount(len(reports))
        for row, report in enumerate(reports):
            exists = report.exists
            items = [
                QTableWidgetItem(report.created_at.astimezone().strftime("%Y-%m-%d %H:%M")),
                QTableWidgetItem(report.title),
                QTableWidgetItem(report.format.upper()),
                QTableWidgetItem(str(report.path) if exists else f"{report.path} (file missing)"),
            ]
            items[1].setToolTip(report.title)
            items[3].setToolTip(str(report.path))
            for column, item in enumerate(items):
                item.setData(ROLE_ID, report.id)
                if not exists:
                    item.setForeground(muted)
                self.table.setItem(row, column, item)
        self.table.resizeColumnToContents(0)
        self.table.resizeColumnToContents(2)
        self._update_list_buttons()

    def _selected(self) -> Optional[ReportInfo]:
        items = self.table.selectedItems()
        if not items:
            return None
        return self._reports.get(items[0].data(ROLE_ID))

    def _update_list_buttons(self) -> None:
        report = self._selected()
        exists = report is not None and report.exists
        self.open_button.setEnabled(exists)
        self.folder_button.setEnabled(exists)
        self.forget_button.setEnabled(report is not None)
        self.delete_button.setEnabled(exists)

    def _open_selected(self) -> None:
        report = self._selected()
        if report is not None and report.exists:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(report.path)))

    def _show_folder(self) -> None:
        report = self._selected()
        if report is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(report.path.parent)))

    def _remove(self, *, delete_file: bool) -> None:
        report = self._selected()
        if report is None:
            return
        if delete_file:
            answer = QMessageBox.warning(
                self,
                "Delete report",
                f"Delete {report.path.name} from disk? This cannot be undone.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        try:
            self.context.reports.remove(report.id, delete_file=delete_file)
        except OSError as exc:
            show_exception(self, GenmapError("The report file could not be deleted.", details=str(exc)), "Delete failed")
            return
        self.context.reports_changed.emit()
