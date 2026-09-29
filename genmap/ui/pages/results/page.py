"""Results viewer for a completed scan or an imported Nmap XML file."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QModelIndex, QSortFilterProxyModel, Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTableView,
    QTabWidget,
    QTextBrowser,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from genmap.core.results import ScanResult
from genmap.engine.run_store import RunRecord
from genmap.errors import GenmapError
from genmap.nmap.xml_parser import parse_nmap_xml_file
from genmap.reporting import result_to_csv
from genmap.ui.app_context import AppContext
from genmap.ui.pages.base import BasePage
from genmap.ui.pages.results.details import host_html, port_html
from genmap.ui.pages.results.models import (
    FILTER_FIELDS,
    ROLE_HOST_INDEX,
    ROLE_KIND,
    ROLE_PORT_INDEX,
    ROLE_SORT,
    PortTableModel,
    ResultFilterProxy,
    ResultTreeModel,
)
from genmap.ui.pages.scan_monitor import format_duration
from genmap.ui.tasks import run_in_background
from genmap.ui.widgets.common import Banner, Card, KeyValueGrid, Metric, PageHeader, label
from genmap.ui.widgets.error_dialog import show_exception
from genmap.ui.widgets.inputs import EnumCombo, TextField

log = logging.getLogger(__name__)


class ResultsPage(BasePage):
    page_key = "results"
    page_title = "Results"

    rerun_requested = pyqtSignal(object)  # ScanConfiguration
    report_requested = pyqtSignal(str)  # run id

    def __init__(self, context: AppContext, parent: Optional[QWidget] = None) -> None:
        super().__init__(context, parent)
        self.result: Optional[ScanResult] = None
        self.record: Optional[RunRecord] = None
        self.source_xml: Optional[Path] = None
        self._load_token = 0

        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 22, 28, 18)
        outer.setSpacing(12)
        header_row = QHBoxLayout()
        self.header = PageHeader("Results", "Open a scan from the history or import an Nmap XML file.")
        header_row.addWidget(self.header, 1)
        self.import_button = QPushButton("Import XML...")
        self.import_button.setToolTip("Open an XML file produced by nmap -oX")
        self.import_button.clicked.connect(self.import_xml_dialog)
        self.rerun_button = QPushButton("Edit and rerun")
        self.rerun_button.setToolTip("Load this scan's configuration into New Scan")
        self.rerun_button.clicked.connect(self._rerun)
        self.export_button = QPushButton("Export")
        export_menu = QMenu(self.export_button)
        export_menu.addAction("Nmap XML (original)", lambda: self._export("xml"))
        export_menu.addAction("JSON (Genmap normalized)", lambda: self._export("json"))
        export_menu.addAction("CSV (one row per port)", lambda: self._export("csv"))
        export_menu.addSeparator()
        self.report_action = export_menu.addAction("Create a report...", lambda: self.record and self.report_requested.emit(self.record.run_id))
        self.export_button.setMenu(export_menu)
        for button in (self.import_button, self.rerun_button, self.export_button):
            header_row.addWidget(button, 0, Qt.AlignmentFlag.AlignTop)
        outer.addLayout(header_row)

        self.banner = Banner("warning")
        outer.addWidget(self.banner)

        self.stack = QStackedWidget()
        outer.addWidget(self.stack, 1)
        self.empty = QWidget()
        empty_layout = QVBoxLayout(self.empty)
        empty_layout.addStretch(1)
        self.empty_label = label("No results loaded.", role="subtitle")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_layout.addWidget(self.empty_label)
        empty_layout.addStretch(2)
        self.stack.addWidget(self.empty)

        self.content = QWidget()
        content_layout = QVBoxLayout(self.content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(12)
        metrics = QHBoxLayout()
        metrics.setSpacing(12)
        self.metric_hosts = Metric("Hosts up")
        self.metric_open = Metric("Open ports")
        self.metric_services = Metric("Identified services")
        self.metric_elapsed = Metric("Scan time")
        for metric in (self.metric_hosts, self.metric_open, self.metric_services, self.metric_elapsed):
            metrics.addWidget(metric)
        content_layout.addLayout(metrics)

        self.tabs = QTabWidget()
        content_layout.addWidget(self.tabs, 1)
        self.stack.addWidget(self.content)

        self._build_hosts_tab()
        self._build_ports_tab()
        self._build_info_tab()
        self.output_view = QPlainTextEdit()
        self.output_view.setReadOnly(True)
        self.output_view.setProperty("role", "console")
        self.output_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.tabs.addTab(self.output_view, "Nmap output")
        self.xml_view = QPlainTextEdit()
        self.xml_view.setReadOnly(True)
        self.xml_view.setProperty("role", "mono")
        self.xml_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.tabs.addTab(self.xml_view, "XML")
        self._set_actions_enabled(False)
        context.theme.theme_changed.connect(lambda _p: self._reload_model())

    def _build_hosts_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        filters = QHBoxLayout()
        self.filter_text = TextField("Filter, e.g. 443, ssh, Apache, windows, cpe:/a:openbsd")
        self.filter_text.setAccessibleName("Filter results")
        self.filter_field = EnumCombo([(caption, key) for key, caption in FILTER_FIELDS])
        self.filter_field.setToolTip("Which field the filter text is matched against")
        self.filter_state = EnumCombo([
            ("Any port state", ""),
            ("open", "open"),
            ("closed", "closed"),
            ("filtered", "filtered"),
            ("open|filtered", "open|filtered"),
            ("unfiltered", "unfiltered"),
            ("closed|filtered", "closed|filtered"),
        ])
        self.hide_down = QCheckBox("Hide hosts that are down")
        self.hide_down.setChecked(True)
        filters.addWidget(self.filter_text, 1)
        filters.addWidget(self.filter_field)
        filters.addWidget(self.filter_state)
        filters.addWidget(self.hide_down)
        layout.addLayout(filters)
        self.filter_status = label("", role="small")
        layout.addWidget(self.filter_status)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        self.tree_model = ResultTreeModel(palette_lookup=lambda: self.context.theme.palette)
        self.proxy = ResultFilterProxy()
        self.proxy.setSourceModel(self.tree_model)
        self.tree = QTreeView()
        self.tree.setModel(self.proxy)
        self.tree.setAlternatingRowColors(True)
        self.tree.setSortingEnabled(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tree.setAccessibleName("Hosts and ports")
        header = self.tree.header()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.tree.selectionModel().currentRowChanged.connect(self._on_tree_selection)
        splitter.addWidget(self.tree)
        self.details = QTextBrowser()
        self.details.setOpenExternalLinks(False)
        self.details.setAccessibleName("Selected item details")
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([640, 420])
        layout.addWidget(splitter, 1)
        self.tabs.addTab(tab, "Hosts")

        # Typing is debounced so large results do not refilter on every keystroke.
        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(200)
        self._filter_timer.timeout.connect(self._apply_filter)
        self.filter_text.textChanged.connect(self._filter_timer.start)
        for signal in (self.filter_field.currentIndexChanged, self.filter_state.currentIndexChanged, self.hide_down.toggled):
            signal.connect(self._apply_filter)

    def _build_ports_tab(self) -> None:
        self.port_model = PortTableModel()
        self.port_proxy = QSortFilterProxyModel()
        self.port_proxy.setSourceModel(self.port_model)
        self.port_proxy.setSortRole(ROLE_SORT)
        self.port_proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.port_proxy.setFilterKeyColumn(-1)
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        self.port_filter = TextField("Filter any column")
        self.port_filter.textChanged.connect(self.port_proxy.setFilterFixedString)
        layout.addWidget(self.port_filter)
        self.port_table = QTableView()
        self.port_table.setModel(self.port_proxy)
        self.port_table.setSortingEnabled(True)
        self.port_table.setAlternatingRowColors(True)
        self.port_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.port_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.port_table.verticalHeader().setVisible(False)
        self.port_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.port_table, 1)
        self.tabs.addTab(tab, "Ports")

    def _build_info_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        card = Card("Scan metadata")
        self.info = KeyValueGrid()
        card.add_widget(self.info)
        layout.addWidget(card)
        self.scripts_view = QTextBrowser()
        layout.addWidget(label("Pre and post scan script output", role="section"))
        layout.addWidget(self.scripts_view, 1)
        self.tabs.addTab(tab, "Scan info")

    def _set_actions_enabled(self, loaded: bool) -> None:
        self.export_button.setEnabled(loaded)
        self.report_action.setEnabled(loaded and self.record is not None)
        self.rerun_button.setEnabled(loaded and self.record is not None)

    def show_run(self, run_id: str) -> None:
        try:
            record = self.context.run_store.load(run_id)
        except GenmapError as exc:
            show_exception(self, exc, "Scan could not be opened")
            return
        xml_path = self.context.run_store.xml_path(run_id)
        self._begin_load(xml_path, record)

    def import_xml_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import Nmap XML", str(Path.home()), "Nmap XML (*.xml);;All files (*)")
        if path:
            self.import_xml(Path(path))

    def import_xml(self, path: Path) -> None:
        self._begin_load(path, None)

    def _begin_load(self, xml_path: Path, record: Optional[RunRecord]) -> None:
        self._load_token += 1
        token = self._load_token
        self.banner.hide()
        self.stack.setCurrentWidget(self.empty)
        self.empty_label.setText(f"Loading {xml_path.name}...")
        self.header.title_label.setText("Results")
        self.header.set_subtitle(record.target_summary if record else str(xml_path))

        if not xml_path.is_file():
            self.record = record
            self.result = None
            self.source_xml = None
            message = "This scan did not produce an XML result file."
            if record and record.error_message:
                message += f" {record.error_message}"
            self.empty_label.setText(message)
            self._set_actions_enabled(False)
            self.rerun_button.setEnabled(record is not None)
            return

        def on_success(result: ScanResult) -> None:
            if token == self._load_token:
                self._display(result, record, xml_path)

        def on_error(exc: BaseException) -> None:
            if token != self._load_token:
                return
            self.empty_label.setText("The results could not be loaded.")
            self.record = record
            self.rerun_button.setEnabled(record is not None)
            show_exception(self, exc, "Results could not be loaded")

        run_in_background(lambda: parse_nmap_xml_file(xml_path), on_success, on_error)

    def _display(self, result: ScanResult, record: Optional[RunRecord], xml_path: Path) -> None:
        self.result = result
        self.record = record
        self.source_xml = xml_path
        title = record.target_summary if record else xml_path.name
        self.header.title_label.setText(f"Results: {title}")
        when = result.started_at.strftime("%Y-%m-%d %H:%M") if result.started_at else "unknown time"
        self.header.set_subtitle(f"Nmap {result.nmap_version or '?'}  •  {when}" + (f"  •  {record.status.label}" if record else "  •  imported file"))
        self.metric_hosts.set_value(f"{len(result.hosts_up)} / {len(result.hosts) or result.statistics.hosts_total}")
        self.metric_open.set_value(str(result.total_open_ports))
        identified = result.identified_services
        guessed = result.distinct_services - identified
        self.metric_services.set_value(str(len(identified)))
        self.metric_services.setToolTip(
            "Services Nmap confirmed with version detection."
            + (f" {len(guessed)} more name(s) only come from Nmap's port table: {', '.join(sorted(guessed))}." if guessed else "")
        )
        elapsed = result.statistics.elapsed_seconds
        if elapsed is None and record and record.duration_seconds is not None:
            elapsed = record.duration_seconds
        self.metric_elapsed.set_value(format_duration(elapsed) if elapsed is not None else "n/a")

        notes: list[str] = []
        if result.truncated:
            notes.append("Nmap did not finish writing this file. Only hosts completed before it stopped are shown.")
        if result.statistics.exit_status == "error":
            notes.append(f"Nmap reported an error: {result.statistics.error_message or 'no message'}")
        if record and record.error_message:
            notes.append(record.error_message)
        if notes:
            self.banner.show_message("Partial or incomplete results", " ".join(notes), "warning")
        else:
            self.banner.hide()

        self._reload_model()
        self.port_model.load(result)
        self.port_table.resizeColumnsToContents()
        self._fill_info(result, record)
        stdout = self.context.run_store.read_text(record.run_id, "stdout.log") if record else ""
        stderr = self.context.run_store.read_text(record.run_id, "stderr.log") if record else ""
        combined = stdout + (("\n--- stderr ---\n" + stderr) if stderr.strip() else "")
        self.output_view.setPlainText(combined or "Console output was not captured for this result.")
        try:
            size = xml_path.stat().st_size
            if size <= 3_000_000:
                self.xml_view.setPlainText(xml_path.read_text(encoding="utf-8", errors="replace"))
            else:
                self.xml_view.setPlainText(f"The XML file is {size / 1_000_000:.1f} MB; open it from {xml_path} or export it.")
        except OSError as exc:
            self.xml_view.setPlainText(f"Could not read {xml_path}: {exc}")
        self.stack.setCurrentWidget(self.content)
        self._set_actions_enabled(True)

    def _reload_model(self) -> None:
        if self.result is None:
            return
        self.tree_model.load(self.result)
        self.tree.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self._apply_filter()
        for column in range(4):
            self.tree.resizeColumnToContents(column)
        if self.proxy.rowCount() <= 20 and self._visible_port_rows() <= 2000:
            self.tree.expandAll()
        first = self.proxy.index(0, 0)
        if first.isValid():
            self.tree.setCurrentIndex(first)
        else:
            self.details.setHtml("")

    def _apply_filter(self) -> None:
        self._filter_timer.stop()
        self.proxy.set_filter(
            self.filter_text.text(),
            str(self.filter_field.current_value()),
            str(self.filter_state.current_value()),
            self.hide_down.isChecked(),
        )
        if self.proxy.is_filtering() and self._visible_port_rows() <= 2000:
            self.tree.expandAll()
        shown = self.proxy.rowCount()
        total = self.tree_model.rowCount()
        hidden = total - shown
        self.filter_status.setText(f"Showing {shown} of {total} hosts" + (f" ({hidden} hidden by filters)" if hidden else "") + ".")

    def _visible_port_rows(self) -> int:
        return sum(self.proxy.rowCount(self.proxy.index(row, 0)) for row in range(self.proxy.rowCount()))

    def _on_tree_selection(self, current: QModelIndex, _previous: QModelIndex) -> None:
        if self.result is None or not current.isValid():
            self.details.setHtml("")
            return
        source = self.proxy.mapToSource(current)
        first = source.siblingAtColumn(0)
        kind = first.data(ROLE_KIND)
        host_index = first.data(ROLE_HOST_INDEX)
        if host_index is None or host_index >= len(self.result.hosts):
            return
        host = self.result.hosts[host_index]
        palette = self.context.theme.palette
        if kind == "port":
            port = host.ports[first.data(ROLE_PORT_INDEX)]
            self.details.setHtml(port_html(host, port, palette))
        else:
            self.details.setHtml(host_html(host, palette))

    def _fill_info(self, result: ScanResult, record: Optional[RunRecord]) -> None:
        self.info.clear()
        self.info.add_row("Scanner", f"{result.scanner} {result.nmap_version or ''}".strip())
        self.info.add_row("Command", result.command_line or (record.command.display if record and record.command else ""), mono=True)
        self.info.add_row("Started", result.started_at.strftime("%Y-%m-%d %H:%M:%S %Z") if result.started_at else "")
        stats = result.statistics
        self.info.add_row("Finished", stats.finished_at.strftime("%Y-%m-%d %H:%M:%S %Z") if stats.finished_at else "Not recorded")
        self.info.add_row("Nmap summary", stats.summary or "")
        self.info.add_row("Hosts", f"{stats.hosts_up} up, {stats.hosts_down} down, {stats.hosts_total} total")
        for info in result.scan_infos:
            self.info.add_row(f"{info.protocol.upper()} {info.scan_type}", f"{info.number_of_services} ports" if info.number_of_services is not None else "")
        if record is not None:
            self.info.add_row("Genmap run", record.run_id, mono=True)
            self.info.add_row("Status", record.status.label + (f" (exit code {record.exit_code})" if record.exit_code is not None else ""))
            if record.profile_name:
                self.info.add_row("Starting point", record.profile_name)
            self.info.add_row("Stored in", str(self.context.run_store.run_directory(record.run_id)), mono=True)
        if self.source_xml is not None and record is None:
            self.info.add_row("Imported from", str(self.source_xml), mono=True)
        warnings = list(result.warnings)
        if record:
            warnings += [w for w in record.warnings if w not in warnings]
        if warnings:
            self.info.add_row("Warnings", "\n".join(warnings[:30]))
        from genmap.ui.pages.results.details import _css, _scripts

        blocks = []
        if result.pre_scripts:
            blocks.append("<h3>Pre-scan scripts</h3>" + _scripts(result.pre_scripts))
        if result.post_scripts:
            blocks.append("<h3>Post-scan scripts</h3>" + _scripts(result.post_scripts))
        self.scripts_view.setHtml(_css(self.context.theme.palette) + ("".join(blocks) or "<p class='muted'>No pre or post scan scripts ran.</p>"))

    def _export(self, kind: str) -> None:
        if self.result is None:
            return
        base = self.record.run_id if self.record else (self.source_xml.stem if self.source_xml else "genmap-results")
        filters = {"xml": "Nmap XML (*.xml)", "json": "JSON (*.json)", "csv": "CSV (*.csv)"}
        from genmap.ui.pages.reports import default_report_directory

        directory = str(default_report_directory(self.context.settings.reports.default_output_directory))
        path, _ = QFileDialog.getSaveFileName(self, "Export results", str(Path(directory) / f"{base}.{kind}"), filters[kind])
        if not path:
            return
        target = Path(path)
        try:
            if kind == "xml":
                if self.source_xml is None:
                    raise GenmapError("The original XML file is not available.")
                if self.source_xml.resolve() != target.resolve():
                    shutil.copyfile(self.source_xml, target)
            elif kind == "json":
                target.write_text(self.result.model_dump_json(indent=2), encoding="utf-8")
            else:
                target.write_text(result_to_csv(self.result), encoding="utf-8", newline="")
        except (OSError, GenmapError) as exc:
            show_exception(self, exc, "Export failed")
            return
        QMessageBox.information(self, "Export complete", f"Saved to {target}")

    def _rerun(self) -> None:
        if self.record is None:
            return
        try:
            config = self.record.scan_configuration()
        except Exception as exc:
            show_exception(self, exc, "Configuration could not be loaded")
            return
        self.rerun_requested.emit(config)
