"""Compare page: differences between two stored scans."""

from __future__ import annotations

import difflib
import html
import re
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QColor, QDesktopServices
from PyQt6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from genmap.core.comparison import Change, ChangeKind, ComparisonResult, compare_scans, side_from, summarize
from genmap.engine.run_store import RunStatus
from genmap.errors import GenmapError
from genmap.reporting.comparison import SUMMARY_LABELS, export_comparison
from genmap.storage.models import Scan
from genmap.ui.app_context import AppContext
from genmap.ui.pages.base import BasePage
from genmap.ui.pages.history import status_label
from genmap.ui.pages.reports import default_report_directory
from genmap.ui.tasks import run_in_background
from genmap.ui.widgets.common import Banner, Metric, PageHeader, label
from genmap.ui.widgets.error_dialog import show_exception
from genmap.ui.widgets.inputs import EnumCombo
from genmap.ui.widgets.responsive import FlowLayout, ResponsiveGrid

ROLE_CHANGE = Qt.ItemDataRole.UserRole + 1
ROLE_HOST = Qt.ItemDataRole.UserRole + 2

FILTERS: dict[str, frozenset[ChangeKind]] = {
    "hosts": frozenset({ChangeKind.HOST_NEW, ChangeKind.HOST_MISSING, ChangeKind.HOST_STATE, ChangeKind.HOST_OUT_OF_SCOPE,
                        ChangeKind.MAC_CHANGED, ChangeKind.HOSTNAME_CHANGED}),
    "ports": frozenset({ChangeKind.PORT_OPENED, ChangeKind.PORT_NO_LONGER_OPEN, ChangeKind.PORT_STATE, ChangeKind.PORT_NOT_COVERED}),
    "services": frozenset({ChangeKind.SERVICE_CHANGED, ChangeKind.VERSION_CHANGED, ChangeKind.SERVICE_UNCONFIRMED}),
    "os": frozenset({ChangeKind.OS_CHANGED}),
    "scripts": frozenset({ChangeKind.SCRIPT_ADDED, ChangeKind.SCRIPT_REMOVED, ChangeKind.SCRIPT_CHANGED}),
}

HOST_STATUS_TEXT = {
    "new": "New",
    "missing": "Not seen in the newer scan",
    "changed": "Changed",
    "unchanged": "No changes",
    "out_of_scope": "Outside the other scan's targets",
}

_COMPARABLE = {
    RunStatus.COMPLETED.value,
    RunStatus.COMPLETED_WITH_WARNINGS.value,
    RunStatus.CANCELLED.value,
    RunStatus.TIMED_OUT.value,
    RunStatus.INTERRUPTED.value,
    RunStatus.FAILED.value,
    RunStatus.CRASHED.value,
}


_PLAIN_SUBJECTS = {"host", "MAC", "OS", "hostname"}


def first_line(text: Optional[str]) -> str:
    """The first non blank line, for the one line summary columns."""
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()
    return ""


def scan_label(scan: Scan) -> str:
    return f"{scan.created_at.astimezone().strftime('%Y-%m-%d %H:%M')}  {scan.target_summary}"


def comparison_file_name(baseline_id: str, newer_id: str, extension: str) -> str:
    safe = lambda text: re.sub(r"[^A-Za-z0-9._-]+", "_", text)  # noqa: E731
    return f"genmap-compare-{safe(baseline_id)}-vs-{safe(newer_id)}{extension}"


class ComparePage(BasePage):
    page_key = "compare"
    page_title = "Compare Scans"

    def __init__(self, context: AppContext, parent: Optional[QWidget] = None) -> None:
        super().__init__(context, parent)
        self._scans: dict[str, Scan] = {}
        self._result: Optional[ComparisonResult] = None
        self._pair: Optional[tuple[str, str]] = None
        self._request = 0
        self._busy = False

        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 22, 28, 18)
        outer.setSpacing(12)
        outer.addWidget(PageHeader(
            "Compare Scans",
            "See what changed between two scans. Every change shows what Nmap reported in each scan; "
            "the italic reading underneath is Genmap's interpretation, not something Nmap reported.",
        ))

        picker = FlowLayout()
        self.baseline = EnumCombo([])
        self.baseline.setAccessibleName("Baseline scan")
        picker.addWidget(self._labelled("Baseline", self.baseline))
        self.swap_button = QPushButton("Swap")
        self.swap_button.setToolTip("Exchange the baseline and newer scans")
        picker.addWidget(self.swap_button)
        self.newer = EnumCombo([])
        self.newer.setAccessibleName("Newer scan")
        picker.addWidget(self._labelled("Newer", self.newer))
        self.compare_button = QPushButton("Compare")
        self.compare_button.setProperty("accent", True)
        picker.addWidget(self.compare_button)
        outer.addLayout(picker)

        self.order_note = label("", role="small", status="warning", wrap=True)
        self.order_note.hide()
        outer.addWidget(self.order_note)

        self.metrics: dict[str, Metric] = {}
        self.summary = ResponsiveGrid({0: 2, 560: 4, 1050: 7}, spacing=10)
        for key, caption in SUMMARY_LABELS:
            metric = Metric(caption, "-")
            metric.caption_label.setWordWrap(True)
            self.metrics[key] = metric
            self.summary.add(metric)
        outer.addWidget(self.summary)

        self.notes = Banner("info")
        outer.addWidget(self.notes)

        filters = FlowLayout()
        self.filter = EnumCombo([
            ("All changes", ""),
            ("Hosts", "hosts"),
            ("Ports", "ports"),
            ("Services and versions", "services"),
            ("OS guesses", "os"),
            ("Script output", "scripts"),
        ])
        self.filter.setAccessibleName("Change filter")
        filters.addWidget(self.filter)
        self.show_unchanged = QCheckBox("Show hosts without changes")
        self.show_informational = QCheckBox("Show items that could not be compared")
        self.show_informational.setToolTip(
            "Hosts outside the other scan's targets, ports only one scan probed, and services only one scan identified by probing"
        )
        filters.addWidget(self.show_unchanged)
        filters.addWidget(self.show_informational)
        self.export_html_button = QPushButton("Export HTML...")
        self.export_json_button = QPushButton("Export JSON...")
        filters.addWidget(self.export_html_button)
        filters.addWidget(self.export_json_button)
        outer.addLayout(filters)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(3)
        self.tree.setHeaderLabels(["Host and change", "Baseline (Nmap)", "Newer (Nmap)"])
        self.tree.setAlternatingRowColors(True)
        self.tree.setUniformRowHeights(True)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.tree.header().setStretchLastSection(True)
        self.tree.setAccessibleName("Changes by host")
        splitter.addWidget(self.tree)
        detail = QWidget()
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        self.details = QTextBrowser()
        self.details.setOpenLinks(False)
        self.details.setAccessibleName("Change details")
        detail_layout.addWidget(self.details, 1)
        splitter.addWidget(detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([640, 420])
        outer.addWidget(splitter, 1)

        status_row = QHBoxLayout()
        self.status = label("", role="small", wrap=True, selectable=True)
        status_row.addWidget(self.status, 1)
        outer.addLayout(status_row)

        self.swap_button.clicked.connect(self.swap)
        self.compare_button.clicked.connect(self.run_comparison)
        self.baseline.currentIndexChanged.connect(lambda *_: self._update_controls())
        self.newer.currentIndexChanged.connect(lambda *_: self._update_controls())
        self.filter.currentIndexChanged.connect(lambda *_: self._populate())
        self.show_unchanged.toggled.connect(lambda *_: self._populate())
        self.show_informational.toggled.connect(lambda *_: self._populate())
        self.tree.currentItemChanged.connect(lambda current, _previous: self._show_details(current))
        self.export_html_button.clicked.connect(lambda: self.export("html"))
        self.export_json_button.clicked.connect(lambda: self.export("json"))
        self.status.linkActivated.connect(lambda link: QDesktopServices.openUrl(QUrl(link)))
        context.index_changed.connect(self._reload_if_visible)
        self._show_empty_result()

    @staticmethod
    def _labelled(caption: str, combo: EnumCombo) -> QWidget:
        # Keeps each caption on the same row as its combo when the picker wraps.
        box = QWidget()
        row = QHBoxLayout(box)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        row.addWidget(label(caption, role="muted"))
        combo.setMinimumWidth(260)
        row.addWidget(combo)
        return box

    # Scan selection ---------------------------------------------------------

    def on_shown(self) -> None:
        self.reload_scans()

    def _reload_if_visible(self) -> None:
        if self.isVisible():
            self.reload_scans()

    def reload_scans(self) -> None:
        baseline, newer = self.baseline.current_value(), self.newer.current_value()
        try:
            scans = [s for s in self.context.scan_index.list_scans(include_missing=False) if s.status in _COMPARABLE]
        except Exception as exc:
            scans = []
            self.status.setText(f"Scans could not be listed: {exc}")
        self._scans = {s.run_id: s for s in scans}
        for combo in (self.baseline, self.newer):
            combo.blockSignals(True)
            combo.clear()
            for scan in scans:
                text = scan_label(scan)
                if scan.status != RunStatus.COMPLETED.value:
                    text += f"  ({status_label(scan.status)})"
                combo.addItem(text, scan.run_id)
            combo.blockSignals(False)
        # list_scans returns newest first, so the default pair is the two most recent scans.
        if baseline in self._scans and newer in self._scans:
            self.baseline.set_current_value(baseline)
            self.newer.set_current_value(newer)
        elif len(scans) >= 2:
            self.baseline.setCurrentIndex(1)
            self.newer.setCurrentIndex(0)
        self._update_controls()

    def select_pair(self, baseline_id: str, newer_id: str, *, run: bool = True) -> None:
        self.reload_scans()
        self.baseline.set_current_value(baseline_id)
        self.newer.set_current_value(newer_id)
        self._update_controls()
        if run and self.compare_button.isEnabled():
            self.run_comparison()

    def swap(self) -> None:
        baseline, newer = self.baseline.current_value(), self.newer.current_value()
        self.baseline.set_current_value(newer)
        self.newer.set_current_value(baseline)
        self._update_controls()

    def _update_controls(self) -> None:
        baseline, newer = self.baseline.current_value(), self.newer.current_value()
        ready = bool(baseline and newer and baseline != newer)
        self.compare_button.setEnabled(ready and not self._busy)
        self.swap_button.setEnabled(bool(baseline and newer))
        has_result = self._result is not None and not self._busy
        self.export_html_button.setEnabled(has_result)
        self.export_json_button.setEnabled(has_result)
        a, b = self._scans.get(str(baseline or "")), self._scans.get(str(newer or ""))
        if len(self._scans) < 2:
            self.order_note.setText("Comparing needs at least two stored scans with their files still on disk.")
            self.order_note.show()
        elif baseline and baseline == newer:
            self.order_note.setText("Pick two different scans.")
            self.order_note.show()
        elif a is not None and b is not None and a.created_at > b.created_at:
            self.order_note.setText("The baseline ran after the newer scan. Changes will read backwards in time; use Swap if that is not intended.")
            self.order_note.show()
        else:
            self.order_note.hide()

    # Comparison -------------------------------------------------------------

    def run_comparison(self) -> None:
        baseline_id, newer_id = str(self.baseline.current_value() or ""), str(self.newer.current_value() or "")
        if not baseline_id or not newer_id or baseline_id == newer_id or self._busy:
            return
        store = self.context.run_store
        self._request += 1
        request = self._request

        def load_side(run_id: str):
            record = store.load(run_id)
            result = store.load_result(run_id)
            if result is None:
                raise GenmapError(
                    f"The scan of {record.target_summary} started {record.created_at.astimezone():%Y-%m-%d %H:%M} has no Nmap XML to compare.",
                    remedy=record.error_message or "Pick a scan that finished with results.",
                )
            label_text = f"{record.created_at.astimezone():%Y-%m-%d %H:%M} {record.target_summary}"
            return side_from(result, label_text, record.configuration)

        def work() -> ComparisonResult:
            return compare_scans(load_side(baseline_id), load_side(newer_id))

        def done(result: ComparisonResult) -> None:
            if request != self._request:
                return
            self._set_busy(False)
            self._result = result
            self._pair = (baseline_id, newer_id)
            self._show_result()

        def failed(exc: BaseException) -> None:
            if request != self._request:
                return
            self._set_busy(False)
            self.status.setText("")
            show_exception(self, exc, "Comparison failed")

        self._set_busy(True)
        self.status.setText("Comparing...")
        run_in_background(work, done, failed)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self._update_controls()

    def _show_empty_result(self) -> None:
        for metric in self.metrics.values():
            metric.set_value("-")
        self.notes.hide()
        self.tree.clear()
        self.details.setHtml("")

    def _show_result(self) -> None:
        result = self._result
        if result is None:
            self._show_empty_result()
            return
        summary = summarize(result)
        for key, metric in self.metrics.items():
            metric.set_value(str(summary[key]))
        if result.notes:
            self.notes.show_message("What was compared", "\n".join(f"• {note}" for note in result.notes), "info")
        else:
            self.notes.hide()
        self._populate()
        significant = len(result.changes())
        compared = summary["changed_hosts"] + summary["unchanged_hosts"] + summary["new_hosts"] + summary["missing_hosts"]
        text = f"{significant} change{'s' if significant != 1 else ''} across {compared} host{'s' if compared != 1 else ''} compared."
        if summary["out_of_scope_hosts"]:
            text += f" {summary['out_of_scope_hosts']} host{'s were' if summary['out_of_scope_hosts'] != 1 else ' was'} outside the other scan's targets."
        self.status.setText(text)

    def _visible_changes(self, changes: list[Change]) -> list[Change]:
        wanted = FILTERS.get(str(self.filter.current_value() or ""))
        informational = self.show_informational.isChecked()
        return [c for c in changes if (wanted is None or c.kind in wanted) and (informational or c.significant)]

    def _populate(self) -> None:
        self.tree.clear()
        self.details.setHtml("")
        result = self._result
        if result is None:
            return
        palette = self.context.theme.palette
        muted = QColor(palette.text_muted)
        filtered = bool(self.filter.current_value())
        first: Optional[QTreeWidgetItem] = None
        for host in result.hosts:
            if host.status == "out_of_scope" and not self.show_informational.isChecked():
                continue
            changes = self._visible_changes(host.changes)
            if not changes and not (self.show_unchanged.isChecked() and host.status == "unchanged" and not filtered):
                continue
            top = QTreeWidgetItem([host.name, "", HOST_STATUS_TEXT.get(host.status, host.status)])
            top.setData(0, ROLE_HOST, host.address)
            if host.status in ("unchanged", "out_of_scope"):
                for column in range(3):
                    top.setForeground(column, muted)
            self.tree.addTopLevelItem(top)
            for change in changes:
                caption = change.label if change.subject in _PLAIN_SUBJECTS else f"{change.label}: {change.subject}"
                child = QTreeWidgetItem([caption, first_line(change.before), first_line(change.after)])
                child.setData(0, ROLE_CHANGE, change)
                child.setToolTip(0, change.reading)
                child.setToolTip(1, (change.before or "")[:600])
                child.setToolTip(2, (change.after or "")[:600])
                if not change.significant:
                    for column in range(3):
                        child.setForeground(column, muted)
                top.addChild(child)
                if first is None:
                    first = child
            top.setExpanded(True)
        self._size_columns()
        if self.tree.topLevelItemCount() == 0:
            self.details.setHtml(self._empty_html())
        elif first is not None:
            self.tree.setCurrentItem(first)

    def _size_columns(self) -> None:
        available = max(self.tree.viewport().width(), 480)
        self.tree.resizeColumnToContents(0)
        first = min(self.tree.columnWidth(0), int(available * 0.45))
        self.tree.setColumnWidth(0, first)
        self.tree.setColumnWidth(1, max(120, (available - first) // 2))

    def _empty_html(self) -> str:
        result = self._result
        if result is None:
            return ""
        if self.filter.current_value():
            return "<p>No changes of this kind.</p>"
        if result.has_changes:
            return "<p>Nothing matches the current filter.</p>"
        return "<p>Nmap reported the same hosts, ports, services, and script output in both scans, as far as they could be compared.</p>"

    def _show_details(self, item: Optional[QTreeWidgetItem]) -> None:
        if item is None:
            self.details.setHtml("")
            return
        change = item.data(0, ROLE_CHANGE)
        if isinstance(change, Change):
            self.details.setHtml(self.change_html(change))
            return
        address = item.data(0, ROLE_HOST)
        host = next((h for h in (self._result.hosts if self._result else []) if h.address == address), None)
        if host is None:
            self.details.setHtml("")
            return
        e = html.escape
        count = len(host.significant_changes)
        self.details.setHtml(
            self._style()
            + f"<h3>{e(host.name)}</h3><p>{e(host.address)}</p>"
            + f"<p>{e(HOST_STATUS_TEXT.get(host.status, host.status))}. {count} change{'s' if count != 1 else ''}.</p>"
        )

    def _style(self) -> str:
        palette = self.context.theme.palette
        return f"""<style>
            h3 {{ margin: 0 0 6px 0; }} h4 {{ margin: 12px 0 4px 0; }}
            .muted {{ color: {palette.text_muted}; }}
            .reading {{ color: {palette.text_muted}; font-style: italic; }}
            .add {{ color: {palette.success}; }} .del {{ color: {palette.danger}; }}
            pre {{ background: {palette.surface_alt}; padding: 8px; white-space: pre-wrap; font-family: Consolas, 'Cascadia Mono', Menlo, monospace; }}
        </style>"""

    def change_html(self, change: Change) -> str:
        e = html.escape
        where = change.address if change.subject in _PLAIN_SUBJECTS else f"{change.subject} on {change.address}"
        parts = [self._style(), f"<h3>{e(change.label)}</h3><p>{e(where)}</p>"]
        parts.append("<h4>What Nmap reported</h4>")
        parts.append(f"<p class='muted'>Baseline: {e(self._result.baseline_label) if self._result else ''}</p>")
        parts.append(f"<pre>{e(change.before) if change.before else '(nothing)'}</pre>")
        parts.append(f"<p class='muted'>Newer: {e(self._result.current_label) if self._result else ''}</p>")
        parts.append(f"<pre>{e(change.after) if change.after else '(nothing)'}</pre>")
        if change.kind == ChangeKind.SCRIPT_CHANGED and change.before and change.after:
            diff = list(difflib.unified_diff(change.before.splitlines(), change.after.splitlines(), "baseline", "newer", lineterm="", n=1))
            if diff:
                rendered = []
                for line in diff[2:]:
                    css = "add" if line.startswith("+") else "del" if line.startswith("-") else "muted" if line.startswith("@@") else ""
                    rendered.append(f"<span class='{css}'>{e(line)}</span>" if css else e(line))
                parts.append("<h4>Line by line</h4><pre>" + "\n".join(rendered) + "</pre>")
        parts.append("<h4>Genmap's reading</h4>")
        parts.append(f"<p class='reading'>{e(change.reading)}</p>")
        if not change.significant:
            parts.append("<p class='muted'>This item is shown for context only and is not counted as a change.</p>")
        return "".join(parts)

    # Export -----------------------------------------------------------------

    def export(self, fmt: str) -> None:
        if self._result is None or self._pair is None:
            return
        extension = ".html" if fmt == "html" else ".json"
        folder = default_report_directory(self.context.settings.reports.default_output_directory)
        suggested = folder / comparison_file_name(self._pair[0], self._pair[1], extension)
        caption = "HTML page (*.html)" if fmt == "html" else "JSON data (*.json)"
        path, _ = QFileDialog.getSaveFileName(self, "Export comparison", str(suggested), caption)
        if not path:
            return
        target = Path(path)
        if target.suffix.lower() != extension:
            target = target.with_suffix(extension)
        self.export_to(fmt, target)

    def export_to(self, fmt: str, path: Path) -> Optional[Path]:
        if self._result is None:
            return None
        try:
            written = export_comparison(self._result, fmt, path, include_unchanged=self.show_unchanged.isChecked())
        except GenmapError as exc:
            show_exception(self, exc, "Export failed")
            return None
        url = QUrl.fromLocalFile(str(written)).toString()
        self.status.setText(f"Saved <a href='{html.escape(url)}'>{html.escape(str(written))}</a>")
        return written
