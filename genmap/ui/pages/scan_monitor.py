"""Live view of a running scan."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QListWidget,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from genmap.engine.run_store import RunRecord, RunStatus
from genmap.engine.scan_engine import ScanJob
from genmap.nmap.output_monitor import LiveScanState, TaskProgress
from genmap.ui.app_context import AppContext
from genmap.ui.pages.base import BasePage
from genmap.ui.widgets.common import Card, KeyValueGrid, Metric, PageHeader, label, set_status
from genmap.ui.widgets.console_view import ConsoleView

_STATUS_STYLE = {
    RunStatus.RUNNING: "info",
    RunStatus.COMPLETED: "ok",
    RunStatus.COMPLETED_WITH_WARNINGS: "warning",
    RunStatus.FAILED: "error",
    RunStatus.CRASHED: "error",
    RunStatus.TIMED_OUT: "warning",
    RunStatus.CANCELLED: "warning",
    RunStatus.INTERRUPTED: "warning",
}


def format_duration(seconds: float) -> str:
    seconds = int(max(seconds, 0))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes}:{secs:02d}"


class ScanMonitorPage(BasePage):
    page_key = "scan_monitor"
    page_title = "Live Scan"

    view_results_requested = pyqtSignal(str)  # run id
    new_scan_requested = pyqtSignal()

    def __init__(self, context: AppContext, parent: Optional[QWidget] = None) -> None:
        super().__init__(context, parent)
        self.job: Optional[ScanJob] = None
        self._pending: list[tuple[str, bool]] = []

        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 22, 28, 18)
        outer.setSpacing(12)

        header_row = QHBoxLayout()
        self.header = PageHeader("Live Scan", "No scan has been started in this session.")
        header_row.addWidget(self.header, 1)
        self.status_label = label("Idle", role="section")
        header_row.addWidget(self.status_label, 0, Qt.AlignmentFlag.AlignTop)
        outer.addLayout(header_row)

        top = QHBoxLayout()
        top.setSpacing(12)
        info_card = Card("Scan")
        self.info = KeyValueGrid()
        self.info.add_row("Target")
        self.info.add_row("Started")
        self.info.add_row("Elapsed")
        self.info.add_row("Command", mono=True)
        info_card.add_widget(self.info)
        top.addWidget(info_card, 3)

        progress_card = Card("Progress")
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(True)
        self.progress.setAccessibleName("Scan progress")
        progress_card.add_widget(self.progress)
        self.progress_text = label("Waiting for Nmap to start.", role="muted", wrap=True)
        progress_card.add_widget(self.progress_text)
        progress_card.add_stretch()
        top.addWidget(progress_card, 2)
        outer.addLayout(top)

        metrics = QGridLayout()
        metrics.setHorizontalSpacing(12)
        self.metric_hosts = Metric("Hosts reported")
        self.metric_up = Metric("Hosts up")
        self.metric_ports = Metric("Open ports found")
        self.metric_services = Metric("Services identified")
        for column, metric in enumerate((self.metric_hosts, self.metric_up, self.metric_ports, self.metric_services)):
            metrics.addWidget(metric, 0, column)
        outer.addLayout(metrics)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        console_box = QWidget()
        console_layout = QVBoxLayout(console_box)
        console_layout.setContentsMargins(0, 0, 0, 0)
        console_layout.addWidget(label("Nmap output", role="section"))
        self.console = ConsoleView(max_lines=context.settings.scanning.output_buffer_lines)
        self.console.setAccessibleName("Nmap output")
        console_layout.addWidget(self.console, 1)
        splitter.addWidget(console_box)

        side = QWidget()
        side_layout = QVBoxLayout(side)
        side_layout.setContentsMargins(0, 0, 0, 0)
        side_layout.addWidget(label("Warnings and problems", role="section"))
        self.problems = QListWidget()
        self.problems.setWordWrap(True)
        self.problems.setAccessibleName("Warnings and problems")
        side_layout.addWidget(self.problems, 1)
        side_layout.addWidget(label("Open ports", role="section"))
        self.ports = QListWidget()
        self.ports.setAccessibleName("Open ports found so far")
        side_layout.addWidget(self.ports, 1)
        splitter.addWidget(side)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([700, 280])
        outer.addWidget(splitter, 1)

        buttons = QHBoxLayout()
        self.result_message = label("", wrap=True, selectable=True)
        buttons.addWidget(self.result_message, 1)
        self.new_button = QPushButton("New scan")
        self.new_button.clicked.connect(self.new_scan_requested)
        self.cancel_button = QPushButton("Cancel scan")
        self.cancel_button.setProperty("danger", True)
        self.cancel_button.clicked.connect(self._confirm_cancel)
        self.results_button = QPushButton("View results")
        self.results_button.setProperty("accent", True)
        self.results_button.clicked.connect(self._open_results)
        for button in (self.new_button, self.cancel_button, self.results_button):
            buttons.addWidget(button)
        outer.addLayout(buttons)

        self._clock = QTimer(self)
        self._clock.setInterval(1000)
        self._clock.timeout.connect(self._tick)
        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(80)
        self._flush_timer.timeout.connect(self._flush_output)
        self._set_idle()
        context.theme.theme_changed.connect(lambda p: self.console.set_stderr_color(p.console_stderr))
        self.console.set_stderr_color(context.theme.palette.console_stderr)

    def _set_idle(self) -> None:
        self.cancel_button.setEnabled(False)
        self.results_button.setEnabled(False)
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setFormat("")

    def attach(self, job: ScanJob) -> None:
        if self.job is not None:
            for signal, slot in (
                (self.job.output, self._on_output),
                (self.job.live_state_changed, self._on_live_state),
                (self.job.progress_changed, self._on_progress),
                (self.job.finished, self._on_finished),
            ):
                try:
                    signal.disconnect(slot)
                except (TypeError, RuntimeError):
                    pass
        self.job = job
        self._pending.clear()
        self.console.clear()
        self.console.set_max_lines(self.context.settings.scanning.output_buffer_lines)
        self.problems.clear()
        self.ports.clear()
        self.result_message.setText("")
        record = job.record
        self.header.title_label.setText(f"Scanning {record.target_summary}")
        self.header.set_subtitle(f"Run {record.run_id}" + (f"  •  {record.profile_name}" if record.profile_name else ""))
        self.info.set_value("Target", record.target_summary)
        started = record.started_at or datetime.now().astimezone()
        self.info.set_value("Started", started.strftime("%Y-%m-%d %H:%M:%S"))
        self.info.set_value("Elapsed", "0:00")
        self.info.set_value("Command", job.plan.display())
        for metric in (self.metric_hosts, self.metric_up, self.metric_ports, self.metric_services):
            metric.set_value("0")
        config = record.scan_configuration()
        if config.service_detection.enabled or config.aggressive:
            self.metric_services.caption_label.setText("Services identified")
            self.metric_services.setToolTip("Service names confirmed by Nmap's version detection.")
        else:
            self.metric_services.caption_label.setText("Service names (port table)")
            self.metric_services.setToolTip(
                "Version detection is off, so these names come from Nmap's port table and are not confirmed."
            )
        self.progress.setRange(0, 0)
        self.progress.setFormat("")
        self.progress_text.setText("Nmap has not reported progress yet. Progress appears when Nmap prints timing estimates.")
        self._set_status(RunStatus.RUNNING)
        self.cancel_button.setEnabled(True)
        self.results_button.setEnabled(False)
        job.output.connect(self._on_output)
        job.live_state_changed.connect(self._on_live_state)
        job.progress_changed.connect(self._on_progress)
        job.finished.connect(self._on_finished)
        self._clock.start()
        self._flush_timer.start()
        if not job.is_running and job.record.status.is_terminal:
            self._on_finished(job.record)

    def _set_status(self, status: RunStatus) -> None:
        self.status_label.setText(status.label)
        set_status(self.status_label, _STATUS_STYLE.get(status))

    def _tick(self) -> None:
        if self.job is not None:
            self.info.set_value("Elapsed", format_duration(self.job.elapsed_seconds))

    def _on_output(self, line: str, is_stderr: bool) -> None:
        self._pending.append((line, is_stderr))

    def _flush_output(self) -> None:
        if not self._pending:
            return
        batch, self._pending = self._pending, []
        run: list[str] = []
        run_stderr = batch[0][1]
        for text, is_stderr in batch:
            if is_stderr != run_stderr:
                self.console.append_line("\n".join(run), run_stderr)
                run, run_stderr = [], is_stderr
            run.append(text)
        if run:
            self.console.append_line("\n".join(run), run_stderr)

    def _on_live_state(self, state: LiveScanState) -> None:
        self.metric_hosts.set_value(str(len(state.hosts_reported)))
        self.metric_up.set_value(str(state.hosts_up))
        self.metric_ports.set_value(str(state.open_port_count))
        self.metric_services.set_value(str(len(state.services)))
        known_ports = self.ports.count()
        open_ports = [p for p in state.ports if p.state == "open"]
        for port in open_ports[known_ports:]:
            self.ports.addItem(f"{port.host}  {port.port}/{port.protocol}")
        known_problems = self.problems.count()
        messages = [f"{p.message} {p.remedy}" for p in state.problems]
        seen_messages = {self.problems.item(i).text() for i in range(known_problems)}
        for message in messages:
            if message not in seen_messages:
                self.problems.addItem(message)
                seen_messages.add(message)
        for warning in state.warnings[-20:]:
            if warning not in seen_messages and not any(warning == p.source_line for p in state.problems):
                self.problems.addItem(warning)
                seen_messages.add(warning)
        if state.stats is not None and state.progress is None:
            self.progress_text.setText(
                f"{state.stats.task}: {state.stats.hosts_completed} hosts completed, {state.stats.hosts_undergoing} in progress."
            )

    def _on_progress(self, progress: TaskProgress) -> None:
        self.progress.setRange(0, 1000)
        self.progress.setValue(int(progress.percent * 10))
        self.progress.setFormat(f"{progress.percent:.1f}%")
        detail = f"{progress.task}: {progress.percent:.1f}% done"
        if progress.remaining:
            detail += f", about {progress.remaining} remaining (Nmap's estimate for this phase)"
        self.progress_text.setText(detail + ".")

    def _on_finished(self, record: RunRecord) -> None:
        self.header.title_label.setText(f"Scan of {record.target_summary}")
        self._flush_output()
        self._clock.stop()
        self._flush_timer.stop()
        self._tick()
        self._set_status(record.status)
        self.cancel_button.setEnabled(False)
        has_results = self.context.run_store.xml_path(record.run_id).is_file()
        self.results_button.setEnabled(has_results)
        self.progress.setRange(0, 1)
        self.progress.setValue(1 if record.status in (RunStatus.COMPLETED, RunStatus.COMPLETED_WITH_WARNINGS) else 0)
        self.progress.setFormat("")
        if self.job is not None:
            self._on_live_state(self.job.live_state)
        summary = record.summary
        parts: list[str] = []
        if record.status in (RunStatus.COMPLETED, RunStatus.COMPLETED_WITH_WARNINGS):
            if summary is not None:
                parts.append(f"{summary.hosts_up} of {summary.hosts_total} hosts up, {summary.open_ports} open ports.")
            if record.status == RunStatus.COMPLETED_WITH_WARNINGS:
                if record.error_message:
                    parts.append(record.error_message)
                    if record.error_remedy:
                        parts.append(record.error_remedy)
                elif record.warnings:
                    parts.append(record.warnings[-1])
            self.progress_text.setText(summary.nmap_summary if summary and summary.nmap_summary else "Scan finished.")
        else:
            if record.error_message:
                parts.append(record.error_message)
            if record.error_remedy:
                parts.append(record.error_remedy)
            if record.exit_code not in (None, 0) and record.status == RunStatus.FAILED:
                parts.append(f"Exit code {record.exit_code}.")
            self.progress_text.setText(record.status.label + ".")
            if has_results:
                parts.append("Partial results are available.")
        self.result_message.setText(" ".join(parts))
        set_status(self.result_message, _STATUS_STYLE.get(record.status) if record.status != RunStatus.COMPLETED else None)

    def _confirm_cancel(self) -> None:
        if self.job is None or not self.job.is_running:
            return
        if self.context.settings.general.confirm_scan_cancel:
            answer = QMessageBox.question(
                self,
                "Cancel scan",
                "Stop this scan? Hosts Nmap already finished will still be available as partial results.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.cancel_button.setEnabled(False)
        self.progress_text.setText("Stopping Nmap...")
        self.job.cancel()

    def _open_results(self) -> None:
        if self.job is not None:
            self.view_results_requested.emit(self.job.run_id)
