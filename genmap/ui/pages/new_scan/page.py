"""The New Scan page: configure, inspect, and launch an Nmap scan."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from pydantic import ValidationError
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from genmap.core.intrusiveness import assess_intrusiveness
from genmap.core.scan_config import (
    ScanConfiguration,
    TargetSpecification,
    ValidationIssue,
    has_errors,
    issues_from_validation_error,
    validate_configuration,
)
from genmap.core.targets import split_target_text
from genmap.errors import GenmapError
from genmap.nmap.command_builder import CommandPlan, build_command_plan
from genmap.nmap.environment import NmapEnvironment
from genmap.nmap.locator import EXECUTABLE_NAME
from genmap.ui.app_context import AppContext
from genmap.ui.pages.base import BasePage
from genmap.ui.pages.new_scan.confirm_dialog import ConfirmScanDialog
from genmap.storage.profiles import strip_targets
from genmap.ui.pages.new_scan.option_tabs import ALL_TABS, OptionTab, ScriptsTab, TargetsTab, describe_target_scope
from genmap.ui.widgets.command_inspector import CommandInspectorDialog
from genmap.ui.widgets.common import PageHeader, label, set_status
from genmap.ui.widgets.error_dialog import show_exception
from genmap.ui.widgets.inputs import EnumCombo, TextField
from genmap.ui.widgets.name_dialog import NameDialog

log = logging.getLogger(__name__)

_PREVIEW_XML = Path("<scan folder>") / "result.xml"


class NewScanPage(BasePage):
    page_key = "new_scan"
    page_title = "New Scan"

    scan_started = pyqtSignal(object)  # ScanJob
    save_targets_requested = pyqtSignal(list, list)  # targets, exclusions

    def __init__(self, context: AppContext, parent: Optional[QWidget] = None) -> None:
        super().__init__(context, parent)
        self._config: ScanConfiguration = ScanConfiguration()
        self._current: Optional[ScanConfiguration] = None
        self._issues: list[ValidationIssue] = []
        self._plan: Optional[CommandPlan] = None
        self._loading = False
        self._starting_point = "Nmap defaults"
        self._profile_id: Optional[int] = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 22, 28, 18)
        outer.setSpacing(12)

        header_row = QHBoxLayout()
        header_row.addWidget(PageHeader("New Scan", "Choose targets, adjust options, and review the exact Nmap command before it runs."), 1)
        header_row.addWidget(label("Profile", role="muted"))
        self.profile_combo = EnumCombo([])
        self.profile_combo.setMinimumWidth(200)
        self.profile_combo.setToolTip("Load a saved profile. Your targets are kept.")
        self.profile_combo.activated.connect(self._on_profile_chosen)
        header_row.addWidget(self.profile_combo)
        reset = QPushButton("Reset")
        reset.setToolTip("Reload the selected profile, keeping the targets.")
        reset.clicked.connect(lambda: self._on_profile_chosen(self.profile_combo.currentIndex()))
        header_row.addWidget(reset)
        self.save_profile_button = QPushButton("Save as profile...")
        self.save_profile_button.setToolTip("Save these options as a new profile. Targets are not included.")
        self.save_profile_button.clicked.connect(self.save_as_profile)
        header_row.addWidget(self.save_profile_button)
        self.update_profile_button = QPushButton("Update profile")
        self.update_profile_button.setToolTip("Store the current options in the selected profile.")
        self.update_profile_button.clicked.connect(self.update_profile)
        header_row.addWidget(self.update_profile_button)
        outer.addLayout(header_row)

        target_row = QHBoxLayout()
        target_label = QLabel("&Targets")
        target_label.setProperty("role", "section")
        self.targets = TextField("192.168.1.0/24, scanme.nmap.org, 10.0.0.5-20 ...", mono=True)
        self.targets.setMinimumHeight(34)
        self.targets.setAccessibleName("Targets")
        target_label.setBuddy(self.targets)
        target_row.addWidget(target_label)
        target_row.addWidget(self.targets, 1)
        self.groups_button = QToolButton()
        self.groups_button.setText("Groups")
        self.groups_button.setToolTip("Load a saved target group, or save these targets as one")
        self.groups_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.groups_button.setMinimumHeight(34)
        self.groups_menu = QMenu(self.groups_button)
        self.groups_menu.aboutToShow.connect(self._fill_groups_menu)
        self.groups_button.setMenu(self.groups_menu)
        target_row.addWidget(self.groups_button)
        outer.addLayout(target_row)
        self.target_status = label("Enter at least one target.", role="small")
        outer.addWidget(self.target_status)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(False)
        self.tabs.setUsesScrollButtons(True)
        self.option_tabs: list[OptionTab] = []
        for tab_class in ALL_TABS:
            tab = tab_class()
            tab.changed.connect(self._schedule_refresh)
            self.option_tabs.append(tab)
            self.tabs.addTab(tab, tab_class.title)
        splitter.addWidget(self.tabs)

        inspector = QWidget()
        inspector_layout = QVBoxLayout(inspector)
        inspector_layout.setContentsMargins(0, 8, 0, 0)
        inspector_layout.setSpacing(6)
        inspector_header = QHBoxLayout()
        inspector_header.addWidget(label("Command preview", role="section"))
        inspector_header.addStretch(1)
        self.copy_button = QPushButton("Copy")
        self.copy_button.setToolTip("Copy the command, including the options Genmap manages")
        self.copy_button.clicked.connect(self._copy_command)
        self.inspect_button = QPushButton("Inspect...")
        self.inspect_button.setToolTip("Open the Command Inspector (Ctrl+I)")
        self.inspect_button.clicked.connect(self.open_inspector)
        inspector_header.addWidget(self.copy_button)
        inspector_header.addWidget(self.inspect_button)
        inspector_layout.addLayout(inspector_header)
        self.command_view = QPlainTextEdit()
        self.command_view.setReadOnly(True)
        self.command_view.setProperty("role", "mono")
        self.command_view.setMinimumHeight(54)
        self.command_view.setAccessibleName("Generated command")
        inspector_layout.addWidget(self.command_view, 1)
        self.issue_list = QListWidget()
        self.issue_list.setMinimumHeight(40)
        self.issue_list.setAccessibleName("Validation messages")
        inspector_layout.addWidget(self.issue_list, 1)
        splitter.addWidget(inspector)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([520, 190])
        outer.addWidget(splitter, 1)

        footer = QHBoxLayout()
        self.summary = label("", role="muted", wrap=True)
        footer.addWidget(self.summary, 1)
        self.start_button = QPushButton("Start scan")
        self.start_button.setProperty("accent", True)
        self.start_button.setMinimumWidth(140)
        self.start_button.setToolTip("Start the scan (Ctrl+Enter)")
        self.start_button.clicked.connect(self.start_scan)
        footer.addWidget(self.start_button)
        outer.addLayout(footer)

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.setInterval(180)
        self._refresh_timer.timeout.connect(self.refresh)
        self.targets.textChanged.connect(self._schedule_refresh)
        self.targets.returnPressed.connect(self.start_scan)

        for sequence in ("Ctrl+Return", "Ctrl+Enter"):
            shortcut = QShortcut(QKeySequence(sequence), self)
            shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
            shortcut.activated.connect(self.start_scan)
        inspect_shortcut = QShortcut(QKeySequence("Ctrl+I"), self)
        inspect_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        inspect_shortcut.activated.connect(self.open_inspector)

        context.environment_changed.connect(self._on_environment_changed)
        context.engine.job_started.connect(lambda _job: self._update_start_enabled())
        context.engine.job_finished.connect(lambda _job: self._update_start_enabled())
        context.profiles_changed.connect(self._reload_profiles)
        self._reload_profiles()
        default = next((p for p in self._profiles.values() if p.builtin_key == "default"), None)
        if default is not None:
            self.apply_profile(default.id, keep_targets=False)
        else:
            self.load_configuration(self._defaults(), starting_point="Nmap defaults")

    def _defaults(self) -> ScanConfiguration:
        config = ScanConfiguration()
        config.output.verbosity = self.context.settings.scanning.default_verbosity
        timeout = self.context.settings.nse.default_script_timeout
        if timeout:
            config.scripts.timeout = timeout
        return config

    # Profiles ----------------------------------------------------------------

    def _reload_profiles(self) -> None:
        try:
            profiles = self.context.profiles.list()
        except Exception:
            log.exception("Profiles could not be loaded")
            profiles = []
        self._profiles = {p.id: p for p in profiles}
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()
        self.profile_combo.addItem("No profile (Nmap defaults)", None)
        for profile in profiles:
            self.profile_combo.addItem(profile.name, profile.id)
            if profile.description:
                self.profile_combo.setItemData(self.profile_combo.count() - 1, profile.description, Qt.ItemDataRole.ToolTipRole)
        if self._profile_id not in self._profiles:
            self._profile_id = None
        self.profile_combo.set_current_value(self._profile_id)
        self.profile_combo.blockSignals(False)
        self._update_profile_buttons()

    def _target_spec(self) -> dict:
        data: dict[str, Any] = {}
        self.option_tabs[ALL_TABS.index(TargetsTab)].dump(data)
        data["targets"]["targets"] = split_target_text(self.targets.text())
        return data["targets"]

    def apply_profile(self, profile_id: Optional[int], *, keep_targets: bool = True) -> None:
        spec = self._target_spec() if keep_targets else None
        if profile_id is None or profile_id not in self._profiles:
            config, name, profile_id = self._defaults(), "Nmap defaults", None
        else:
            profile = self._profiles[profile_id]
            config, name = profile.configuration.model_copy(deep=True), profile.name
        self._profile_id = profile_id
        self.profile_combo.set_current_value(profile_id)
        self.load_configuration(config, starting_point=name, profile_id=profile_id)
        if spec is not None:
            self._loading = True
            try:
                self.option_tabs[ALL_TABS.index(TargetsTab)].load(self._with_targets(config, spec))
                self.targets.setText(", ".join(spec.get("targets", [])))
            finally:
                self._loading = False
            self.refresh()

    @staticmethod
    def _with_targets(config: ScanConfiguration, spec: dict) -> ScanConfiguration:
        clone = config.model_copy(deep=True)
        try:
            clone.targets = TargetSpecification.model_validate(spec)
        except (ValidationError, GenmapError):
            pass
        return clone

    def _on_profile_chosen(self, index: int) -> None:
        self.apply_profile(self.profile_combo.itemData(index))

    def _profile_differs(self) -> bool:
        if self._profile_id is None or self._current is None or self._profile_id not in self._profiles:
            return False
        stored = self._profiles[self._profile_id].configuration
        return strip_targets(self._current) != strip_targets(stored)

    def _update_profile_buttons(self) -> None:
        self.save_profile_button.setEnabled(self._current is not None)
        differs = self._profile_differs()
        self.update_profile_button.setEnabled(differs)
        self.update_profile_button.setText("Update profile *" if differs else "Update profile")

    def save_as_profile(self) -> None:
        self.refresh()
        if self._current is None:
            return
        repo = self.context.profiles

        def validate(name: str) -> Optional[str]:
            return f"A profile named \"{name}\" already exists." if repo.find_by_name(name) else None

        dialog = NameDialog(
            self,
            "Save as profile",
            name="" if self._profile_id is None else f"{self._starting_point} copy",
            note="The profile keeps every option on these tabs. Targets are not saved in profiles; use target groups for those.",
            validator=validate,
        )
        if dialog.exec() != NameDialog.DialogCode.Accepted:
            return
        name, description = dialog.values()
        try:
            profile = repo.create(name, self._current, description)
        except GenmapError as exc:
            show_exception(self, exc, "Profile not saved")
            return
        self._profile_id = profile.id
        self._starting_point = profile.name
        self.context.profiles_changed.emit()
        self.refresh()

    def update_profile(self) -> None:
        if not self._profile_differs() or self._current is None:
            return
        profile = self._profiles[self._profile_id]
        answer = QMessageBox.question(
            self,
            "Update profile",
            f"Replace the options stored in \"{profile.name}\" with the ones on this page? Scans already run are not affected.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            self.context.profiles.update(profile.id, config=self._current)
        except GenmapError as exc:
            show_exception(self, exc, "Profile not updated")
            return
        self.context.profiles_changed.emit()
        self.refresh()

    def on_shown(self) -> None:
        self._on_environment_changed(self.context.environment)
        self._update_start_enabled()
        self.targets.setFocus()

    def _on_environment_changed(self, env: Optional[NmapEnvironment]) -> None:
        for tab in self.option_tabs:
            tab.set_environment(env)
        self._schedule_refresh()

    def _schedule_refresh(self) -> None:
        if not self._loading:
            self._refresh_timer.start()

    def load_configuration(
        self,
        config: ScanConfiguration,
        *,
        starting_point: Optional[str] = None,
        keep_targets: bool = False,
        profile_id: Optional[int] = None,
    ) -> None:
        """Populate the form from a configuration (profiles, history, and rerun)."""
        self._profile_id = profile_id if profile_id in getattr(self, "_profiles", {}) else None
        if hasattr(self, "profile_combo"):
            self.profile_combo.set_current_value(self._profile_id)
        self._loading = True
        try:
            if keep_targets:
                config = config.model_copy(deep=True)
                config.targets.targets = self._config.targets.targets if self._current is None else self._current.targets.targets
            self._config = config.model_copy(deep=True)
            self.targets.setText(", ".join(config.targets.targets))
            for tab in self.option_tabs:
                tab.load(config)
            if starting_point:
                self._starting_point = starting_point
        finally:
            self._loading = False
        self.refresh()

    def set_targets(self, text: str) -> None:
        self.targets.setText(text)

    def set_target_spec(self, targets: list[str], exclusions: list[str]) -> None:
        tab = self.option_tabs[ALL_TABS.index(TargetsTab)]
        tab.exclusions.setText(", ".join(exclusions))
        self.targets.setText(", ".join(targets))
        self.refresh()

    def add_script(self, name: str) -> bool:
        """Append a script to the selection. Returns False when it was already there."""
        tab = self.option_tabs[ALL_TABS.index(ScriptsTab)]
        items = tab._current_items()
        if name in items:
            return False
        tab.expressions.setText(", ".join(items + [name]))
        self.refresh()
        return True

    def _fill_groups_menu(self) -> None:
        self.groups_menu.clear()
        try:
            groups = self.context.target_groups.list()
        except Exception:
            groups = []
        for group in groups:
            action = self.groups_menu.addAction(f"{group.name}  ({len(group.targets)})")
            action.setToolTip(", ".join(group.targets[:10]))
            action.triggered.connect(lambda _c=False, g=group: self.set_target_spec(g.targets, g.exclusions))
        if not groups:
            self.groups_menu.addAction("No saved groups yet").setEnabled(False)
        self.groups_menu.addSeparator()
        save = self.groups_menu.addAction("Save these targets as a group...")
        spec = self._target_spec()
        save.setEnabled(bool(spec.get("targets")))
        save.triggered.connect(lambda: self.save_targets_requested.emit(list(spec.get("targets", [])), list(spec.get("exclusions", []))))

    def collect(self) -> tuple[Optional[ScanConfiguration], list[ValidationIssue]]:
        data: dict[str, Any] = self._config.model_dump(mode="json")
        data.setdefault("targets", {})["targets"] = split_target_text(self.targets.text())
        for tab in self.option_tabs:
            tab.dump(data)
        try:
            config = ScanConfiguration.model_validate(data)
        except ValidationError as exc:
            return None, issues_from_validation_error(exc)
        except GenmapError as exc:
            return None, [ValidationIssue(severity="error", message=exc.message, remedy=exc.remedy)]
        return config, validate_configuration(config)

    def _program_for_preview(self) -> Path:
        env = self.context.environment
        if env is not None and env.executable is not None:
            return env.executable
        return Path(EXECUTABLE_NAME)

    def refresh(self) -> None:
        summary, status = describe_target_scope(self.targets.text())
        self.target_status.setText(summary)
        set_status(self.target_status, "error" if status == "error" else None)
        self.targets.setProperty("invalid", status == "error")
        self.targets.style().unpolish(self.targets)
        self.targets.style().polish(self.targets)

        config, issues = self.collect()
        self._current = config
        self._issues = list(issues)
        self._plan = None
        if config is not None:
            try:
                self._plan = build_command_plan(
                    self._program_for_preview(),
                    config,
                    xml_output=_PREVIEW_XML,
                    stats_interval=self.context.engine.stats_interval,
                )
            except GenmapError as exc:
                self._issues.append(ValidationIssue(severity="error", message=exc.message, remedy=exc.remedy))
            else:
                self._issues.extend(ValidationIssue(severity="warning", message=w) for w in self._plan.warnings)
                for notice in self._notices(config):
                    self._issues.append(ValidationIssue(severity="notice", message=notice.message))

        if self._plan is not None:
            if self.context.settings.advanced.show_managed_arguments:
                self.command_view.setPlainText(self._plan.display())
            else:
                self.command_view.setPlainText(self._plan.display_user_command())
        else:
            self.command_view.setPlainText("The command cannot be generated until the problems below are fixed.")

        self.issue_list.clear()
        for issue in self._issues:
            prefix = {"error": "Error", "warning": "Warning", "notice": "Review"}.get(issue.severity, "Note")
            text = f"{prefix}: {issue.message}"
            if issue.remedy:
                text += f"  {issue.remedy}"
            item = QListWidgetItem(text)
            item.setToolTip(text)
            color = {"error": "danger", "warning": "warning", "notice": "warning"}.get(issue.severity)
            if color:
                palette = self.context.theme.palette
                from PyQt6.QtGui import QColor

                item.setForeground(QColor(getattr(palette, color)))
            self.issue_list.addItem(item)
        if not self._issues:
            self.issue_list.addItem(QListWidgetItem("No problems found."))

        errors = sum(1 for i in self._issues if i.severity == "error")
        warnings = sum(1 for i in self._issues if i.severity in ("warning", "notice"))
        parts = [f"Starting point: {self._starting_point}"]
        if errors:
            parts.append(f"{errors} problem{'s' if errors != 1 else ''} to fix")
        if warnings:
            parts.append(f"{warnings} item{'s' if warnings != 1 else ''} to review")
        self.summary.setText(".  ".join(parts) + ".")
        self._update_profile_buttons()
        self.copy_button.setEnabled(self._plan is not None)
        self.inspect_button.setEnabled(self._plan is not None)
        self._update_start_enabled()

    def _notices(self, config: ScanConfiguration):
        env = self.context.environment
        catalog = env.scripts if env is not None and env.scripts.scripts else None
        return assess_intrusiveness(config, self.context.settings.nse.intrusive_categories, catalog)

    def _update_start_enabled(self) -> None:
        env = self.context.environment
        ready = self._plan is not None and not has_errors(self._issues)
        usable = env is not None and env.usable
        busy = self.context.engine.is_busy
        self.start_button.setEnabled(ready and usable and not busy)
        if not usable:
            self.start_button.setToolTip("Nmap is not available. See Settings, Nmap.")
        elif busy:
            self.start_button.setToolTip("A scan is already running.")
        elif not ready:
            self.start_button.setToolTip("Fix the problems listed in the command preview first.")
        else:
            self.start_button.setToolTip("Start the scan (Ctrl+Enter)")

    def _copy_command(self) -> None:
        if self._plan is not None:
            QApplication.clipboard().setText(self._plan.display(program_name=str(self._plan.program)))

    def open_inspector(self) -> None:
        self._refresh_timer.stop()
        self.refresh()
        if self._plan is None or self._current is None:
            return
        dialog = CommandInspectorDialog(self, self._plan, self._current, self.context.environment, self._starting_point)
        dialog.exec()

    def start_scan(self) -> None:
        self._refresh_timer.stop()
        self.refresh()
        if not self.start_button.isEnabled() or self._current is None or self._plan is None:
            if has_errors(self._issues):
                self.tabs.setFocus()
            return
        config = self._current
        env = self.context.environment
        notices = self._notices(config)
        env_warnings: list[str] = []
        if env is not None:
            raw = env.capabilities.get("raw_packets")
            needs_raw = config.techniques.uses_raw_packets or config.os_detection.enabled or config.aggressive
            if needs_raw and raw is not None and raw.available is False:
                env_warnings.append("Raw packet access looks unavailable, so Nmap will probably refuse this scan: " + raw.detail)
        if self.context.settings.general.confirm_intrusive_scans or notices or env_warnings:
            dialog = ConfirmScanDialog(
                self,
                self._plan.display(),
                ", ".join(config.targets.targets) or (config.targets.target_file or ""),
                notices,
                env_warnings,
            )
            if dialog.exec() != ConfirmScanDialog.DialogCode.Accepted:
                return
        try:
            job = self.context.engine.start(config, profile_name=self._starting_point, profile_id=self._profile_id)
        except Exception as exc:
            show_exception(self, exc, "Scan could not be started")
            return
        self.context.remember_targets(config.targets.targets)
        self.scan_started.emit(job)
