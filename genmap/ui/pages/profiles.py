"""Profiles page: manage reusable scan configurations."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from genmap.core.intrusiveness import assess_intrusiveness
from genmap.core.scan_config import PortSelectionMode, ScanConfiguration, ScanMode, TcpScanTechnique
from genmap.errors import GenmapError
from genmap.nmap.command_builder import build_user_arguments, format_command
from genmap.storage.profiles import ProfileInfo
from genmap.ui.app_context import AppContext
from genmap.ui.pages.base import BasePage
from genmap.ui.widgets.common import Card, KeyValueGrid, PageHeader, hint, label
from genmap.ui.widgets.error_dialog import show_exception
from genmap.ui.widgets.name_dialog import NameDialog
from genmap.ui.widgets.responsive import FlowLayout

ROLE_ID = Qt.ItemDataRole.UserRole + 1


def describe_configuration(config: ScanConfiguration) -> list[tuple[str, str]]:
    """Plain language summary of what a configuration does."""
    tech = config.techniques
    if tech.mode == ScanMode.PING_ONLY:
        mode = "Host discovery only (no port scan)"
    elif tech.mode == ScanMode.LIST_ONLY:
        mode = "List targets only (nothing is sent to them)"
    else:
        parts = []
        if tech.tcp == TcpScanTechnique.AUTO:
            parts.append("TCP (Nmap chooses SYN or connect)")
        elif tech.tcp is not None:
            parts.append(f"TCP {tech.tcp.value.replace('_', ' ')}")
        if tech.udp:
            parts.append("UDP")
        if tech.sctp:
            parts.append(f"SCTP {tech.sctp.value.replace('_', ' ')}")
        if tech.ip_protocol:
            parts.append("IP protocol")
        mode = "Port scan: " + (", ".join(parts) or "no technique")
    ports = {
        PortSelectionMode.DEFAULT: "Nmap default (top 1000)",
        PortSelectionMode.SPECIFIC: config.ports.specification or "(none given)",
        PortSelectionMode.TOP: f"Top {config.ports.top_ports}",
        PortSelectionMode.FAST: "Fast (top 100)",
        PortSelectionMode.ALL: "All 65535",
    }[config.ports.mode]
    detection = [name for name, on in (
        ("service versions", config.service_detection.enabled or config.aggressive),
        ("operating system", config.os_detection.enabled or config.aggressive),
        ("traceroute", config.discovery.traceroute or config.aggressive),
    ) if on]
    timing = f"T{config.timing.template}" if config.timing.template is not None else "Nmap default (T3)"
    rows = [
        ("Does", mode),
        ("Ports", ports if tech.mode == ScanMode.PORT_SCAN else "Not scanned"),
        ("Detects", ", ".join(detection) or "Nothing beyond port state"),
        ("Scripts", ", ".join(config.scripts.scripts) or ("default (via -A)" if config.aggressive else "None")),
        ("Timing", timing),
    ]
    if config.discovery.skip_discovery:
        rows.append(("Discovery", "Skipped (-Pn): every address is treated as up"))
    if config.advanced_arguments:
        rows.append(("Extra arguments", config.advanced_arguments))
    return rows


class ProfilesPage(BasePage):
    page_key = "profiles"
    page_title = "Profiles"

    use_profile_requested = pyqtSignal(object)  # profile id
    edit_profile_requested = pyqtSignal(object)  # profile id

    def __init__(self, context: AppContext, parent: Optional[QWidget] = None) -> None:
        super().__init__(context, parent)
        self._profiles: dict[int, ProfileInfo] = {}
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 22, 28, 18)
        outer.setSpacing(12)
        outer.addWidget(PageHeader(
            "Profiles",
            "Reusable scan configurations. A profile stores how to scan; targets are chosen when you start a scan.",
        ))

        toolbar = QHBoxLayout()
        self.new_button = QPushButton("New profile...")
        self.import_button = QPushButton("Import...")
        self.import_button.setToolTip("Import a profile exported from Genmap (.json)")
        toolbar.addWidget(self.new_button)
        toolbar.addWidget(self.import_button)
        toolbar.addStretch(1)
        outer.addLayout(toolbar)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        self.list = QListWidget()
        self.list.setMinimumWidth(240)
        self.list.setAccessibleName("Profiles")
        splitter.addWidget(self.list)

        detail = QWidget()
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(8, 0, 0, 0)
        detail_layout.setSpacing(12)
        self.title = label("", role="title", wrap=True)
        self.origin = label("", role="muted", wrap=True)
        detail_layout.addWidget(self.title)
        detail_layout.addWidget(self.origin)
        actions = FlowLayout()
        self.use_button = QPushButton("Scan with this profile")
        self.use_button.setProperty("accent", True)
        self.edit_button = QPushButton("Edit options")
        self.edit_button.setToolTip("Open the profile in New Scan; use Update profile there to save changes")
        self.rename_button = QPushButton("Rename...")
        self.duplicate_button = QPushButton("Duplicate")
        self.reset_button = QPushButton("Reset to built in")
        self.export_button = QPushButton("Export...")
        self.delete_button = QPushButton("Delete")
        self.delete_button.setProperty("danger", True)
        for button in (self.use_button, self.edit_button, self.rename_button, self.duplicate_button, self.reset_button, self.export_button, self.delete_button):
            actions.addWidget(button)
        detail_layout.addLayout(actions)
        summary_card = Card("What this profile does")
        self.summary = KeyValueGrid()
        summary_card.add_widget(self.summary)
        self.notices = hint("")
        summary_card.add_widget(self.notices)
        detail_layout.addWidget(summary_card)
        command_card = Card("Command it produces")
        self.command = QPlainTextEdit()
        self.command.setReadOnly(True)
        self.command.setProperty("role", "mono")
        self.command.setMaximumHeight(90)
        command_card.add_widget(self.command)
        command_card.add_widget(hint("<targets> is replaced by the targets you choose when starting a scan. Genmap adds its own -oX and --stats-every when it runs."))
        detail_layout.addWidget(command_card)
        detail_layout.addStretch(1)
        # A scroll area keeps the summary readable when the window is short.
        scroller = QScrollArea()
        scroller.setWidgetResizable(True)
        scroller.setFrameShape(QScrollArea.Shape.NoFrame)
        scroller.setWidget(detail)
        splitter.addWidget(scroller)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([260, 700])
        outer.addWidget(splitter, 1)

        self.list.currentItemChanged.connect(lambda *_: self._show_selected())
        self.list.itemDoubleClicked.connect(lambda _item: self._use())
        self.new_button.clicked.connect(self._new)
        self.import_button.clicked.connect(self._import)
        self.use_button.clicked.connect(self._use)
        self.edit_button.clicked.connect(self._edit)
        self.rename_button.clicked.connect(self._rename)
        self.duplicate_button.clicked.connect(self._duplicate)
        self.reset_button.clicked.connect(self._reset)
        self.export_button.clicked.connect(self._export)
        self.delete_button.clicked.connect(self._delete)
        context.profiles_changed.connect(self._reload_if_visible)

    def on_shown(self) -> None:
        self.reload()

    def _reload_if_visible(self) -> None:
        if self.isVisible():
            self.reload()

    def reload(self, select_id: Optional[int] = None) -> None:
        current = select_id if select_id is not None else self._selected_id()
        try:
            profiles = self.context.profiles.list()
        except Exception as exc:
            show_exception(self, exc, "Profiles could not be loaded")
            return
        self._profiles = {p.id: p for p in profiles}
        self.list.blockSignals(True)
        self.list.clear()
        for profile in profiles:
            item = QListWidgetItem(profile.name + ("   (built in)" if profile.builtin_key else ""))
            item.setData(ROLE_ID, profile.id)
            item.setToolTip(profile.description)
            self.list.addItem(item)
        self.list.blockSignals(False)
        row = next((i for i in range(self.list.count()) if self.list.item(i).data(ROLE_ID) == current), 0)
        if self.list.count():
            self.list.setCurrentRow(row)
        self._show_selected()

    def _selected_id(self) -> Optional[int]:
        item = self.list.currentItem()
        return item.data(ROLE_ID) if item else None

    def _selected(self) -> Optional[ProfileInfo]:
        profile_id = self._selected_id()
        return self._profiles.get(profile_id) if profile_id is not None else None

    def _show_selected(self) -> None:
        profile = self._selected()
        for button in (self.use_button, self.edit_button, self.rename_button, self.duplicate_button, self.export_button, self.delete_button):
            button.setEnabled(profile is not None)
        self.reset_button.setVisible(profile is not None and profile.builtin_key is not None)
        self.summary.clear()
        if profile is None:
            self.title.setText("No profile selected")
            self.origin.setText("Create a profile, or save one from the New Scan page.")
            self.command.setPlainText("")
            self.notices.setText("")
            return
        self.title.setText(profile.name)
        updated = profile.updated_at.astimezone().strftime("%Y-%m-%d %H:%M")
        origin = "Built in starting point, editable. " if profile.builtin_key else ""
        self.origin.setText(f"{origin}{profile.description}\nLast changed {updated}.".strip())
        for key, value in describe_configuration(profile.configuration):
            self.summary.add_row(key, value)
        try:
            arguments, _warnings = build_user_arguments(profile.configuration)
            self.command.setPlainText(format_command(["nmap", *arguments]) + " <targets>")
        except GenmapError as exc:
            self.command.setPlainText(f"This profile cannot produce a command: {exc.message}")
        env = self.context.environment
        catalog = env.scripts if env is not None and env.scripts.scripts else None
        config = profile.configuration.model_copy(deep=True)
        config.targets.targets = ["192.0.2.1"]
        notices = [n for n in assess_intrusiveness(config, self.context.settings.nse.intrusive_categories, catalog)]
        self.notices.setText("\n".join(f"Review: {n.message}" for n in notices))
        self.notices.setProperty("status", "warning" if notices else None)
        self.notices.style().unpolish(self.notices)
        self.notices.style().polish(self.notices)

    def _name_taken(self, exclude_id: Optional[int] = None):
        def check(name: str) -> Optional[str]:
            existing = self.context.profiles.find_by_name(name)
            if existing is not None and existing.id != exclude_id:
                return f"A profile named \"{name}\" already exists."
            return None

        return check

    def _changed(self, select_id: Optional[int] = None) -> None:
        self.context.profiles_changed.emit()
        self.reload(select_id)

    def _new(self) -> None:
        dialog = NameDialog(self, "New profile", note="The new profile starts from Nmap's defaults. Adjust it on the New Scan page afterwards.", validator=self._name_taken())
        if dialog.exec() != NameDialog.DialogCode.Accepted:
            return
        name, description = dialog.values()
        try:
            profile = self.context.profiles.create(name, ScanConfiguration(), description)
        except GenmapError as exc:
            show_exception(self, exc, "Profile not created")
            return
        self._changed(profile.id)
        self.edit_profile_requested.emit(profile.id)

    def _use(self) -> None:
        profile = self._selected()
        if profile is not None:
            self.use_profile_requested.emit(profile.id)

    def _edit(self) -> None:
        profile = self._selected()
        if profile is not None:
            self.edit_profile_requested.emit(profile.id)

    def _rename(self) -> None:
        profile = self._selected()
        if profile is None:
            return
        dialog = NameDialog(self, "Rename profile", name=profile.name, description=profile.description, validator=self._name_taken(profile.id))
        if dialog.exec() != NameDialog.DialogCode.Accepted:
            return
        name, description = dialog.values()
        try:
            self.context.profiles.update(profile.id, name=name, description=description)
        except GenmapError as exc:
            show_exception(self, exc, "Profile not renamed")
            return
        self._changed(profile.id)

    def _duplicate(self) -> None:
        profile = self._selected()
        if profile is None:
            return
        try:
            copy = self.context.profiles.duplicate(profile.id)
        except GenmapError as exc:
            show_exception(self, exc, "Profile not duplicated")
            return
        self._changed(copy.id)

    def _reset(self) -> None:
        profile = self._selected()
        if profile is None or profile.builtin_key is None:
            return
        answer = QMessageBox.question(
            self,
            "Reset profile",
            f"Restore \"{profile.name}\" to Genmap's built in options? Your changes to it will be lost.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            self.context.profiles.reset_builtin(profile.id)
        except GenmapError as exc:
            show_exception(self, exc, "Profile not reset")
            return
        self._changed(profile.id)

    def _export(self) -> None:
        profile = self._selected()
        if profile is None:
            return
        safe = "".join(c if c.isalnum() or c in " ._" else "_" for c in profile.name).strip() or "profile"
        path, _ = QFileDialog.getSaveFileName(self, "Export profile", str(Path.home() / f"{safe}.genmap-profile.json"), "Genmap profile (*.json)")
        if not path:
            return
        try:
            self.context.profiles.export_file(profile.id, Path(path))
        except GenmapError as exc:
            show_exception(self, exc, "Export failed")
            return
        QMessageBox.information(self, "Profile exported", f"Saved to {path}")

    def _import(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import profile", str(Path.home()), "Genmap profile (*.json);;All files (*)")
        if not path:
            return
        try:
            profile = self.context.profiles.import_file(Path(path))
        except GenmapError as exc:
            show_exception(self, exc, "Import failed")
            return
        self._changed(profile.id)

    def _delete(self) -> None:
        profile = self._selected()
        if profile is None:
            return
        answer = QMessageBox.warning(
            self,
            "Delete profile",
            f"Delete the profile \"{profile.name}\"? Scans already run with it keep their own copy of the configuration.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.context.profiles.delete(profile.id)
        self._changed()
