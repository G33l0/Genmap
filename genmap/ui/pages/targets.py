"""Targets page: saved target groups and recently scanned targets."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from genmap.core.targets import estimate_host_count, parse_targets, split_target_text
from genmap.errors import GenmapError
from genmap.storage.target_groups import TargetGroupInfo
from genmap.ui.app_context import AppContext
from genmap.ui.pages.base import BasePage
from genmap.ui.widgets.common import PageHeader, form_layout, hint, label, set_status
from genmap.ui.widgets.error_dialog import show_exception
from genmap.ui.widgets.inputs import TextField
from genmap.ui.widgets.name_dialog import NameDialog
from genmap.ui.widgets.responsive import FlowLayout

ROLE_ID = Qt.ItemDataRole.UserRole + 1


def _lines(editor: QPlainTextEdit) -> list[str]:
    return split_target_text(editor.toPlainText())


class TargetsPage(BasePage):
    page_key = "targets"
    page_title = "Targets"

    scan_targets_requested = pyqtSignal(list, list)  # targets, exclusions

    def __init__(self, context: AppContext, parent: Optional[QWidget] = None) -> None:
        super().__init__(context, parent)
        self._groups: dict[int, TargetGroupInfo] = {}
        self._dirty = False
        self._draft = False  # editing a group that has not been saved yet
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 22, 28, 18)
        outer.setSpacing(12)
        outer.addWidget(PageHeader("Targets", "Save the networks and hosts you scan often, and reuse anything you scanned before."))
        self.tabs = QTabWidget()
        outer.addWidget(self.tabs, 1)
        self.tabs.addTab(self._build_groups(), "Target groups")
        self.tabs.addTab(self._build_recent(), "Recently scanned")
        context.target_groups_changed.connect(self._reload_if_visible)
        context.index_changed.connect(self._reload_recent_if_visible)

    # Groups ---------------------------------------------------------------

    def _build_groups(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        toolbar = QHBoxLayout()
        self.new_button = QPushButton("New group...")
        self.import_button = QPushButton("Import...")
        self.import_button.setToolTip("Import a target list (one target per line, as used by nmap -iL) or a Genmap JSON export")
        toolbar.addWidget(self.new_button)
        toolbar.addWidget(self.import_button)
        toolbar.addStretch(1)
        layout.addLayout(toolbar)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        self.group_list = QListWidget()
        self.group_list.setMinimumWidth(200)
        self.group_list.setAccessibleName("Target groups")
        splitter.addWidget(self.group_list)

        editor = QWidget()
        editor_layout = QVBoxLayout(editor)
        editor_layout.setContentsMargins(8, 0, 0, 0)
        form = form_layout()
        self.name = TextField("Group name")
        self.description = TextField("Optional description")
        form.addRow("Name", self.name)
        form.addRow("Description", self.description)
        editor_layout.addLayout(form)
        editors = QHBoxLayout()
        targets_box = QVBoxLayout()
        targets_box.addWidget(label("Targets", role="section"))
        self.targets_edit = QPlainTextEdit()
        self.targets_edit.setProperty("role", "mono")
        self.targets_edit.setPlaceholderText("One per line: 10.0.0.0/24, files.lab.internal, 2001:db8::/120 ...")
        self.targets_edit.setTabChangesFocus(True)
        targets_box.addWidget(self.targets_edit, 1)
        exclusions_box = QVBoxLayout()
        exclusions_box.addWidget(label("Exclusions", role="section"))
        self.exclusions_edit = QPlainTextEdit()
        self.exclusions_edit.setProperty("role", "mono")
        self.exclusions_edit.setPlaceholderText("Addresses or networks never to scan")
        self.exclusions_edit.setTabChangesFocus(True)
        exclusions_box.addWidget(self.exclusions_edit, 1)
        editors.addLayout(targets_box, 2)
        editors.addLayout(exclusions_box, 1)
        editor_layout.addLayout(editors, 1)
        self.validation = label("", role="small", wrap=True)
        editor_layout.addWidget(self.validation)
        actions = FlowLayout()
        self.scan_button = QPushButton("Scan this group")
        self.scan_button.setProperty("accent", True)
        self.save_button = QPushButton("Save")
        self.revert_button = QPushButton("Revert")
        self.export_button = QPushButton("Export...")
        self.delete_button = QPushButton("Delete")
        self.delete_button.setProperty("danger", True)
        for button in (self.scan_button, self.save_button, self.revert_button, self.export_button, self.delete_button):
            actions.addWidget(button)
        editor_layout.addLayout(actions)
        splitter.addWidget(editor)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([240, 700])
        layout.addWidget(splitter, 1)

        self._validate_timer = QTimer(self)
        self._validate_timer.setSingleShot(True)
        self._validate_timer.setInterval(250)
        self._validate_timer.timeout.connect(self._validate)
        for widget in (self.targets_edit, self.exclusions_edit):
            widget.textChanged.connect(self._edited)
        for widget in (self.name, self.description):
            widget.textEdited.connect(self._edited)
        self.group_list.currentItemChanged.connect(self._on_group_selected)
        self.new_button.clicked.connect(self._new)
        self.import_button.clicked.connect(self._import)
        self.scan_button.clicked.connect(self._scan)
        self.save_button.clicked.connect(self._save)
        self.revert_button.clicked.connect(self._show_group)
        self.export_button.clicked.connect(self._export)
        self.delete_button.clicked.connect(self._delete)
        return tab

    def on_shown(self) -> None:
        self.reload()
        self.reload_recent()

    def _reload_if_visible(self) -> None:
        if self.isVisible() and not self._dirty:
            self.reload()

    def reload(self, select_id: Optional[int] = None) -> None:
        current = select_id if select_id is not None else self._selected_id()
        try:
            groups = self.context.target_groups.list()
        except Exception as exc:
            show_exception(self, exc, "Target groups could not be loaded")
            return
        self._groups = {g.id: g for g in groups}
        self.group_list.blockSignals(True)
        self.group_list.clear()
        for group in groups:
            item = QListWidgetItem(f"{group.name}  ({len(group.targets)})")
            item.setData(ROLE_ID, group.id)
            item.setToolTip(group.description or ", ".join(group.targets[:10]))
            self.group_list.addItem(item)
        self.group_list.blockSignals(False)
        row = next((i for i in range(self.group_list.count()) if self.group_list.item(i).data(ROLE_ID) == current), 0)
        if self.group_list.count():
            self.group_list.setCurrentRow(row)
        self._show_group()

    def _selected_id(self) -> Optional[int]:
        item = self.group_list.currentItem()
        return item.data(ROLE_ID) if item else None

    def _selected(self) -> Optional[TargetGroupInfo]:
        group_id = self._selected_id()
        return self._groups.get(group_id) if group_id is not None else None

    def _on_group_selected(self, current, previous) -> None:
        if self._dirty and (previous is not None or self._draft):
            answer = QMessageBox.question(
                self,
                "Unsaved changes",
                "Save the changes to this target group first?",
                QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Save,
            )
            target = previous.data(ROLE_ID) if previous is not None else None
            if answer == QMessageBox.StandardButton.Cancel or (answer == QMessageBox.StandardButton.Save and not self._save(target)):
                self.group_list.blockSignals(True)
                self.group_list.setCurrentItem(previous)
                self.group_list.blockSignals(False)
                return
        self._show_group()

    def _show_group(self) -> None:
        self._draft = False
        group = self._selected()
        editable = group is not None
        for widget in (self.name, self.description, self.targets_edit, self.exclusions_edit, self.scan_button, self.export_button, self.delete_button):
            widget.setEnabled(editable)
        for widget in (self.targets_edit, self.exclusions_edit, self.name, self.description):
            widget.blockSignals(True)
        self.name.setText(group.name if group else "")
        self.description.setText(group.description if group else "")
        self.targets_edit.setPlainText("\n".join(group.targets) if group else "")
        self.exclusions_edit.setPlainText("\n".join(group.exclusions) if group else "")
        for widget in (self.targets_edit, self.exclusions_edit, self.name, self.description):
            widget.blockSignals(False)
        self._dirty = False
        self._validate()

    def _edited(self) -> None:
        self._dirty = True
        self._validate_timer.start()
        self._update_buttons(valid=None)

    def _validate(self) -> bool:
        self._validate_timer.stop()
        if self._selected() is None and not self._draft:
            self.validation.setText("Create a group or import a target list to get started." if not self._groups else "")
            set_status(self.validation, None)
            self._update_buttons(valid=False)
            return False
        try:
            targets = parse_targets(_lines(self.targets_edit))
            exclusions = parse_targets(_lines(self.exclusions_edit))
        except GenmapError as exc:
            self.validation.setText(exc.message)
            set_status(self.validation, "error")
            self._update_buttons(valid=False)
            return False
        if self._draft and not " ".join(self.name.text().split()):
            self.validation.setText("Give the new group a name.")
            set_status(self.validation, None)
            self._update_buttons(valid=False)
            return False
        if not targets:
            self.validation.setText("A group needs at least one target.")
            set_status(self.validation, "error")
            self._update_buttons(valid=False)
            return False
        count = estimate_host_count(targets)
        scope = f"about {count:,} addresses" if count is not None else "size depends on name resolution"
        self.validation.setText(f"{len(targets)} target expression{'s' if len(targets) != 1 else ''} ({scope}), {len(exclusions)} exclusion{'s' if len(exclusions) != 1 else ''}.")
        set_status(self.validation, None)
        self._update_buttons(valid=True)
        return True

    def _update_buttons(self, valid: Optional[bool]) -> None:
        selected = self._selected() is not None or self._draft
        self.save_button.setEnabled(selected and self._dirty and valid is not False)
        self.revert_button.setEnabled(selected and self._dirty)
        self.scan_button.setEnabled(selected and valid is not False)
        self.save_button.setText("Save *" if self._dirty else "Save")

    def _save(self, group_id: Optional[int] = None) -> bool:
        if self._draft:
            if not self._validate():
                return False
            try:
                group = self.context.target_groups.create(
                    self.name.text(), _lines(self.targets_edit), _lines(self.exclusions_edit), self.description.text()
                )
            except GenmapError as exc:
                show_exception(self, exc, "Target group not created")
                return False
            self._draft = False
            self._dirty = False
            self.context.target_groups_changed.emit()
            self.reload(group.id)
            return True
        group_id = group_id if group_id is not None else self._selected_id()
        if group_id is None or not self._validate():
            return False
        try:
            self.context.target_groups.update(
                group_id,
                name=self.name.text(),
                description=self.description.text(),
                targets=_lines(self.targets_edit),
                exclusions=_lines(self.exclusions_edit),
            )
        except GenmapError as exc:
            show_exception(self, exc, "Target group not saved")
            return False
        self._dirty = False
        self.context.target_groups_changed.emit()
        self.reload(group_id)
        return True

    def has_unsaved_changes(self) -> bool:
        return self._dirty

    def _name_check(self, name: str) -> Optional[str]:
        return f'A target group named "{name}" already exists.' if any(g.name.lower() == name.lower() for g in self._groups.values()) else None

    def create_group(self, targets: list[str], exclusions: Optional[list[str]] = None, *, title: str = "New target group") -> Optional[int]:
        dialog = NameDialog(self, title, validator=self._name_check)
        if dialog.exec() != NameDialog.DialogCode.Accepted:
            return None
        name, description = dialog.values()
        try:
            group = self.context.target_groups.create(name, targets, exclusions or [], description)
        except GenmapError as exc:
            show_exception(self, exc, "Target group not created")
            return None
        self.context.target_groups_changed.emit()
        self.reload(group.id)
        self.tabs.setCurrentIndex(0)
        return group.id

    def _new(self) -> None:
        if self._dirty and not self._confirm_discard():
            return
        self.group_list.blockSignals(True)
        self.group_list.clearSelection()
        self.group_list.setCurrentRow(-1)
        self.group_list.blockSignals(False)
        for widget in (self.targets_edit, self.exclusions_edit, self.name, self.description):
            widget.blockSignals(True)
            widget.clear()
            widget.blockSignals(False)
        for widget in (self.name, self.description, self.targets_edit, self.exclusions_edit):
            widget.setEnabled(True)
        self.export_button.setEnabled(False)
        self.delete_button.setEnabled(False)
        self._draft = True
        self._dirty = True
        self.tabs.setCurrentIndex(0)
        self._validate()
        self.name.setFocus()

    def _confirm_discard(self) -> bool:
        answer = QMessageBox.question(
            self,
            "Unsaved changes",
            "Discard the changes to the current target group?",
            QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        return answer == QMessageBox.StandardButton.Discard

    def _scan(self) -> None:
        if not self._validate():
            return
        # Scanning uses what is in the editor, saved or not, so nothing unexpected is scanned.
        self.scan_targets_requested.emit(_lines(self.targets_edit), _lines(self.exclusions_edit))

    def _import(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import targets", str(Path.home()), "Target lists (*.txt *.lst *.json);;All files (*)")
        if not path:
            return
        try:
            group = self.context.target_groups.import_file(Path(path))
        except GenmapError as exc:
            show_exception(self, exc, "Import failed")
            return
        self.context.target_groups_changed.emit()
        self.reload(group.id)

    def _export(self) -> None:
        group = self._selected()
        if group is None:
            return
        safe = "".join(c if c.isalnum() or c in " ._" else "_" for c in group.name).strip() or "targets"
        path, chosen = QFileDialog.getSaveFileName(
            self,
            "Export target group",
            str(Path.home() / f"{safe}.txt"),
            "Target list for nmap -iL (*.txt);;Genmap target group (*.json)",
        )
        if not path:
            return
        try:
            if path.lower().endswith(".json") or "json" in chosen:
                Path(path).write_text(json.dumps(self.context.target_groups.export_data(group.id), indent=2), encoding="utf-8")
            else:
                Path(path).write_text(self.context.target_groups.export_text(group.id), encoding="utf-8")
        except (OSError, GenmapError) as exc:
            show_exception(self, exc, "Export failed")
            return
        QMessageBox.information(self, "Targets exported", f"Saved to {path}")

    def _delete(self) -> None:
        group = self._selected()
        if group is None:
            return
        answer = QMessageBox.warning(
            self,
            "Delete target group",
            f'Delete the target group "{group.name}"? Scans already run keep their own record of the targets.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.context.target_groups.delete(group.id)
        self._dirty = False
        self.context.target_groups_changed.emit()
        self.reload()

    # Recent ---------------------------------------------------------------

    def _build_recent(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.addWidget(hint("Target expressions from your scan history, newest first. Select several to scan them together or save them as a group."))
        self.recent_table = QTableWidget(0, 3)
        self.recent_table.setHorizontalHeaderLabels(["Target", "Last scanned", "Scans"])
        self.recent_table.verticalHeader().setVisible(False)
        self.recent_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.recent_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.recent_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.recent_table.setSortingEnabled(True)
        self.recent_table.setAccessibleName("Recently scanned targets")
        layout.addWidget(self.recent_table, 1)
        row = QHBoxLayout()
        self.recent_scan = QPushButton("Scan selected")
        self.recent_scan.setProperty("accent", True)
        self.recent_save = QPushButton("Save selected as group...")
        row.addWidget(self.recent_scan)
        row.addWidget(self.recent_save)
        row.addStretch(1)
        layout.addLayout(row)
        self.recent_scan.clicked.connect(lambda: self._selected_recent() and self.scan_targets_requested.emit(self._selected_recent(), []))
        self.recent_save.clicked.connect(lambda: self._selected_recent() and self.create_group(self._selected_recent(), title="Save as target group"))
        self.recent_table.itemSelectionChanged.connect(self._update_recent_buttons)
        self.recent_table.doubleClicked.connect(lambda _i: self.recent_scan.click())
        self._update_recent_buttons()
        return tab

    def _reload_recent_if_visible(self) -> None:
        if self.isVisible():
            self.reload_recent()

    def reload_recent(self) -> None:
        try:
            rows = self.context.scan_index.recent_targets(limit=200)
        except Exception:
            rows = []
        self.recent_table.setSortingEnabled(False)
        self.recent_table.setRowCount(len(rows))
        for index, (expression, when, count) in enumerate(rows):
            items = [QTableWidgetItem(expression), QTableWidgetItem(when.astimezone().strftime("%Y-%m-%d %H:%M")), QTableWidgetItem()]
            items[2].setData(Qt.ItemDataRole.DisplayRole, count)
            for column, item in enumerate(items):
                self.recent_table.setItem(index, column, item)
        self.recent_table.setSortingEnabled(True)
        self.recent_table.resizeColumnToContents(1)
        self._update_recent_buttons()

    def _selected_recent(self) -> list[str]:
        rows = sorted({i.row() for i in self.recent_table.selectedIndexes()})
        return [self.recent_table.item(r, 0).text() for r in rows]

    def _update_recent_buttons(self) -> None:
        has = bool(self._selected_recent())
        self.recent_scan.setEnabled(has)
        self.recent_save.setEnabled(has)
