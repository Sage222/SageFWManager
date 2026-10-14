"""
ui/rules_manager.py

The real rule editor: create, edit, and delete firewall rules from the
GUI. This is the Rules tab's actual content in shell.py -- the Dashboard's
embedded rules table (dashboard.py's RulesOverviewWidget) stays read-only
plus Tidy Up, by design; this module is where you make real changes.

Safety boundaries, consistent with the rest of the app:
  - Edit and Delete are only ever enabled for rules THIS app created
    (rule.is_ours, i.e. carrying the [NFW] prefix). Pre-existing Windows
    or other-software rules can be viewed and searched here, but never
    edited or deleted from this screen -- Tidy Up (on the Dashboard) is
    the one deliberate, separately-confirmed exception for removing
    truly orphaned rules regardless of origin.
  - New rules always get the [NFW] prefix automatically.
  - Every create/edit/delete goes through firewall_engine directly (the
    same COM wrapper used everywhere else) -- no separate code path.

Depends on: PyQt6, PyQt6-Fluent-Widgets (qfluentwidgets).
"""

from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QMenu,
    QWidget, QVBoxLayout, QHBoxLayout, QApplication, QTableWidget,
    QTableWidgetItem, QDialog, QFormLayout, QFileDialog, QMessageBox,
    QCheckBox, QLineEdit,
)

from qfluentwidgets import (
    TitleLabel, SubtitleLabel, CaptionLabel, PushButton, PrimaryPushButton,
    SearchLineEdit, ComboBox, LineEdit, InfoBar, InfoBarPosition, setTheme, Theme,
)

sys.path.append(str(Path(__file__).resolve().parent.parent))  # allow importing core/*
from firewall_engine import (
    FirewallEngine, FirewallRule, RULE_PREFIX,
    DIR_IN, DIR_OUT, ACTION_ALLOW, ACTION_BLOCK,
    PROFILE_DOMAIN, PROFILE_PRIVATE, PROFILE_PUBLIC, PROFILE_ALL,
    PROTOCOL_TCP, PROTOCOL_UDP, PROTOCOL_ANY,
)
from firewall_engine import BlockIncompatibleError  # sagefw-blockfix-v1
from app_resolver import resolve_app
from rule_store import RuleStore

# Reuse the shared table setup/sort-preservation helpers rather than
# duplicating them -- see dashboard.py for the reasoning behind each.
from dashboard import _configure_table_header, _repopulate_preserving_sort, ALLOW_COLOR, BLOCK_COLOR, search_google, exe_name_from_path  # sagefw-google-v1
from dashboard import resolve_group_name, GROUP_INDEX  # sagefw-groups-v1

# sagefw-rules-cols-v1
# ---- rule type classification + first-seen/created tracking (SageFW) ----
import json as _json
import os as _os
import sys as _sys
import datetime as _dt
from PyQt6.QtGui import QColor as _QColor, QFont as _QFont

TYPE_SYSTEM = ("System", _QColor(80, 160, 255))
TYPE_STORE = ("Store app", _QColor(180, 120, 255))
TYPE_INSTALLED = ("Installed", _QColor(70, 190, 100))
TYPE_USER = ("User app", _QColor(240, 160, 60))
TYPE_PORT = ("Port / any app", _QColor(150, 150, 150))
TYPE_OTHER = ("Other", _QColor(150, 150, 150))


def classify_rule(rule):
    raw = (rule.application_path or "").strip()
    name = (rule.name or "")
    if not raw:
        return TYPE_SYSTEM if name.startswith("@") else TYPE_PORT
    path = _os.path.expandvars(raw).replace("/", "\\").lower()
    drive = _os.environ.get("SystemDrive", "C:").lower()
    windir = _os.environ.get("SystemRoot", drive + "\\windows").lower()
    pf = _os.environ.get("ProgramFiles", drive + "\\program files").lower()
    pf86 = _os.environ.get("ProgramFiles(x86)", drive + "\\program files (x86)").lower()
    pdata = _os.environ.get("ProgramData", drive + "\\programdata").lower()
    users = drive + "\\users"
    if path.startswith(windir + "\\") or path == windir:
        return TYPE_SYSTEM
    if "\\windowsapps\\" in path:
        return TYPE_STORE
    if path.startswith((pf + "\\", pf86 + "\\", pdata + "\\")):
        return TYPE_INSTALLED
    if path.startswith(users + "\\"):
        return TYPE_USER
    return TYPE_OTHER



# ---- shared rule list so the Inbound and Outbound pages load rules once (SageFW) ----
_RULES_SHARED = {"time": 0.0, "rules": None}
_RULES_INSTANCES = []

# sagefw-polish-v1
PROTOCOL_LABELS = {1: "ICMPv4", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 43: "IPv6-Route", 44: "IPv6-Frag",
                   47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 59: "IPv6-NoNxt", 60: "IPv6-Opts", 256: "Any"}


def protocol_label(protocol) -> str:
    return PROTOCOL_LABELS.get(protocol, str(protocol))


def ports_label(protocol, spec) -> str:
    # Ports only apply to TCP and UDP; show "-" for anything else.
    if protocol not in (6, 17):
        return "-"
    spec = (spec or "*").strip()
    return "Any" if spec in ("", "*") else spec


PROTOCOL_CHOICES = {"Any": PROTOCOL_ANY, "TCP": PROTOCOL_TCP, "UDP": PROTOCOL_UDP}
PROTOCOL_NAMES_REVERSE = {v: k for k, v in PROTOCOL_CHOICES.items()}


class RuleEditorDialog(QDialog):
    """
    Create-or-edit dialog. Pass an existing FirewallRule to pre-fill for
    editing; pass None to create a new rule from scratch.
    """

    def __init__(self, engine: FirewallEngine, existing_rule: FirewallRule | None = None, parent=None,
                 prefill: dict | None = None):
        super().__init__(parent)
        self.engine = engine
        self.existing_rule = existing_rule
        self.setWindowTitle("Edit Rule" if existing_rule else "New Rule")
        self.setMinimumWidth(480)
        self._build_ui()
        if existing_rule:
            self._populate_from_existing(existing_rule)
        elif prefill:
            self._apply_prefill(prefill)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        self.any_app_check = QCheckBox("Apply to any application (port/protocol-based rule)")
        self.any_app_check.stateChanged.connect(self._on_any_app_toggled)
        layout.addWidget(self.any_app_check)

        path_row = QHBoxLayout()
        self.app_path_edit = LineEdit()
        self.app_path_edit.setPlaceholderText("Path to .exe")
        self.app_path_edit.textChanged.connect(self._suggest_name)
        browse_btn = PushButton("Browse...")
        browse_btn.clicked.connect(self._browse_for_app)
        path_row.addWidget(self.app_path_edit)
        path_row.addWidget(browse_btn)

        form_widget = QWidget()
        form = QFormLayout(form_widget)
        form.addRow("Application:", path_row)

        self.name_edit = LineEdit()
        form.addRow("Rule name:", self.name_edit)

        self.direction_combo = ComboBox()
        self.direction_combo.addItems(["Outbound", "Inbound"])
        form.addRow("Direction:", self.direction_combo)

        self.action_combo = ComboBox()
        self.action_combo.addItems(["Allow", "Block"])
        self.action_combo.currentTextChanged.connect(self._suggest_name)
        form.addRow("Action:", self.action_combo)

        self.protocol_combo = ComboBox()
        self.protocol_combo.addItems(list(PROTOCOL_CHOICES.keys()))
        self.protocol_combo.currentTextChanged.connect(self._on_protocol_changed)
        form.addRow("Protocol:", self.protocol_combo)

        self.local_ports_edit = LineEdit()
        self.local_ports_edit.setText("*")
        self.local_ports_edit.setPlaceholderText("e.g. 80, 443, 8000-8100, or *")
        form.addRow("Local port(s):", self.local_ports_edit)

        self.remote_ports_edit = LineEdit()
        self.remote_ports_edit.setText("*")
        self.remote_ports_edit.setPlaceholderText("e.g. 80, 443, 8000-8100, or *")
        form.addRow("Remote port(s):", self.remote_ports_edit)

        self.remote_addr_edit = LineEdit()
        self.remote_addr_edit.setText("*")
        self.remote_addr_edit.setPlaceholderText("e.g. 192.168.1.0/24, or *")
        form.addRow("Remote address(es):", self.remote_addr_edit)

        profiles_row = QHBoxLayout()
        self.domain_check = QCheckBox("Domain")
        self.private_check = QCheckBox("Private")
        self.public_check = QCheckBox("Public")
        for cb in (self.domain_check, self.private_check, self.public_check):
            cb.setChecked(True)
            profiles_row.addWidget(cb)
        form.addRow("Profiles:", profiles_row)

        self.enabled_check = QCheckBox("Rule enabled")
        self.enabled_check.setChecked(True)
        form.addRow("", self.enabled_check)

        layout.addWidget(form_widget)

        self._on_protocol_changed(self.protocol_combo.currentText())

        button_row = QHBoxLayout()
        button_row.addStretch()
        cancel_btn = PushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        save_btn = PrimaryPushButton("Save")
        save_btn.clicked.connect(self._on_save_clicked)
        button_row.addWidget(cancel_btn)
        button_row.addWidget(save_btn)
        layout.addLayout(button_row)

    def _apply_prefill(self, p: dict) -> None:
        app_path = p.get("application_path")
        if app_path:
            self.any_app_check.setChecked(False)
            self.app_path_edit.setText(app_path)
        else:
            self.any_app_check.setChecked(True)
        self.direction_combo.setCurrentText(p.get("direction", "Outbound"))
        self.action_combo.setCurrentText(p.get("action", "Allow"))
        self.protocol_combo.setCurrentText(p.get("protocol", "Any"))
        self.local_ports_edit.setText(p.get("local_ports", "*"))
        self.remote_ports_edit.setText(p.get("remote_ports", "*"))
        self.remote_addr_edit.setText(p.get("remote_addresses", "*"))
        self._suggest_name()
        if p.get("name_suffix"):
            self.name_edit.setText(self.name_edit.text() + p["name_suffix"])

    def _on_any_app_toggled(self, _state) -> None:
        is_any = self.any_app_check.isChecked()
        self.app_path_edit.setEnabled(not is_any)
        if is_any:
            self._suggest_name()

    def _on_protocol_changed(self, protocol_text: str) -> None:
        is_port_based = protocol_text in ("TCP", "UDP")
        self.local_ports_edit.setEnabled(is_port_based)
        self.remote_ports_edit.setEnabled(is_port_based)

    def _browse_for_app(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select application", "", "Executables (*.exe);;All files (*.*)"
        )
        if path:
            self.app_path_edit.setText(path)

    def _suggest_name(self) -> None:
        if self.existing_rule:
            return  # Don't overwrite a name the user is editing.
        action = self.action_combo.currentText()
        direction = self.direction_combo.currentText()
        if self.any_app_check.isChecked() or not self.app_path_edit.text().strip():
            label = "Any Application"
        else:
            info = resolve_app(self.app_path_edit.text().strip())
            label = info.display_name or Path(self.app_path_edit.text()).stem
        self.name_edit.setText(f"{RULE_PREFIX}{action} {label} ({direction})")

    def _populate_from_existing(self, rule: FirewallRule) -> None:
        if rule.application_path:
            self.app_path_edit.setText(rule.application_path)
        else:
            self.any_app_check.setChecked(True)
        self.name_edit.setText(rule.name)
        self.direction_combo.setCurrentText("Inbound" if rule.direction == DIR_IN else "Outbound")
        self.action_combo.setCurrentText("Allow" if rule.action == ACTION_ALLOW else "Block")
        self.protocol_combo.setCurrentText(PROTOCOL_NAMES_REVERSE.get(rule.protocol, "Any"))
        self.local_ports_edit.setText(rule.local_ports or "*")
        self.remote_ports_edit.setText(rule.remote_ports or "*")
        self.remote_addr_edit.setText(rule.remote_addresses or "*")
        self.domain_check.setChecked(bool(rule.profiles & PROFILE_DOMAIN))
        self.private_check.setChecked(bool(rule.profiles & PROFILE_PRIVATE))
        self.public_check.setChecked(bool(rule.profiles & PROFILE_PUBLIC))
        self.enabled_check.setChecked(rule.enabled)

    def _on_save_clicked(self) -> None:
        name = self.name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Missing name", "Please enter a rule name.")
            return

        is_any_app = self.any_app_check.isChecked()
        app_path = None if is_any_app else self.app_path_edit.text().strip()
        if not is_any_app and not app_path:
            QMessageBox.warning(self, "Missing application",
                                 "Choose an application, or check 'Apply to any application'.")
            return

        profiles = 0
        if self.domain_check.isChecked():
            profiles |= PROFILE_DOMAIN
        if self.private_check.isChecked():
            profiles |= PROFILE_PRIVATE
        if self.public_check.isChecked():
            profiles |= PROFILE_PUBLIC
        if profiles == 0:
            QMessageBox.warning(self, "No profiles selected",
                                 "Select at least one network profile (Domain/Private/Public).")
            return

        # Rules created/edited here always carry our prefix, regardless of
        # what the user types, so they remain identifiable as ours and
        # editable/deletable later. If they typed a name without it, add it.
        foreign_edit = bool(self.existing_rule and not self.existing_rule.is_ours)
        if not foreign_edit and not name.startswith(RULE_PREFIX):
            name = RULE_PREFIX + name

        rule = FirewallRule(
            name=name,
            description=(getattr(self.existing_rule, "description", None) or "") if foreign_edit else "Created via SageFW Rules Manager",
            application_path=app_path,
            protocol=PROTOCOL_CHOICES[self.protocol_combo.currentText()],
            local_ports=self.local_ports_edit.text().strip() or "*",
            remote_ports=self.remote_ports_edit.text().strip() or "*",
            remote_addresses=self.remote_addr_edit.text().strip() or "*",
            direction=DIR_IN if self.direction_combo.currentText() == "Inbound" else DIR_OUT,
            action=ACTION_ALLOW if self.action_combo.currentText() == "Allow" else ACTION_BLOCK,
            enabled=self.enabled_check.isChecked(),
            profiles=profiles,
            is_ours=(self.existing_rule.is_ours if self.existing_rule else True),
            service_name=getattr(self.existing_rule, "service_name", None),
            grouping=getattr(self.existing_rule, "grouping", ""),
            edge_traversal=getattr(self.existing_rule, "edge_traversal", False),
            interface_types=getattr(self.existing_rule, "interface_types", "All"),
        )

        try:
            if self.existing_rule is not None:
                try:
                    self.engine.update_rule_in_place(self.existing_rule, rule)
                except BlockIncompatibleError as blocked:
                    answer = QMessageBox.question(
                        self, "Block rules cannot keep these settings",
                        "Windows does not allow a Block rule to carry:\n\n  - "
                        + "\n  - ".join(blocked.labels)
                        + "\n\nThese settings only make sense on Allow rules. Clear them and change the rule "
                          "to Block?",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    )
                    if answer != QMessageBox.StandardButton.Yes:
                        return
                    self.engine.update_rule_in_place(self.existing_rule, rule, clear_incompatible=True)
            else:
                self.engine.create_rule(rule, overwrite=True)
        except Exception as exc:
            QMessageBox.critical(self, "Could not save rule", str(exc))
            return

        self.accept()


class RulesManagerWidget(QWidget):
    """
    Full rule editor: table of every current rule (viewable regardless of
    origin), with New/Edit/Delete acting only on rules this app created.
    """

    def __init__(self, engine: FirewallEngine, store: RuleStore | None = None, parent=None,
                 direction: int | None = None):
        super().__init__(parent)
        self.engine = engine
        self.store = store
        self._all_rules: list[FirewallRule] = []
        self.direction = direction
        _RULES_INSTANCES.append(self)
        self._build_ui()
        if direction is not None:
            self.table.setColumnHidden(2, True)
        self.refresh(force=False)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        header_row = QHBoxLayout()
        header_row.addWidget(SubtitleLabel("Manage Rules"))
        header_row.addStretch()

        self.new_btn = PrimaryPushButton("New Rule")
        self.new_btn.clicked.connect(self._on_new_clicked)
        header_row.addWidget(self.new_btn)

        self.edit_btn = PushButton("Edit")
        self.edit_btn.setEnabled(False)
        self.edit_btn.clicked.connect(self._on_edit_clicked)
        header_row.addWidget(self.edit_btn)

        self.delete_btn = PushButton("Delete")
        self.delete_btn.setEnabled(False)
        self.delete_btn.clicked.connect(self._on_delete_clicked)
        header_row.addWidget(self.delete_btn)

        self.refresh_btn = PushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh)
        header_row.addWidget(self.refresh_btn)
        layout.addLayout(header_row)

        note = CaptionLabel(
            "You can edit or delete any rule here, including Windows and other software's "
            "rules. Deleting a rule SageFW did not create asks for extra confirmation, because "
            "removing a built-in rule can break network features."
        )
        note.setWordWrap(True)
        layout.addWidget(note)

        self.filter_box = SearchLineEdit()
        self.filter_box.setPlaceholderText("Filter by rule name or application...")
        self.filter_box.textChanged.connect(self._apply_filter)
        layout.addWidget(self.filter_box)

        self.table = QTableWidget(0, 11)
        self.table.setHorizontalHeaderLabels(
            ["Name", "Application", "Direction", "Action", "Protocol", "Local Ports", "Remote Ports",
             "Enabled", "Source", "Type", "Group"]
        )
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        self.table.itemDoubleClicked.connect(self._on_row_double_clicked)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_context_menu)
        _configure_table_header(self.table)
        _hdr = self.table.horizontalHeader()  # sagefw-width-v1
        _hdr.resizeSection(1, _hdr.defaultSectionSize() * 4)
        layout.addWidget(self.table)

    def refresh(self, *_args, force: bool = True) -> None:
        import time as _time
        stale = (_time.monotonic() - _RULES_SHARED["time"]) > 5
        if force or _RULES_SHARED["rules"] is None or stale:
            _RULES_SHARED["rules"] = self.engine.list_rules(ours_only=False)
            _RULES_SHARED["time"] = _time.monotonic()
            GROUP_INDEX.update(_RULES_SHARED["rules"])
            for inst in list(_RULES_INSTANCES):
                inst._all_rules = _RULES_SHARED["rules"]
                if inst is not self:
                    inst._render()
        self._all_rules = _RULES_SHARED["rules"]
        self._render()

    def _render(self) -> None:
        query = self.filter_box.text().strip().lower()
        rows = []
        for r in self._all_rules:
            if self.direction is not None and r.direction != self.direction:
                continue
            label, color = classify_rule(r)
            group = resolve_group_name(getattr(r, "grouping", ""))
            proto = protocol_label(r.protocol)
            lports = ports_label(r.protocol, r.local_ports)
            rports = ports_label(r.protocol, r.remote_ports)
            if query and not (query in (r.name or "").lower()
                              or query in (r.application_path or "").lower()
                              or query in label.lower()
                              or query in group.lower()
                              or query in proto.lower()
                              or query in lports.lower()
                              or query in rports.lower()):
                continue
            rows.append((r, label, color, group, proto, lports, rports))

        def populate():
            self.table.setRowCount(len(rows))
            for i, (rule, label, color, group, proto, lports, rports) in enumerate(rows):
                direction = "IN" if rule.direction == DIR_IN else "OUT"
                action = "Allow" if rule.action == ACTION_ALLOW else "Block"
                source = "This app" if rule.is_ours else "Windows / other"
                values = [rule.name, rule.application_path or "(any)", direction, action,
                          proto, lports, rports,
                          "Yes" if rule.enabled else "No", source, label, group]
                tint = _QColor(color)
                tint.setAlpha(40)
                for col, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    if col == 3:
                        item.setForeground(ALLOW_COLOR if action == "Allow" else BLOCK_COLOR)
                    if col == 0:
                        item.setData(Qt.ItemDataRole.UserRole, rule)
                    if col in (0, 9):
                        item.setBackground(tint)
                    if col == 9:
                        item.setForeground(color)
                        font = _QFont(item.font())
                        font.setBold(True)
                        item.setFont(font)
                    self.table.setItem(i, col, item)

        _repopulate_preserving_sort(self.table, populate)

    def _on_context_menu(self, pos) -> None:
        item = self.table.itemAt(pos)
        if item is None:
            return
        row = item.row()
        self.table.selectRow(row)
        rule = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        if rule is None:
            return
        search_name = exe_name_from_path(rule.application_path) or (rule.name or "")
        menu = QMenu(self)
        google_action = menu.addAction(f'Search Google for "{search_name}"')
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen is google_action:
            search_google(search_name)

    def _apply_filter(self, _text: str) -> None:
        self._render()

    def _selected_rule(self) -> FirewallRule | None:
        selected = self.table.selectedItems()
        if not selected:
            return None
        row = selected[0].row()
        name_item = self.table.item(row, 0)
        return name_item.data(Qt.ItemDataRole.UserRole) if name_item else None

    def _on_selection_changed(self) -> None:
        rule = self._selected_rule()
        can_edit = rule is not None
        self.edit_btn.setEnabled(can_edit)
        self.delete_btn.setEnabled(can_edit)

    def _on_new_clicked(self) -> None:
        dialog = RuleEditorDialog(self.engine, existing_rule=None, parent=self)
        if self.direction is not None:
            dialog.direction_combo.setCurrentText("Inbound" if self.direction == DIR_IN else "Outbound")
            dialog._suggest_name()
        if dialog.exec() == QDialog.DialogCode.Accepted:
            InfoBar.success(title="Rule created", content="", duration=2500, parent=self.window())
            self.refresh()

    def _name_is_ambiguous(self, rule) -> bool:
        # The engine removes rules by NAME only, so a shared name could hit the wrong rule.
        count = sum(1 for r in self._all_rules if r.name == rule.name)
        if count > 1:
            QMessageBox.information(
                self, "Cannot safely change this rule",
                f"{count} rules share the name '{rule.name}'. SageFW removes and recreates "
                f"rules by name, so it cannot target just one of them without risking the "
                f"others.\n\nUse Windows Defender Firewall with Advanced Security (wf.msc) "
                f"for this rule.",
            )
            return True
        return False

    def _on_edit_clicked(self) -> None:
        rule = self._selected_rule()
        if not rule:
            return
        dialog = RuleEditorDialog(self.engine, existing_rule=rule, parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            InfoBar.success(title="Rule updated", content="", duration=2500, parent=self.window())
            self.refresh()

    def _on_row_double_clicked(self, _item) -> None:
        rule = self._selected_rule()
        if rule:
            self._on_edit_clicked()

    def _log_deleted_rule(self, rule) -> None:
        # Record what is being deleted (portable: inside the SageFW folder).
        try:
            import dataclasses, datetime, json
            if dataclasses.is_dataclass(rule):
                data = dataclasses.asdict(rule)
            else:
                data = dict(vars(rule))
            data = {k: (v if isinstance(v, (str, int, float, bool, type(None))) else str(v))
                    for k, v in data.items()}
            data["deleted_at"] = datetime.datetime.now().isoformat(timespec="seconds")
            here = Path(__file__).resolve().parent
            app_dir = here.parent if here.name.lower() == "ui" else here
            log_dir = app_dir / "data"
            log_dir.mkdir(parents=True, exist_ok=True)
            with open(log_dir / "deleted_rules_log.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps(data) + "\n")
        except Exception:
            pass

    def _on_delete_clicked(self) -> None:
        rule = self._selected_rule()
        if not rule:
            return
        if self._name_is_ambiguous(rule):
            return
        if rule.is_ours:
            message = (f"Delete rule '{rule.name}'?\n\nThis cannot be undone from here -- "
                       f"use a snapshot restore if you need it back.")
        else:
            message = (f"'{rule.name}' was NOT created by SageFW (it belongs to Windows or "
                       f"other software).\n\nDeleting it can break network features, and "
                       f"Windows will not recreate it automatically.\n\n"
                       f"Its details will be saved to data\\deleted_rules_log.jsonl first.\n\n"
                       f"Delete it anyway?")
        confirm = QMessageBox.question(
            self, "Delete rule", message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        if not rule.is_ours:
            self._log_deleted_rule(rule)
        self.engine.delete_rule(rule.name)
        InfoBar.success(title="Rule deleted", content=rule.name, duration=2500, parent=self.window())
        self.refresh()

if __name__ == "__main__":
    from firewall_engine import FirewallEngine as _FE

    app = QApplication(sys.argv)
    setTheme(Theme.DARK)

    engine = _FE()
    store = RuleStore()

    widget = RulesManagerWidget(engine, store=store)
    widget.setWindowTitle("Rules Manager -- standalone test")
    widget.resize(900, 600)
    widget.show()

    sys.exit(app.exec())

# sagefw-patch-v1

# sagefw-edit-all-v2

# sagefw-keepsettings-v1
