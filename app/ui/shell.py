"""
ui/shell.py

The main application window. Ties the previously-standalone UI pieces
(dashboard, rules manager) into one window with sidebar navigation, plus:

  - A system tray icon -- this app is meant to run persistently in the
    background, not sit as a foreground window you babysit. Closing the
    window (the X button) minimizes to tray instead of quitting; only
    the tray menu's "Exit" actually terminates the process.
  - A Ctrl+Q keyboard shortcut that ALSO quits, independent of the tray
    icon -- added after real-world testing showed a large batch of
    notification cards could grow tall enough to visually cover the tray
    icon, making it briefly unreachable and forcing a Task Manager kill.
    The notification panel's height is now capped (see
    notification_popup.py) so that shouldn't recur, but this shortcut is
    a deliberate second, independent way out regardless.
  - A Settings page wired to config.AppConfig (prompt timeout, focus-steal
    toggles) -- the first place those settings are actually user-editable
    rather than just code defaults.
  - Owns the NotificationPanel (from notification_popup.py) as a floating
    overlay that shows up regardless of which page is currently active in
    the shell -- it's not part of the page stack, it just floats on top.

This module does NOT construct the backend (RuleStore, FirewallEngine,
NotificationManager) -- those are created once in main.py and passed in,
keeping backend lifecycle management in one place.

Uses qfluentwidgets' FluentWindow, which provides the sidebar navigation
shell out of the box (Windows 11 Fluent style) rather than building that
scaffolding by hand.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor, QAction, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QApplication, QSystemTrayIcon, QMenu,
    QFormLayout,
)

from qfluentwidgets import (
    FluentWindow, FluentIcon, NavigationItemPosition, TitleLabel, SubtitleLabel,
    CaptionLabel, SwitchButton, SpinBox, PushButton, setTheme, Theme, InfoBar,
    InfoBarPosition,
)

sys.path.append(str(Path(__file__).resolve().parent.parent))  # allow importing core/*
from config import AppConfig
from firewall_engine import FirewallEngine, DIR_IN, DIR_OUT  # sagefw-groups-v1
from PyQt6.QtWidgets import QMessageBox  # sagefw-startup-v1
from rule_store import RuleStore
from notification_manager import NotificationManager

from dashboard import TrafficFeedWidget, TrafficBridge
from dashboard import TidyUpDialog  # sagefw-cleanup-v1
from backup_restore_ui import BackupRestoreWidget  # sagefw-backup-v1
from firewall_engine import FirewallRule  # sagefw-dupes-v1
from PyQt6.QtWidgets import QListWidget, QListWidgetItem, QDialogButtonBox
from import_export import tidy_up_orphaned_rules
import os
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QDialog, QMessageBox
from rules_manager import RulesManagerWidget
from connection_monitor import ConnectionMonitor
from notification_popup import NotificationPanel, apply_fluent_theme


# sagefw-patch-v1
from PyQt6.QtCore import QRectF
from PyQt6.QtGui import QPainterPath, QLinearGradient, QFont


def _make_app_icon() -> QIcon:
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        pm = QPixmap(size, size)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.scale(size / 256, size / 256)

        shield = QPainterPath()
        shield.moveTo(128, 12)
        shield.lineTo(228, 44)
        shield.cubicTo(228, 150, 190, 215, 128, 244)
        shield.cubicTo(66, 215, 28, 150, 28, 44)
        shield.closeSubpath()

        grad = QLinearGradient(0, 0, 0, 256)
        grad.setColorAt(0.0, QColor("#46b0ff"))
        grad.setColorAt(1.0, QColor("#1b46c8"))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(grad)
        p.drawPath(shield)

        p.save()
        p.setClipPath(shield)
        p.setBrush(QColor(255, 255, 255, 38))
        p.drawRect(QRectF(0, 0, 128, 256))
        p.restore()

        p.setPen(QColor("white"))
        p.setFont(QFont("Segoe UI", 118, QFont.Weight.Black))
        p.drawText(QRectF(0, 36, 256, 180), Qt.AlignmentFlag.AlignCenter, "S")
        p.end()
        icon.addPixmap(pm)
    return icon


class DashboardPage(QWidget):
    """Live traffic feed page. Owns its own full ConnectionMonitor
    (allowed + blocked), separate from NotificationManager's
    blocked-only monitor."""

    def __init__(self, engine=None, parent=None):
        super().__init__(parent)
        self.setObjectName("dashboardPage")
        layout = QVBoxLayout(self)
        layout.addWidget(TitleLabel("Dashboard"))

        self.feed = TrafficFeedWidget(engine=engine)
        layout.addWidget(self.feed)

        self._monitor = ConnectionMonitor(blocked_only=False)
        self.bridge = TrafficBridge()
        self.bridge.event_ready.connect(self.feed.add_event)
        self._monitor.on_event(self.bridge.event_ready.emit)
        self._monitor.start()

    def stop(self) -> None:
        self._monitor.stop()


class RulesPage(QWidget):
    def __init__(self, engine: FirewallEngine, store: RuleStore, direction=None,
                 title="Rules", object_name="rulesPage", parent=None):
        super().__init__(parent)
        self.setObjectName(object_name)
        layout = QVBoxLayout(self)
        layout.addWidget(TitleLabel(title))
        self.manager_widget = RulesManagerWidget(engine, store=store, direction=direction)
        layout.addWidget(self.manager_widget)


class DuplicatesDialog(QDialog):
    def __init__(self, ops, parent=None):
        super().__init__(parent)
        from qfluentwidgets import PrimaryPushButton
        self.setWindowTitle("Remove Duplicate Rules")
        self.setMinimumSize(660, 480)
        self.ops = ops
        total = sum(op["removes"] for op in ops)
        layout = QVBoxLayout(self)
        layout.addWidget(SubtitleLabel(f"Found {total} duplicate rule(s) in {len(ops)} group(s):"))
        note = CaptionLabel(
            "Duplicates have identical settings (program, direction, action, ports, addresses, "
            "profiles and more). One copy of each is always kept. Untick a group to leave it alone."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        self.list_widget = QListWidget()
        for i, op in enumerate(ops):
            how = "same name: one copy is kept" if op["type"] == "recreate" else f"kept copy: {op['keeper_name']}"
            text = f"{op['name']}   (removes {op['removes']})\n   {how}\n   program: {op['path'] or '(any)'}"
            item = QListWidgetItem(text)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            item.setData(Qt.ItemDataRole.UserRole, i)
            self.list_widget.addItem(item)
        layout.addWidget(self.list_widget)
        row = QHBoxLayout()
        all_btn = PushButton("Select All")
        all_btn.clicked.connect(lambda: self._set_all(True))
        none_btn = PushButton("Select None")
        none_btn.clicked.connect(lambda: self._set_all(False))
        row.addWidget(all_btn)
        row.addWidget(none_btn)
        row.addStretch()
        layout.addLayout(row)
        buttons = QDialogButtonBox()
        ok_btn = PrimaryPushButton("Remove Selected")
        ok_btn.clicked.connect(self.accept)
        cancel_btn = PushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        buttons.addButton(ok_btn, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.addButton(cancel_btn, QDialogButtonBox.ButtonRole.RejectRole)
        layout.addWidget(buttons)

    def _set_all(self, checked):
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        for i in range(self.list_widget.count()):
            self.list_widget.item(i).setCheckState(state)

    def selected_ops(self):
        chosen = []
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                chosen.append(self.ops[item.data(Qt.ItemDataRole.UserRole)])
        return chosen


class OrphanCleanupWidget(QWidget):
    rules_changed = pyqtSignal()

    def __init__(self, engine, store, parent=None):
        super().__init__(parent)
        self.engine = engine
        self.store = store
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(SubtitleLabel("Maintenance"))
        note = CaptionLabel(
            "Finds firewall rules that point to programs (.exe files) that no longer exist on "
            "disk. You review the list before anything is removed, and a safety snapshot is "
            "taken first. Rules on drives that are not connected, network paths, and rules "
            "sharing a name with a rule for a program that still exists are skipped."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        row = QHBoxLayout()
        self.btn = PushButton("Remove rules for missing programs...")
        self.btn.clicked.connect(self._on_clicked)
        row.addWidget(self.btn)
        self.dup_btn = PushButton("Remove duplicate rules...")
        self.dup_btn.clicked.connect(self._on_duplicates_clicked)
        row.addWidget(self.dup_btn)
        row.addStretch()
        layout.addLayout(row)
        dup_note = CaptionLabel(
            "Duplicates are rules with identical settings. One copy of each is kept; you review the list first."
        )
        dup_note.setWordWrap(True)
        layout.addWidget(dup_note)

    @staticmethod
    def _is_missing(path) -> bool:
        raw = (path or "").strip().strip('"')
        if not raw:
            return False
        expanded = os.path.expandvars(raw)
        if not os.path.isabs(expanded):
            return False
        drive, _ = os.path.splitdrive(expanded)
        if not drive or drive.startswith("\\\\"):
            return False
        if not os.path.exists(drive + "\\"):
            return False
        return not os.path.exists(expanded)

    @staticmethod
    def _log_deleted(rules, reason="program no longer exists") -> None:
        try:
            import dataclasses, datetime, json
            here = Path(__file__).resolve().parent
            app_dir = here.parent if here.name.lower() == "ui" else here
            log_dir = app_dir / "data"
            log_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.datetime.now().isoformat(timespec="seconds")
            with open(log_dir / "deleted_rules_log.jsonl", "a", encoding="utf-8") as fh:
                for r in rules:
                    data = dataclasses.asdict(r) if dataclasses.is_dataclass(r) else dict(vars(r))
                    data = {k: (v if isinstance(v, (str, int, float, bool, type(None))) else str(v))
                            for k, v in data.items()}
                    data["deleted_at"] = stamp
                    data["reason"] = reason
                    fh.write(json.dumps(data) + "\n")
        except Exception:
            pass

    _EXTRA_PROPS = ("LocalAddresses", "IcmpTypesAndCodes", "Interfaces", "LocalAppPackageId",
                    "LocalUserOwner", "LocalUserAuthorizedList", "RemoteUserAuthorizedList",
                    "RemoteMachineAuthorizedList", "SecureFlags", "EdgeTraversalOptions")

    @staticmethod
    def _norm_extra(val) -> str:
        if val is None:
            return ""
        if isinstance(val, (list, tuple)):
            return ", ".join(sorted(str(v) for v in val))
        return str(val).strip()

    @staticmethod
    def _signature(rule, extras) -> tuple:
        def norm(s):
            return (s or "").strip().lower()
        path = os.path.normpath(os.path.expandvars(rule.application_path)).lower() if rule.application_path else ""
        return (path, norm(rule.service_name), rule.protocol, norm(rule.local_ports), norm(rule.remote_ports),
                norm(rule.remote_addresses), rule.direction, rule.action, bool(rule.enabled), rule.profiles,
                norm(rule.interface_types), bool(rule.edge_traversal), norm(rule.grouping)) + tuple(extras)

    @staticmethod
    def _lossless(rec) -> bool:
        # Recreating a rule through SageFW only keeps what FirewallRule models, so it is only
        # allowed when every setting SageFW cannot copy is at its default.
        return True  # verified copies are lossless (engine.replace_copies_with_one)

    def _scan(self):
        records = []
        for com_rule in self.engine._policy.Rules:
            try:
                rule = FirewallRule.from_com(com_rule, include_extra=True)
                extras = []
                for prop in self._EXTRA_PROPS:
                    try:
                        extras.append(self._norm_extra(getattr(com_rule, prop)))
                    except Exception:
                        extras.append("")
                records.append({"rule": rule, "extras": extras, "sig": self._signature(rule, extras)})
            except Exception:
                continue
        return records

    @staticmethod
    def _plan(records):
        by_sig = {}
        for rec in records:
            by_sig.setdefault(rec["sig"], []).append(rec)
        dupe_ids, keeper_of = set(), {}
        for recs in by_sig.values():
            for dup in recs[1:]:
                dupe_ids.add(id(dup))
                keeper_of[id(dup)] = recs[0]
        by_name = {}
        for rec in records:
            by_name.setdefault(rec["rule"].name, []).append(rec)
        ops, skipped = [], 0
        for name, recs in by_name.items():
            mine = [r for r in recs if id(r) in dupe_ids]
            if not mine:
                continue
            kept = [r for r in recs if id(r) not in dupe_ids]
            path = mine[0]["rule"].application_path
            if not kept:
                ops.append({"type": "delete", "name": name, "removes": len(recs),
                            "keeper_name": keeper_of[id(mine[0])]["rule"].name, "path": path,
                            "rules": [r["rule"] for r in recs]})
            elif len({r["sig"] for r in recs}) == 1 and OrphanCleanupWidget._lossless(recs[0]):
                ops.append({"type": "recreate", "name": name, "removes": len(mine), "keeper_name": name,
                            "path": path, "keeper_rule": kept[0]["rule"], "rules": [r["rule"] for r in mine]})
            else:
                skipped += len(mine)
        return ops, skipped

    def _on_duplicates_clicked(self) -> None:
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            records = self._scan()
            ops, skipped = self._plan(records)
        except Exception as exc:
            QApplication.restoreOverrideCursor()
            QMessageBox.critical(self, "Could not scan rules", str(exc))
            return
        QApplication.restoreOverrideCursor()
        before = len(records)

        if not ops:
            extra = f" ({skipped} skipped: removing them would also remove a different rule with the same name)" if skipped else ""
            InfoBar.success(title="No duplicates", content="No removable duplicate rules were found" + extra + ".",
                            position=InfoBarPosition.TOP, duration=4000, parent=self.window())
            return

        dialog = DuplicatesDialog(ops, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        chosen = dialog.selected_ops()
        if not chosen:
            return

        snap = None
        try:
            from import_export import take_snapshot
            snap = take_snapshot(self.engine, self.store, label="before-remove-duplicates")
        except Exception:
            snap = None
        for op in chosen:
            self._log_deleted(op["rules"], reason=f"duplicate of {op['keeper_name']}")

        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            failed = []
            for op in chosen:
                try:
                    if op["type"] == "recreate":
                        self.engine.replace_copies_with_one(op["keeper_rule"])
                    else:
                        tries = 0
                        while tries < 100 and self.engine.delete_rule(op["name"]):
                            tries += 1
                except Exception as exc:
                    failed.append(f"{op['name']}: {exc}")
            after = len(self.engine.list_rules(ours_only=False))
        except Exception as exc:
            QApplication.restoreOverrideCursor()
            QMessageBox.critical(self, "Could not remove duplicates", str(exc))
            self.rules_changed.emit()
            return
        QApplication.restoreOverrideCursor()
        if failed:
            QMessageBox.warning(self, "Some groups were not changed", "\n".join(failed[:10]))
        note = f"safety snapshot #{snap} taken first" if snap else "no snapshot taken"
        more = f" {skipped} skipped (shared names)." if skipped else ""
        InfoBar.success(title="Duplicates removed", content=f"Removed {max(before - after, 0)} duplicate rule(s); {note}.{more}",
                        position=InfoBarPosition.TOP, duration=6000, parent=self.window())
        self.rules_changed.emit()

    def _on_clicked(self) -> None:
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            all_rules = self.engine.list_rules(ours_only=False)
            missing = [r for r in all_rules if self._is_missing(r.application_path)]
        finally:
            QApplication.restoreOverrideCursor()
        missing_ids = {id(r) for r in missing}
        shared_names = {r.name for r in all_rules if id(r) not in missing_ids}
        candidates = [r for r in missing if r.name not in shared_names]
        skipped = len(missing) - len(candidates)

        if not candidates:
            extra = f" ({skipped} skipped because their name is shared with a working rule)" if skipped else ""
            InfoBar.success(title="Nothing to remove",
                            content="No rules point to missing programs" + extra + ".",
                            position=InfoBarPosition.TOP, duration=4000, parent=self.window())
            return

        dialog = TidyUpDialog(candidates, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        names = set(dialog.selected_rule_names())
        if not names:
            return
        chosen = [r for r in candidates if r.name in names]
        self._log_deleted(chosen)
        try:
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            if self.store is not None:
                summary = tidy_up_orphaned_rules(self.engine, self.store, sorted(names))
                removed = summary["rules_removed"]
                note = f"safety snapshot #{summary['snapshot_id']} taken first"
            else:
                removed = self.engine.delete_rules(sorted(names))
                note = "no snapshot (no database available)"
        except Exception as exc:
            QApplication.restoreOverrideCursor()
            QMessageBox.critical(self, "Could not remove rules", str(exc))
            return
        QApplication.restoreOverrideCursor()
        more = f" {skipped} more skipped (shared names)." if skipped else ""
        InfoBar.success(title="Rules removed", content=f"Removed {removed} rule(s); {note}.{more}",
                        position=InfoBarPosition.TOP, duration=6000, parent=self.window())
        self.rules_changed.emit()


class SettingsPage(QWidget):
    """Wires the previously code-only config.AppConfig settings to real
    controls: prompt timeout, focus-steal toggles, theme."""

    def __init__(self, config: AppConfig, parent=None, engine=None, store=None):
        super().__init__(parent)
        self.setObjectName("settingsPage")
        self.config = config

        layout = QVBoxLayout(self)
        layout.addWidget(TitleLabel("Settings"))
        layout.addWidget(CaptionLabel("Changes apply immediately."))

        form_widget = QWidget()
        form = QFormLayout(form_widget)
        form.setSpacing(14)

        self.timeout_spin = SpinBox()
        self.timeout_spin.setRange(5, 300)
        self.timeout_spin.setValue(int(self.config.prompt_timeout_seconds))
        self.timeout_spin.setSuffix(" seconds")
        self.timeout_spin.valueChanged.connect(self._on_timeout_changed)
        form.addRow("Auto-block prompt timeout:", self.timeout_spin)

        self.focus_in_switch = SwitchButton()
        self.focus_in_switch.setChecked(self.config.grab_focus_inbound)
        self.focus_in_switch.checkedChanged.connect(self._on_focus_in_changed)
        form.addRow("Grab focus for new INBOUND connections:", self.focus_in_switch)

        self.focus_out_switch = SwitchButton()
        self.focus_out_switch.setChecked(self.config.grab_focus_outbound)
        self.focus_out_switch.checkedChanged.connect(self._on_focus_out_changed)
        form.addRow("Grab focus for new OUTBOUND connections:", self.focus_out_switch)

        self.theme_switch = SwitchButton()
        self.theme_switch.setChecked(self.config.theme == "dark")
        self.theme_switch.setOnText("Dark")
        self.theme_switch.setOffText("Light")
        self.theme_switch.checkedChanged.connect(self._on_theme_changed)
        form.addRow("Theme:", self.theme_switch)

        layout.addWidget(form_widget)
        if engine is not None and store is not None:
            self.cleanup_widget = OrphanCleanupWidget(engine, store)
            layout.addWidget(self.cleanup_widget)
            self.backup_widget = BackupRestoreWidget(engine)
            self.backup_widget.store = store
            layout.addWidget(self.backup_widget)
        layout.addStretch()


    def _on_timeout_changed(self, value: int) -> None:
        self.config.prompt_timeout_seconds = value

    def _on_focus_in_changed(self, checked: bool) -> None:
        self.config.grab_focus_inbound = checked

    def _on_focus_out_changed(self, checked: bool) -> None:
        self.config.grab_focus_outbound = checked

    def _on_theme_changed(self, checked: bool) -> None:
        theme_name = "dark" if checked else "light"
        self.config.theme = theme_name
        apply_fluent_theme(dark=checked)


class ShellWindow(FluentWindow):
    def __init__(self, engine: FirewallEngine, store: RuleStore,
                 manager: NotificationManager, config: AppConfig, parent=None):
        super().__init__(parent)
        self.engine = engine
        self.store = store
        self.manager = manager
        self.config = config

        self.setWindowTitle("SageFW")
        self.resize(1380, 780)
        self.setWindowIcon(_make_app_icon())

        self.dashboard_page = DashboardPage(engine)
        self.rules_page_in = RulesPage(engine, store, direction=DIR_IN, title="Inbound Rules", object_name="rulesPageInbound")
        self.rules_page_out = RulesPage(engine, store, direction=DIR_OUT, title="Outbound Rules", object_name="rulesPageOutbound")
        self.rules_page = self.rules_page_in
        self.settings_page = SettingsPage(config, engine=engine, store=store)
        _rules_page = getattr(self, "rules_page_in", None) or self.rules_page
        self.settings_page.cleanup_widget.rules_changed.connect(_rules_page.manager_widget.refresh)
        self.settings_page.backup_widget.rules_changed.connect(_rules_page.manager_widget.refresh)
        self.dashboard_page.feed.rule_created.connect(self.rules_page_in.manager_widget.refresh)

        self.addSubInterface(self.dashboard_page, FluentIcon.HOME, "Dashboard")
        self.addSubInterface(self.rules_page_in, getattr(FluentIcon, "DOWN", FluentIcon.APPLICATION), "Inbound Rules")
        self.addSubInterface(self.rules_page_out, getattr(FluentIcon, "UP", FluentIcon.APPLICATION), "Outbound Rules")
        self.addSubInterface(self.settings_page, FluentIcon.SETTING, "Settings",
                              position=NavigationItemPosition.BOTTOM)

        self.notification_panel = NotificationPanel(self.manager)

        self._setup_tray_icon()
        self._setup_shortcuts()

    # ---------- keyboard shortcuts (independent of the tray icon) ----------

    def _setup_shortcuts(self) -> None:
        quit_shortcut = QShortcut(QKeySequence("Ctrl+Q"), self)
        quit_shortcut.activated.connect(self._quit_app)

    # ---------- tray icon / minimize-to-tray behavior ----------

    def _setup_tray_icon(self) -> None:
        self.tray_icon = QSystemTrayIcon(_make_app_icon(), self)
        self.tray_icon.setToolTip("SageFW (Ctrl+Q to quit from the main window)")

        menu = QMenu()
        show_action = QAction("Show", self)
        show_action.triggered.connect(self._show_and_raise)
        menu.addAction(show_action)

        menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self._quit_app)
        menu.addAction(exit_action)

        self.tray_icon.setContextMenu(menu)
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.show()

    def _on_tray_activated(self, reason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._show_and_raise()

    def _show_and_raise(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _quit_app(self) -> None:
        self.dashboard_page.stop()
        self.manager.stop()
        self.store.close()
        self.tray_icon.hide()
        QApplication.quit()

    def _ask_close_action(self) -> str:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Close SageFW")
        box.setText("Do you want to exit SageFW or keep it running in the system tray?")
        box.setInformativeText(
            "While it runs in the tray, SageFW keeps watching connections and prompting you about "
            "new apps. If you exit, those prompts stop (your firewall rules stay in force)."
        )
        tray_btn = box.addButton("Minimise to tray", QMessageBox.ButtonRole.AcceptRole)
        exit_btn = box.addButton("Exit SageFW", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(tray_btn)
        box.exec()
        clicked = box.clickedButton()
        if clicked is exit_btn:
            return "exit"
        if clicked is tray_btn:
            return "tray"
        return "cancel"

    def closeEvent(self, event) -> None:
        choice = self._ask_close_action()
        if choice == "exit":
            event.accept()
            self._quit_app()
            return
        event.ignore()
        if choice == "tray":
            self.hide()
            self.tray_icon.showMessage(
                "SageFW", "Still running in the background. Ctrl+Q to quit.",
                QSystemTrayIcon.MessageIcon.Information, 2000,
            )

if __name__ == "__main__":
    # Standalone smoke test -- builds a real backend (admin required) so
    # the shell can be exercised end-to-end, same as main.py will do.
    app = QApplication(sys.argv)
    setTheme(Theme.DARK)

    store = RuleStore()
    engine = FirewallEngine()
    config = AppConfig(store)
    manager = NotificationManager(
        store, engine,
        prompt_timeout_seconds=config.prompt_timeout_seconds,
        grab_focus_inbound=config.grab_focus_inbound,
        grab_focus_outbound=config.grab_focus_outbound,
    )
    manager.start()

    window = ShellWindow(engine, store, manager, config)
    window.show()

    sys.exit(app.exec())
