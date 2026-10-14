"""
backup_restore_ui.py -- Settings > Backup & Restore.

Back up now:      saves every rule (all settings) + per-profile defaults to a JSON file, plus a
                  Windows-native .wfw policy file, in <app folder>/data/backups.
Restore:          pick a SageFW .json backup (restore missing rules only, or make the rules match
                  the backup) or a Windows .wfw policy file (replaces the whole policy). A backup
                  of the current state is always saved first, so a restore can itself be undone.
"""
from __future__ import annotations

import os

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (QApplication, QCheckBox, QDialog, QFileDialog, QHBoxLayout, QMessageBox,
                             QVBoxLayout, QWidget)
from qfluentwidgets import (CaptionLabel, ComboBox, InfoBar, InfoBarPosition, PrimaryPushButton,
                            PushButton, SubtitleLabel)

import backup_restore as br


class RestoreDialog(QDialog):
    def __init__(self, backup: dict, plans: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Restore from Backup")
        self.setMinimumWidth(560)
        self.plans = plans
        layout = QVBoxLayout(self)
        layout.addWidget(SubtitleLabel("Restore from backup"))
        when = (backup.get("created") or "unknown date").replace("T", " ")
        where = backup.get("computer") or "this PC"
        layout.addWidget(CaptionLabel(f"Backup taken {when} on {where}: {len(backup.get('_rules', []))} rule(s)."))

        self.combo = ComboBox()
        self.combo.addItems(["Restore missing rules only (safe)", "Make rules match the backup (replace)"])
        self.combo.currentIndexChanged.connect(self._update_summary)
        layout.addWidget(self.combo)

        self.summary = CaptionLabel("")
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)

        self.defaults_check = QCheckBox("Also restore each profile's firewall on/off state and default inbound/outbound action")
        has_defaults = bool(backup.get("defaults"))
        self.defaults_check.setEnabled(has_defaults)
        layout.addWidget(self.defaults_check)

        layout.addWidget(CaptionLabel("A backup of the current state is saved first, so this can be undone."))

        row = QHBoxLayout()
        row.addStretch()
        cancel = PushButton("Cancel")
        cancel.clicked.connect(self.reject)
        ok = PrimaryPushButton("Restore")
        ok.clicked.connect(self.accept)
        row.addWidget(cancel)
        row.addWidget(ok)
        layout.addLayout(row)
        self._update_summary()

    def mode(self) -> str:
        return "missing" if self.combo.currentIndex() == 0 else "replace"

    def restore_defaults(self) -> bool:
        return self.defaults_check.isEnabled() and self.defaults_check.isChecked()

    def _update_summary(self) -> None:
        mode = self.mode()
        s = br.summarize(self.plans[mode])
        if mode == "missing":
            text = (f"Will recreate {s['create']} rule(s) that are in the backup but not on this PC. "
                    f"Nothing is deleted and existing rules are not changed.")
        else:
            text = (f"Will make {s['groups']} rule name(s) match the backup: remove {s['delete']} current "
                    f"rule(s) and create {s['create']}. Rules added since the backup are removed and "
                    f"changed rules go back to their backed-up settings.")
        self.summary.setText(text)


class BackupRestoreWidget(QWidget):
    rules_changed = pyqtSignal()

    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine = engine
        self.store = None  # set by the Settings page so the reset can also clear saved decisions
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(SubtitleLabel("Backup & Restore"))
        note = CaptionLabel(
            "Back up every firewall rule with all of its settings, then restore them later. Backups "
            "are saved in the data\\backups folder next to the app. Each backup also includes a "
            "Windows policy file (.wfw)."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        row = QHBoxLayout()
        self.backup_btn = PrimaryPushButton("Back up now")
        self.backup_btn.clicked.connect(self._on_backup)
        self.restore_btn = PushButton("Restore from backup...")
        self.restore_btn.clicked.connect(self._on_restore)
        self.folder_btn = PushButton("Open backup folder")
        self.folder_btn.clicked.connect(self._on_open_folder)
        self.reset_btn = PushButton("Reset to Windows defaults...")
        self.reset_btn.clicked.connect(self._on_reset)
        for btn in (self.backup_btn, self.restore_btn, self.folder_btn, self.reset_btn):
            row.addWidget(btn)
        row.addStretch()
        layout.addLayout(row)

    # ---- helpers ----
    @staticmethod
    def _busy(on: bool) -> None:
        if on:
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        else:
            QApplication.restoreOverrideCursor()

    def _toast(self, title: str, content: str, ms: int = 6000) -> None:
        InfoBar.success(title=title, content=content, position=InfoBarPosition.TOP,
                        duration=ms, parent=self.window())

    def _forget_decisions(self) -> int:
        # SageFW remembers "always allow" choices and silently re-creates those rules when it next sees
        # the app blocked, so a clean slate must forget them too.
        store = getattr(self, "store", None)
        if store is None:
            return 0
        removed = 0
        try:
            conn = store._conn
            tables = [row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%decision%'").fetchall()]
            for table in tables:
                removed += max(conn.execute(f'DELETE FROM "{table}"').rowcount, 0)
            conn.execute("DELETE FROM settings WHERE key LIKE 'session_rule::%'")
            conn.commit()
        except Exception:
            pass
        return removed

    def _on_reset(self) -> None:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Reset firewall to Windows defaults")
        box.setText(
            "This resets the Windows Firewall to its out-of-box state for ALL profiles "
            "(Domain, Private and Public):\n\n"
            "  - every custom rule is deleted, including rules SageFW created and rules added by "
            "installed programs\n"
            "  - Windows' built-in rules are restored\n"
            "  - each profile's on/off state and default actions go back to Windows' defaults "
            "(lockdown mode ends)\n\n"
            "Rules delivered by Group Policy are managed separately. A full backup of the current "
            "state is saved first, and you can restore it from this page.")
        forget = QCheckBox("Also forget SageFW's saved Allow/Block decisions (recommended: otherwise it "
                           "may quietly recreate those Allow rules later)")
        forget.setChecked(True)
        forget.setEnabled(self.store is not None)
        box.setCheckBox(forget)
        go = box.addButton("Reset", QMessageBox.ButtonRole.DestructiveRole)
        cancel = box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(cancel)
        box.exec()
        if box.clickedButton() is not go:
            return
        self._busy(True)
        try:
            pre = br.create_backup(self.engine, label="pre-reset")
        except Exception as exc:
            self._busy(False)
            QMessageBox.critical(self, "Backup failed", f"Nothing was changed.\n\n{exc}")
            return
        try:
            self.engine.reset_to_defaults()
        except Exception as exc:
            self._busy(False)
            QMessageBox.critical(self, "Reset failed", f"{exc}\n\nYour backup is saved as {pre['json'].name}.")
            self.rules_changed.emit()
            return
        forgotten = self._forget_decisions() if forget.isChecked() else 0
        self._busy(False)
        extra = "" if pre["wfw"] else " (the Windows policy file could not be created, but the JSON backup is complete)"
        memory = " Saved decisions cleared." if forget.isChecked() and self.store is not None else ""
        self._toast("Firewall reset to defaults",
                    f"All profiles reset.{memory} Previous state saved as {pre['json'].name}{extra}.", 8000)
        self.rules_changed.emit()

    # ---- actions ----
    def _on_open_folder(self) -> None:
        try:
            os.startfile(str(br.default_backup_dir()))  # Windows only
        except Exception as exc:
            QMessageBox.information(self, "Backup folder", f"{br.default_backup_dir()}\n\n({exc})")

    def _on_backup(self) -> None:
        self._busy(True)
        try:
            result = br.create_backup(self.engine)
        except Exception as exc:
            self._busy(False)
            QMessageBox.critical(self, "Backup failed", str(exc))
            return
        self._busy(False)
        extra = "" if result["wfw"] else " (the Windows policy file could not be created)"
        self._toast("Backup saved", f"{result['rules']} rules saved to {result['json'].name}{extra}")

    def _on_restore(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose a backup to restore", str(br.default_backup_dir()),
            "SageFW backup (*.json);;Windows firewall policy (*.wfw)")
        if not path:
            return
        if path.lower().endswith(".wfw"):
            self._restore_native(path)
        else:
            self._restore_json(path)

    def _restore_native(self, path: str) -> None:
        answer = QMessageBox.warning(
            self, "Restore Windows policy file",
            "Restoring a Windows policy file REPLACES the entire Windows Firewall configuration "
            "(every rule and setting) with the contents of the file. Anything created since that "
            "backup will be lost.\n\nA SageFW backup of the current state is saved first.\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._busy(True)
        try:
            pre = br.create_backup(self.engine, label="pre-restore")
            ok, message = br.import_native(path)
        except Exception as exc:
            self._busy(False)
            QMessageBox.critical(self, "Restore failed", str(exc))
            return
        self._busy(False)
        if not ok:
            QMessageBox.critical(self, "Restore failed", message or "Windows rejected the policy file.")
            return
        self._toast("Policy restored", f"Windows policy file imported. Previous state saved as {pre['json'].name}.")
        self.rules_changed.emit()

    def _restore_json(self, path: str) -> None:
        try:
            backup = br.load_backup(path)
        except Exception as exc:
            QMessageBox.critical(self, "Cannot read backup", str(exc))
            return
        self._busy(True)
        try:
            current = self.engine.list_rules(ours_only=False, include_extra=True)
        except Exception as exc:
            self._busy(False)
            QMessageBox.critical(self, "Cannot read current rules", str(exc))
            return
        self._busy(False)
        plans = {m: br.plan_restore(current, backup["_rules"], m) for m in ("missing", "replace")}
        dialog = RestoreDialog(backup, plans, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        mode, restore_defaults = dialog.mode(), dialog.restore_defaults()
        actions = plans[mode]
        if not actions and not restore_defaults:
            self._toast("Nothing to restore", "The current rules already match the backup.", 4000)
            return
        self._busy(True)
        try:
            pre = br.create_backup(self.engine, label="pre-restore")
            result = br.execute_restore(self.engine, actions)
            problems = self.engine.set_policy_defaults(backup.get("defaults", {})) if restore_defaults else []
            mismatched = br.verify_restore(self.engine, actions, backup["_rules"])
        except Exception as exc:
            self._busy(False)
            QMessageBox.critical(self, "Restore failed", str(exc))
            self.rules_changed.emit()
            return
        self._busy(False)
        self._toast("Restore finished",
                    f"Created {result['created']} and removed {result['deleted']} rule(s). "
                    f"Previous state saved as {pre['json'].name}.")
        issues = [f"{n}: {e}" for n, e in result["failed"]]
        issues += [f"{n}: restored, but not identical to the backup" for n in mismatched if n not in dict(result["failed"])]
        issues += problems
        if issues:
            QMessageBox.warning(self, "Restore finished with problems",
                                "These items need attention:\n\n  - " + "\n  - ".join(issues[:12])
                                + ("\n  - ..." if len(issues) > 12 else "")
                                + f"\n\nYour previous state is saved as {pre['json'].name} "
                                  f"(and a .wfw file) in the backup folder.")
        self.rules_changed.emit()
