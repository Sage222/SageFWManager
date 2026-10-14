"""
ui/dashboard.py

The "see what's going on before you touch anything" screen. Two parts:

  1. Live traffic feed -- a scrolling table of EVERY connection (allowed
     AND blocked), most recent first by default, color-coded green/red.
     Uses its own ConnectionMonitor(blocked_only=False) -- deliberately
     separate from NotificationManager's blocked-only monitor, since this
     view needs the full picture, not just decision-worthy events.
  2. A read-only rules overview table, pulled directly from
     FirewallEngine.list_rules() -- every current native Windows Firewall
     rule (not just ones this app created), searchable, with a manual
     refresh button, PLUS a "Tidy Up" button that finds and (with
     confirmation) removes rules pointing at applications that no longer
     exist on disk -- common cruft left behind by uninstalled software
     that Windows itself never cleans up.

Both tables support click-to-sort on any column header and freely
drag-resizable column widths (see _configure_table_header /
_repopulate_preserving_sort below for how live-updating tables keep an
active sort intact across refreshes instead of resetting to insertion
order every time).

Threading: ConnectionMonitor's callback fires on a background thread.
As with notification_popup.py, a small QObject bridge marshals events
onto the Qt main thread safely via signals before touching any widget.
"""

from __future__ import annotations

import collections
import sys
from pathlib import Path

from PyQt6.QtCore import Qt, QObject, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QApplication, QTableWidget,
    QTableWidgetItem, QHeaderView, QSplitter, QMainWindow, QDialog,
    QListWidget, QListWidgetItem, QDialogButtonBox,
)

from qfluentwidgets import (
    TitleLabel, SubtitleLabel, CaptionLabel, PushButton, PrimaryPushButton,
    SearchLineEdit, setTheme, Theme, InfoBar, InfoBarPosition,
)

sys.path.append(str(Path(__file__).resolve().parent.parent))  # allow importing core/*
from connection_monitor import ConnectionEvent, ConnectionMonitor
from app_resolver import AppInfo, resolve_app
from port_services import describe_port
from firewall_engine import FirewallEngine, FirewallRule
from rule_store import RuleStore
from import_export import find_orphaned_rules, tidy_up_orphaned_rules

# sagefw-patch-v1
from PyQt6.QtWidgets import QMenu
from qfluentwidgets import FluentIcon

# sagefw-google-v1
import ntpath as _ntpath
import urllib.parse as _urlparse
import webbrowser as _webbrowser


def exe_name_from_path(path):
    # 'C:\\Windows\\System32\\svchost.exe' -> 'svchost.exe'
    return _ntpath.basename(str(path or "").replace("/", "\\")).strip()


def search_google(text):
    text = (text or "").strip()
    if text:
        _webbrowser.open("https://www.google.com/search?q=" + _urlparse.quote_plus(text))


# sagefw-groups-v1
# ---- rule groups: readable names + traffic-to-group matching (SageFW) ----
import ctypes as _ct
import os as _os
import re as _re

_GROUP_NAME_CACHE = {}
_DEVICE_MAP = None


def resolve_group_name(raw):
    # Windows often stores group names as resource strings, e.g. "@FirewallAPI.dll,-80200".
    raw = (raw or "").strip()
    if not raw or not raw.startswith("@"):
        return raw
    if raw in _GROUP_NAME_CACHE:
        return _GROUP_NAME_CACHE[raw]
    text = raw
    try:
        buf = _ct.create_unicode_buffer(512)
        if _ct.windll.shlwapi.SHLoadIndirectStringW(raw, buf, len(buf), None) == 0 and buf.value:
            text = buf.value
    except Exception:
        pass
    _GROUP_NAME_CACHE[raw] = text
    return text


def _device_map():
    global _DEVICE_MAP
    if _DEVICE_MAP is None:
        found = {}
        try:
            import string
            buf = _ct.create_unicode_buffer(1024)
            for letter in string.ascii_uppercase:
                if _ct.windll.kernel32.QueryDosDeviceW(f"{letter}:", buf, len(buf)):
                    found[buf.value.lower()] = f"{letter}:"
        except Exception:
            pass
        _DEVICE_MAP = found
    return _DEVICE_MAP


def _norm_path(path):
    path = (path or "").strip().strip('"')
    if not path:
        return ""
    path = _os.path.expandvars(path).replace("/", "\\")
    low = path.lower()
    if low.startswith("\\device\\"):
        for dev, drive in _device_map().items():
            if low.startswith(dev + "\\"):
                path = drive + path[len(dev):]
                break
    return _os.path.normpath(path).lower()


def _port_in_spec(spec, port):
    spec = (spec or "*").strip()
    if spec in ("", "*"):
        return True
    try:
        port = int(port)
    except (TypeError, ValueError):
        return False
    for part in spec.split(","):
        m = _re.fullmatch(r"(\d+)(?:-(\d+))?", part.strip())
        if m:
            lo = int(m.group(1))
            hi = int(m.group(2) or lo)
            if lo <= port <= hi:
                return True
    return False


class RuleGroupIndex:
    # Filled by the Rules pages whenever they load rules; read by Live Traffic.
    PROTO = {"TCP": 6, "UDP": 17, "ICMP": 1, "ICMPV4": 1, "ICMPV6": 58}

    def __init__(self):
        self._rules = []
        self._cache = {}

    def update(self, rules):
        out = []
        for r in rules:
            group = (getattr(r, "grouping", "") or "").strip()
            if not group or not r.enabled:
                continue
            path = _norm_path(r.application_path)
            lports = r.local_ports or "*"
            rports = r.remote_ports or "*"
            if not path and r.protocol == 256 and lports == "*" and rports == "*":
                continue  # matches everything; would only add noise
            out.append((path, r.direction, r.protocol, lports, rports, resolve_group_name(group)))
        self._rules = out
        self._cache.clear()

    def lookup(self, event):
        direction = 1 if str(event.direction).lower().startswith("in") else 2
        proto = self.PROTO.get(str(event.protocol_name or "").upper())
        path = _norm_path(event.application_path)
        port = event.dest_port
        key = (path, direction, proto, port)
        if key in self._cache:
            return self._cache[key]
        groups = []
        for rpath, rdir, rproto, lports, rports, gname in self._rules:
            if rdir != direction:
                continue
            if rpath and rpath != path:
                continue
            if rproto not in (256, proto):
                continue
            if rproto in (6, 17):
                spec = rports if direction == 2 else lports
                if not _port_in_spec(spec, port):
                    continue
            if gname not in groups:
                groups.append(gname)
        text = ", ".join(groups[:3]) + (f" +{len(groups) - 3}" if len(groups) > 3 else "")
        self._cache[key] = text
        return text


GROUP_INDEX = RuleGroupIndex()

TRAFFIC_FEED_MAX_ROWS = 300

ALLOW_COLOR = QColor(60, 180, 90)
BLOCK_COLOR = QColor(220, 70, 70)


class TrafficBridge(QObject):
    event_ready = pyqtSignal(object)  # emits ConnectionEvent


class AppInfoCache:
    """Tiny in-memory cache so the feed doesn't re-run icon/version-info
    extraction (or a PowerShell call, for UWP apps) on every single event
    from the same application."""

    def __init__(self):
        self._cache: dict[str, AppInfo] = {}

    def get(self, raw_path: str | None) -> AppInfo:
        key = raw_path or ""
        if key not in self._cache:
            self._cache[key] = resolve_app(raw_path)
        return self._cache[key]


def _configure_table_header(table: QTableWidget) -> None:
    """Shared setup so every table in this module sorts by click and
    resizes columns by dragging, consistently."""
    table.setSortingEnabled(True)
    header = table.horizontalHeader()
    header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    header.setStretchLastSection(True)
    header.setSectionsMovable(True)


def _repopulate_preserving_sort(table: QTableWidget, populate_fn) -> None:
    """Rebuilds a table's rows via populate_fn() while preserving
    whatever sort column/order the user currently has active -- without
    this, every live refresh would silently reset back to insertion
    order and undo a sort click."""
    header = table.horizontalHeader()
    sort_section = header.sortIndicatorSection()
    sort_order = header.sortIndicatorOrder()

    table.setSortingEnabled(False)
    populate_fn()
    table.setSortingEnabled(True)
    if sort_section >= 0:
        table.sortItems(sort_section, sort_order)


class TrafficFeedWidget(QWidget):
    rule_created = pyqtSignal()

    def __init__(self, engine: FirewallEngine | None = None, parent=None):
        super().__init__(parent)
        self.engine = engine
        self._app_cache = AppInfoCache()
        self._rows: collections.deque = collections.deque(maxlen=TRAFFIC_FEED_MAX_ROWS)
        self._paused = False
        self._pending: collections.deque = collections.deque(maxlen=TRAFFIC_FEED_MAX_ROWS)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        header_row = QHBoxLayout()
        header_row.addWidget(SubtitleLabel("Live Traffic"))
        header_row.addStretch()
        self.pause_btn = PushButton("Pause")
        self.pause_btn.setIcon(FluentIcon.PAUSE)
        self.pause_btn.clicked.connect(self._toggle_pause)
        header_row.addWidget(self.pause_btn)
        layout.addLayout(header_row)

        self.filter_box = SearchLineEdit()
        self.filter_box.setPlaceholderText("Filter by app name, address, or port...")
        self.filter_box.textChanged.connect(self._apply_filter)
        layout.addWidget(self.filter_box)

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(
            ["Time", "App", "Direction", "Source", "Destination", "Service", "Verdict", "Group"]
        )
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_context_menu)
        _configure_table_header(self.table)
        _hdr = self.table.horizontalHeader()  # sagefw-width-v1
        _hdr.resizeSection(1, _hdr.defaultSectionSize() * 2)
        layout.addWidget(self.table)

    def _toggle_pause(self) -> None:
        if self._paused:
            self._paused = False
            for ev in self._pending:
                self._ingest(ev)
            self._pending.clear()
            self._render()
        else:
            self._paused = True
        self._update_pause_button()

    def _update_pause_button(self) -> None:
        if self._paused:
            n = len(self._pending)
            self.pause_btn.setText(f"Resume ({n} new)" if n else "Resume")
            self.pause_btn.setIcon(FluentIcon.PLAY)
        else:
            self.pause_btn.setText("Pause")
            self.pause_btn.setIcon(FluentIcon.PAUSE)

    def add_event(self, event: ConnectionEvent) -> None:
        if self._paused:
            self._pending.append(event)
            self._update_pause_button()
            return
        self._ingest(event)
        self._render()

    def _ingest(self, event: ConnectionEvent) -> None:
        app_info = self._app_cache.get(event.application_path)
        service = describe_port(event.protocol_name, event.dest_port)
        verdict = "Allowed" if event.was_allowed else "Blocked"
        group_text = GROUP_INDEX.lookup(event)
        self._rows.appendleft({
            "event": event,
            "group": group_text,
            "time": event.timestamp.strftime("%H:%M:%S"),
            "app": app_info.display_name or "Unknown",
            "direction": event.direction.upper(),
            "source": f"{event.source_address}:{event.source_port}",
            "dest": f"{event.dest_address}:{event.dest_port}",
            "service": service,
            "verdict": verdict,
            "search_blob": " ".join(str(x) for x in [
                app_info.display_name, event.source_address, event.dest_address,
                event.dest_port, service, group_text,
            ]).lower(),
        })

    def _render(self) -> None:
        query = self.filter_box.text().strip().lower()
        visible_rows = [r for r in self._rows if not query or query in r["search_blob"]]

        def populate():
            self.table.setRowCount(len(visible_rows))
            for i, row in enumerate(visible_rows):
                values = [row["time"], row["app"], row["direction"], row["source"],
                          row["dest"], row["service"], row["verdict"], row["group"]]
                color = ALLOW_COLOR if row["verdict"] == "Allowed" else BLOCK_COLOR
                for col, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    if col == 6:
                        item.setForeground(color)
                    if col == 0:
                        item.setData(Qt.ItemDataRole.UserRole, row["event"])
                    self.table.setItem(i, col, item)

        _repopulate_preserving_sort(self.table, populate)

    def _apply_filter(self, _text: str) -> None:
        self._render()

    def _on_context_menu(self, pos) -> None:
        item = self.table.itemAt(pos)
        if item is None:
            return
        row = item.row()
        event = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        if event is None:
            return
        self.table.selectRow(row)
        app = self.table.item(row, 1).text()
        dest = self.table.item(row, 4).text()

        menu = QMenu(self)
        choices = {
            menu.addAction(f"Allow this traffic ({app} -> {dest})..."): ("Allow", "traffic"),
            menu.addAction(f"Block this traffic ({app} -> {dest})..."): ("Block", "traffic"),
        }
        menu.addSeparator()
        choices[menu.addAction(f"Allow {app} (all traffic)...")] = ("Allow", "app")
        choices[menu.addAction(f"Block {app} (all traffic)...")] = ("Block", "app")

        menu.addSeparator()
        search_name = exe_name_from_path(event.application_path) or app
        google_action = menu.addAction(f'Search Google for "{search_name}"')
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen is google_action:
            search_google(search_name)
            return
        if chosen in choices:
            action, scope = choices[chosen]
            self._open_rule_editor(event, action, scope)

    @staticmethod
    def _event_to_prefill(event: ConnectionEvent, action: str, scope: str) -> dict:
        proto = str(event.protocol_name or "").upper()
        outbound = str(event.direction).lower().startswith("out")
        prefill = {
            "application_path": event.application_path or None,
            "direction": "Outbound" if outbound else "Inbound",
            "action": action,
            "protocol": "Any",
            "local_ports": "*", "remote_ports": "*", "remote_addresses": "*",
            "name_suffix": "",
        }
        if scope == "traffic":
            if proto in ("TCP", "UDP"):
                prefill["protocol"] = proto
                if outbound:
                    prefill["remote_ports"] = str(event.dest_port)
                else:
                    prefill["local_ports"] = str(event.dest_port)
                prefill["name_suffix"] = f" {proto} {event.dest_port}"
            prefill["remote_addresses"] = str(event.dest_address if outbound else event.source_address)
        return prefill

    def _open_rule_editor(self, event: ConnectionEvent, action: str, scope: str) -> None:
        if self.engine is None:
            InfoBar.warning(title="Not available", content="No firewall engine connected.",
                            position=InfoBarPosition.TOP, duration=3000, parent=self.window())
            return
        from rules_manager import RuleEditorDialog  # lazy: rules_manager imports dashboard
        dialog = RuleEditorDialog(self.engine, prefill=self._event_to_prefill(event, action, scope),
                                  parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            InfoBar.success(title="Rule created", content="",
                            position=InfoBarPosition.TOP, duration=2500, parent=self.window())
            self.rule_created.emit()

class TidyUpDialog(QDialog):
    """
    Shows every orphaned rule found (application path no longer exists
    on disk) with a checkbox per row, defaulted to checked. Nothing is
    deleted until the user clicks 'Remove Selected' -- and even then, a
    safety snapshot is taken automatically first (see
    import_export.tidy_up_orphaned_rules).
    """

    def __init__(self, orphaned_rules: list[FirewallRule], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Tidy Up -- Orphaned Rules")
        self.setMinimumSize(560, 420)
        self.orphaned_rules = orphaned_rules

        layout = QVBoxLayout(self)
        layout.addWidget(SubtitleLabel(f"Found {len(orphaned_rules)} rule(s) pointing "
                                        f"to applications that no longer exist:"))
        note = CaptionLabel(
            "These reference .exe paths that are no longer on disk -- usually left "
            "behind by uninstalled software. A backup snapshot is taken automatically "
            "before anything is removed, so this can always be undone."
        )
        note.setWordWrap(True)
        layout.addWidget(note)

        self.list_widget = QListWidget()
        for rule in orphaned_rules:
            item = QListWidgetItem(f"{rule.name}\n    -> {rule.application_path}")
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            item.setData(Qt.ItemDataRole.UserRole, rule.name)
            self.list_widget.addItem(item)
        layout.addWidget(self.list_widget)

        button_row = QHBoxLayout()
        self.select_all_btn = PushButton("Select All")
        self.select_all_btn.clicked.connect(lambda: self._set_all_checked(True))
        self.select_none_btn = PushButton("Select None")
        self.select_none_btn.clicked.connect(lambda: self._set_all_checked(False))
        button_row.addWidget(self.select_all_btn)
        button_row.addWidget(self.select_none_btn)
        button_row.addStretch()
        layout.addLayout(button_row)

        buttons = QDialogButtonBox()
        self.remove_btn = PrimaryPushButton("Remove Selected")
        self.remove_btn.clicked.connect(self.accept)
        self.cancel_btn = PushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        buttons.addButton(self.remove_btn, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.addButton(self.cancel_btn, QDialogButtonBox.ButtonRole.RejectRole)
        layout.addWidget(buttons)

    def _set_all_checked(self, checked: bool) -> None:
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        for i in range(self.list_widget.count()):
            self.list_widget.item(i).setCheckState(state)

    def selected_rule_names(self) -> list[str]:
        names = []
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                names.append(item.data(Qt.ItemDataRole.UserRole))
        return names


class RulesOverviewWidget(QWidget):
    """Read-only view of every current native Windows Firewall rule
    (create/edit lands in a future ui/rules_manager.py), plus a Tidy Up
    action for removing rules that reference apps no longer on disk."""

    def __init__(self, engine: FirewallEngine, store: RuleStore | None = None, parent=None):
        super().__init__(parent)
        self.engine = engine
        self.store = store
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        header_row = QHBoxLayout()
        header_row.addWidget(SubtitleLabel("Current Firewall Rules"))
        header_row.addStretch()
        self.tidy_up_btn = PushButton("Tidy Up")
        self.tidy_up_btn.setToolTip("Find and remove rules pointing to applications "
                                     "that no longer exist on disk.")
        self.tidy_up_btn.clicked.connect(self._on_tidy_up_clicked)
        header_row.addWidget(self.tidy_up_btn)
        self.refresh_btn = PushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh)
        header_row.addWidget(self.refresh_btn)
        layout.addLayout(header_row)

        self.filter_box = SearchLineEdit()
        self.filter_box.setPlaceholderText("Filter by rule name or application...")
        self.filter_box.textChanged.connect(self._apply_filter)
        layout.addWidget(self.filter_box)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Name", "Application", "Direction", "Action", "Enabled", "Source"]
        )
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        _configure_table_header(self.table)
        _hdr = self.table.horizontalHeader()  # sagefw-width-v1
        _hdr.resizeSection(1, _hdr.defaultSectionSize() * 2)
        layout.addWidget(self.table)

        self._all_rules: list[FirewallRule] = []

    def refresh(self) -> None:
        self._all_rules = self.engine.list_rules(ours_only=False)
        self._render()

    def _render(self) -> None:
        query = self.filter_box.text().strip().lower()
        rows = [
            r for r in self._all_rules
            if not query or query in (r.name or "").lower()
            or query in (r.application_path or "").lower()
        ]

        def populate():
            self.table.setRowCount(len(rows))
            for i, rule in enumerate(rows):
                direction = "IN" if rule.direction == 1 else "OUT"
                action = "Allow" if rule.action == 1 else "Block"
                source = "This app" if rule.is_ours else "Windows / other"
                values = [rule.name, rule.application_path or "(any)", direction,
                          action, "Yes" if rule.enabled else "No", source]
                for col, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    if col == 3:
                        item.setForeground(ALLOW_COLOR if action == "Allow" else BLOCK_COLOR)
                    self.table.setItem(i, col, item)

        _repopulate_preserving_sort(self.table, populate)

    def _apply_filter(self, _text: str) -> None:
        self._render()

    def _on_tidy_up_clicked(self) -> None:
        orphaned = find_orphaned_rules(self.engine, ours_only=False)
        if not orphaned:
            InfoBar.success(
                title="Nothing to tidy up",
                content="No rules were found pointing to missing applications.",
                position=InfoBarPosition.TOP, duration=3000, parent=self.window(),
            )
            return

        dialog = TidyUpDialog(orphaned, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        selected_names = dialog.selected_rule_names()
        if not selected_names:
            return

        if self.store is None:
            # No RuleStore available (e.g. standalone dashboard.py without
            # one wired in) -- skip the safety snapshot rather than fail.
            removed = self.engine.delete_rules(selected_names)
            snapshot_note = "(no backup snapshot -- RuleStore not available)"
        else:
            summary = tidy_up_orphaned_rules(self.engine, self.store, selected_names)
            removed = summary["rules_removed"]
            snapshot_note = f"(backup snapshot #{summary['snapshot_id']} created first)"

        InfoBar.success(
            title="Tidy up complete",
            content=f"Removed {removed} orphaned rule(s). {snapshot_note}",
            position=InfoBarPosition.TOP, duration=4000, parent=self.window(),
        )
        self.refresh()


class DashboardWindow(QMainWindow):
    def __init__(self, engine: FirewallEngine, store: RuleStore | None = None, parent=None):
        super().__init__(parent)
        self.engine = engine
        self.setWindowTitle("SageFW -- Dashboard")
        self.resize(1100, 750)

        self._monitor = ConnectionMonitor(blocked_only=False)
        self.bridge = TrafficBridge()
        self.bridge.event_ready.connect(self._on_event)
        self._monitor.on_event(self.bridge.event_ready.emit)

        self._build_ui(store)
        self._monitor.start()

    def _build_ui(self, store: RuleStore | None) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)

        outer.addWidget(TitleLabel("Dashboard"))
        outer.addWidget(CaptionLabel(
            "Live view of current traffic and existing rules -- nothing here "
            "makes changes except the explicit Tidy Up action. Use this to see "
            "what's happening before deciding on lockdown mode or new rules."
        ))

        splitter = QSplitter(Qt.Orientation.Vertical)

        self.feed = TrafficFeedWidget(engine=self.engine)
        self.rules_overview = RulesOverviewWidget(self.engine, store=store)

        splitter.addWidget(self.feed)
        splitter.addWidget(self.rules_overview)
        splitter.setSizes([450, 300])

        outer.addWidget(splitter)

    def _on_event(self, event: ConnectionEvent) -> None:
        self.feed.add_event(event)

    def closeEvent(self, event) -> None:
        self._monitor.stop()
        super().closeEvent(event)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    setTheme(Theme.DARK)

    engine = FirewallEngine()
    store = RuleStore()
    window = DashboardWindow(engine, store=store)
    window.show()

    sys.exit(app.exec())
