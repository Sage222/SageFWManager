"""
ui/notification_popup.py

The actual dialog you see and act on: a non-modal, always-on-top panel
that accumulates decision cards as PendingBatches arrive, lets you pick
Allow/Block with a scope (Once / Always this app / Always this app+dest)
per app, and auto-removes cards once you've decided (or once the backend
times them out).

Height cap: the panel is capped at MAX_PANEL_HEIGHT and wrapped in a
QScrollArea. Without this, a large batch of simultaneous decisions (e.g.
several apps all hitting mDNS/discovery traffic at once during a fresh
lockdown-mode session) could grow the panel tall enough to cover the
system tray icon entirely -- which actually happened during testing and
made the tray's Exit option unreachable, forcing a Task Manager kill.
Capping the height and scrolling extra cards fixes that regardless of
how many decisions arrive at once. (A Ctrl+Q shortcut was also added to
ShellWindow as an independent safety net, so quitting never depends
solely on the tray icon being reachable.)

Threading note: NotificationManager's callbacks (on_batch_ready,
on_focus_requested) fire from background threads -- the connection
monitor's callback thread and internal timer threads. PyQt widgets must
only be touched from the main GUI thread. NotificationBridge (a QObject
with signals) exists specifically to marshal those events safely across
threads.

Depends on: PyQt6, PyQt6-Fluent-Widgets (qfluentwidgets).
"""

from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtCore import Qt, QObject, pyqtSignal, QTimer
from PyQt6.QtGui import QIcon, QPixmap, QGuiApplication
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QApplication, QSizePolicy, QLabel,
    QScrollArea,
)

from qfluentwidgets import (
    CardWidget, BodyLabel, CaptionLabel, StrongBodyLabel, PushButton,
    PrimaryPushButton, RoundMenu, Action, FluentIcon, setTheme, Theme,
    isDarkTheme, TransparentToolButton,
)

sys.path.append(str(Path(__file__).resolve().parent.parent))  # allow importing core/*
from notification_manager import NotificationManager, PendingBatch, PendingDecision

PANEL_WIDTH = 420
MAX_PANEL_HEIGHT = 480  # Hard cap -- extra cards scroll instead of growing the window further.
CARD_SPACING = 8
MARGIN = 12


class NotificationBridge(QObject):
    """Thread-safe relay between NotificationManager's background-thread
    callbacks and Qt's main-thread slots."""
    batch_ready = pyqtSignal(object)     # emits PendingBatch
    focus_requested = pyqtSignal(object)  # emits PendingBatch


class DecisionCard(CardWidget):
    """One row in the panel: icon + app/connection info + Allow/Block
    buttons, each with a dropdown for scope (Once / Always app / Always
    app+destination)."""

    def __init__(self, decision: PendingDecision, manager: NotificationManager,
                 on_resolved, parent=None):
        super().__init__(parent)
        self.decision = decision
        self.manager = manager
        self.on_resolved = on_resolved  # callback(card) -> None, called after a choice is made

        self.setFixedWidth(PANEL_WIDTH - 2 * MARGIN - 16)  # leave room for the scrollbar
        self._build_ui()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 10, 14, 10)
        outer.setSpacing(6)

        # --- top row: icon + app name + publisher ---
        top_row = QHBoxLayout()
        icon_label = QLabel()
        icon_label.setFixedSize(32, 32)
        pixmap = self._load_icon_pixmap()
        if pixmap:
            icon_label.setPixmap(pixmap.scaled(32, 32, Qt.AspectRatioMode.KeepAspectRatio,
                                                Qt.TransformationMode.SmoothTransformation))
        top_row.addWidget(icon_label)

        name_col = QVBoxLayout()
        name_col.setSpacing(0)
        app_name = StrongBodyLabel(self.decision.app_info.display_name or "Unknown application")
        name_col.addWidget(app_name)
        publisher_text = self.decision.app_info.publisher or "Unknown publisher"
        publisher_label = CaptionLabel(publisher_text)
        name_col.addWidget(publisher_label)
        top_row.addLayout(name_col)
        top_row.addStretch()
        outer.addLayout(top_row)

        # --- connection details ---
        event = self.decision.event
        direction_word = "Incoming" if event.direction == "in" else "Outgoing"
        dest_line = f"{direction_word} \u00b7 {event.protocol_name} \u00b7 " \
                    f"{event.source_address}:{event.source_port} \u2192 " \
                    f"{event.dest_address}:{event.dest_port}"
        details = BodyLabel(dest_line)
        details.setWordWrap(True)
        outer.addWidget(details)

        if self.decision.service_label:
            service = CaptionLabel(f"Likely service: {self.decision.service_label}")
            outer.addWidget(service)

        # --- action buttons ---
        button_row = QHBoxLayout()
        button_row.setSpacing(8)

        self.allow_btn = PrimaryPushButton("Allow")
        self.allow_btn.clicked.connect(lambda: self._on_button_clicked("allow", default_scope="once"))
        self.allow_btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._attach_scope_menu(self.allow_btn, "allow")

        self.block_btn = PushButton("Block")
        self.block_btn.clicked.connect(lambda: self._on_button_clicked("block", default_scope="once"))
        self._attach_scope_menu(self.block_btn, "block")

        button_row.addWidget(self.allow_btn)
        button_row.addWidget(self.block_btn)
        button_row.addStretch()
        outer.addLayout(button_row)

        hint = CaptionLabel("Click Allow/Block for a one-time decision, or right-click for "
                             "more options (always allow/block this app).")
        hint.setWordWrap(True)
        outer.addWidget(hint)

    def _load_icon_pixmap(self):
        icon_path = self.decision.app_info.icon_path
        if icon_path and Path(icon_path).exists():
            pix = QPixmap(icon_path)
            if not pix.isNull():
                return pix
        return None

    def _attach_scope_menu(self, button, action: str) -> None:
        """Right-click opens a menu with the two 'always' scope options,
        keeping the main click as a quick 'once' decision."""
        menu = RoundMenu(parent=button)
        app_name = self.decision.app_info.display_name or "this app"
        dest = self.decision.event.dest_address or "this destination"

        once_label = "Allow Once" if action == "allow" else "Block Once"
        always_app_label = f"Always {action.capitalize()} {app_name}"
        always_dest_label = f"Always {action.capitalize()} {app_name} \u2192 {dest}"

        menu.addAction(Action(FluentIcon.ACCEPT if action == "allow" else FluentIcon.CANCEL,
                               once_label, triggered=lambda: self._resolve(action, "once")))
        menu.addAction(Action(FluentIcon.PIN, always_app_label,
                               triggered=lambda: self._resolve(action, "always_app")))
        menu.addAction(Action(FluentIcon.GLOBE, always_dest_label,
                               triggered=lambda: self._resolve(action, "always_app_dest")))

        def show_menu(pos):
            menu.exec(button.mapToGlobal(pos))

        button.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        button.customContextMenuRequested.connect(show_menu)

    def _on_button_clicked(self, action: str, default_scope: str) -> None:
        self._resolve(action, default_scope)

    def _resolve(self, action: str, scope: str) -> None:
        self.manager.apply_decision(self.decision, action=action, scope=scope)
        self.on_resolved(self)


class NotificationPanel(QWidget):
    """
    A non-modal, frameless, always-on-top panel anchored to the bottom
    right of the screen (classic toast-notification position). Stays
    hidden while empty; shows and accumulates DecisionCards as batches
    arrive; auto-hides again once every card has been resolved.

    Height is capped at MAX_PANEL_HEIGHT via an internal QScrollArea --
    see module docstring for why this matters (a large batch could
    otherwise grow tall enough to cover the system tray icon).
    """

    def __init__(self, manager: NotificationManager, parent=None):
        super().__init__(parent, Qt.WindowType.Tool | Qt.WindowType.FramelessWindowHint |
                          Qt.WindowType.WindowStaysOnTopHint)
        self.manager = manager
        self.cards: list[DecisionCard] = []

        self.setWindowTitle("Firewall Decisions")
        self.setFixedWidth(PANEL_WIDTH)
        self.setMaximumHeight(MAX_PANEL_HEIGHT)
        self.setStyleSheet("background-color: rgba(32, 32, 32, 235); border-radius: 8px;")

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QScrollArea.Shape.NoFrame)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.scroll_area.setStyleSheet("background: transparent;")
        outer_layout.addWidget(self.scroll_area)

        self._cards_container = QWidget()
        self._cards_container.setStyleSheet("background: transparent;")
        self._layout = QVBoxLayout(self._cards_container)
        self._layout.setContentsMargins(MARGIN, MARGIN, MARGIN, MARGIN)
        self._layout.setSpacing(CARD_SPACING)
        self._layout.addStretch()
        self.scroll_area.setWidget(self._cards_container)

        self.bridge = NotificationBridge()
        self.bridge.batch_ready.connect(self._on_batch_ready)
        self.bridge.focus_requested.connect(self._on_focus_requested)

        manager.on_batch_ready(self.bridge.batch_ready.emit)
        manager.on_focus_requested(self.bridge.focus_requested.emit)

        self.hide()

    def _on_batch_ready(self, batch: PendingBatch) -> None:
        for decision in batch.decisions:
            card = DecisionCard(decision, self.manager, self._on_card_resolved)
            self._layout.insertWidget(self._layout.count() - 1, card)
            self.cards.append(card)
        self._reposition_and_show()

    def _on_card_resolved(self, card: DecisionCard) -> None:
        self._layout.removeWidget(card)
        card.deleteLater()
        if card in self.cards:
            self.cards.remove(card)
        if not self.cards:
            self.hide()
        else:
            self._reposition_and_show()

    def _on_focus_requested(self, batch: PendingBatch) -> None:
        self.show()
        self.raise_()
        self.activateWindow()

    def _reposition_and_show(self) -> None:
        # Height is capped by setMaximumHeight() above; adjustSize() will
        # never exceed that regardless of how many cards are stacked, so
        # this can never grow tall enough to reach/cover the tray icon.
        self.adjustSize()
        screen = QGuiApplication.primaryScreen().availableGeometry()
        x = screen.right() - self.width() - 16
        y = screen.bottom() - self.height() - 16
        self.move(max(x, 0), max(y, 0))
        self.show()


def apply_fluent_theme(dark: bool = True) -> None:
    setTheme(Theme.DARK if dark else Theme.LIGHT)


if __name__ == "__main__":
    # Standalone smoke test: fabricates a fake batch (no real firewall/
    # connection monitor needed) so the UI can be checked in isolation.
    # This test now creates a LARGE batch (12 fake decisions) specifically
    # to verify the height cap + scrolling actually works and the panel
    # never grows tall enough to reach the bottom of the screen.
    import datetime as dt
    from app_resolver import AppInfo
    from connection_monitor import ConnectionEvent
    from notification_manager import PendingDecision

    app = QApplication(sys.argv)
    apply_fluent_theme(dark=True)

    class _FakeManager:
        def on_batch_ready(self, callback):
            pass

        def on_focus_requested(self, callback):
            pass

        def apply_decision(self, pending, action, scope):
            print(f"[TEST] Would apply: {action} / {scope} for {pending.app_info.display_name}")

    fake_decisions = []
    for i in range(12):
        fake_event = ConnectionEvent(
            timestamp=dt.datetime.utcnow(), event_id=5157,
            application_path=f"C:\\Test\\App{i}.exe",
            direction="out", protocol="6", source_address="10.0.0.49", source_port="51000",
            dest_address="224.0.0.251", dest_port="5353",
        )
        fake_app = AppInfo(original_path=fake_event.application_path,
                            display_name=f"Test App {i}", publisher="Test Publisher")
        fake_decisions.append(PendingDecision(
            id=f"test{i}", created_at=dt.datetime.utcnow(), event=fake_event,
            app_info=fake_app, service_label="mDNS (Multicast DNS / Bonjour)",
        ))

    fake_manager = _FakeManager()
    panel = NotificationPanel(fake_manager)
    fake_batch = PendingBatch(decisions=fake_decisions, created_at=dt.datetime.utcnow())
    panel._on_batch_ready(fake_batch)
    panel._on_focus_requested(fake_batch)

    print(f"[TEST] Panel height: {panel.height()} (should be capped at {MAX_PANEL_HEIGHT})")

    sys.exit(app.exec())
