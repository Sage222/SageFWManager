"""
core/notification_manager.py

Ties together connection_monitor + app_resolver + rule_store + firewall_engine
into the actual decision-prompting pipeline:

  1. Listens for BLOCKED connection events (in a default-block/lockdown
     posture, a blocked connection IS a "new connection needing a
     decision" -- this matches Minimal Firewall's own approach).
  2. Resolves the raw app path into a friendly name/icon/publisher.
  3. Checks rule_store for an existing "always" decision -- if found,
     applies it silently (no popup) via the firewall engine.
  4. Otherwise, builds a PendingDecision with everything needed to inform
     a choice: app name/icon/publisher, direction, source, destination,
     protocol, and a friendly service label (port_services.py).
  5. Groups near-simultaneous *different* PendingDecisions into a single
     PendingBatch for display -- this is grouping for readability, NOT
     suppression. Every distinct app+destination still gets surfaced;
     you just don't get 4 separate popups within the same 300ms window.
  6. Exposes apply_decision() for the UI to call once you choose:
     allow/block, and once/always_app/always_app_dest scope.
  7. Handles the "Allow Once" / "Block Once" nuance: since Windows
     Firewall rules are binary (not per-packet), "once" creates a real
     rule so traffic actually flows/blocks, but tags it session-only in
     rule_store so cleanup_session_rules() can remove it later (call this
     on every app startup, and optionally on a timer).
  8. Auto-resolves any prompt left unanswered past a configurable timeout
     -- default action is "block once" per your stated preference, so an
     ignored popup fails safe without permanently blacklisting the app.

No UI dependency -- the UI layer subscribes via on_batch_ready() and calls
apply_decision() / apply_batch_decision() in response to user clicks.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import threading
import time
from typing import Callable, Optional

from app_resolver import AppInfo, resolve_app
from connection_monitor import ConnectionEvent, ConnectionMonitor
from firewall_engine import Direction, FirewallEngine
from port_services import describe_port
from rule_store import RuleStore

logger = logging.getLogger(__name__)

BATCH_WINDOW_SECONDS = 0.4          # Window for grouping near-simultaneous events for display.
DEFAULT_PROMPT_TIMEOUT_SECONDS = 25  # Auto-resolve if the user doesn't answer.


@dataclasses.dataclass
class PendingDecision:
    id: str  # unique key, e.g. f"{app_path}|{direction}|{dest_address}|{dest_port}"
    created_at: dt.datetime
    event: ConnectionEvent
    app_info: AppInfo
    service_label: str  # e.g. "SMB (Windows File Sharing)", may be ""

    @property
    def summary(self) -> str:
        dest = f"{self.event.dest_address}:{self.event.dest_port}"
        svc = f" -- {self.service_label}" if self.service_label else ""
        return (f"{self.app_info.display_name} wants to connect "
                f"{self.event.direction.upper()} to {dest}{svc}")


@dataclasses.dataclass
class PendingBatch:
    """A group of PendingDecisions that arrived within BATCH_WINDOW_SECONDS
    of each other -- shown to the user as one popup with a list, so e.g.
    4 apps all hitting mDNS at once becomes one dialog, not four."""
    decisions: list[PendingDecision]
    created_at: dt.datetime


class NotificationManager:
    def __init__(self, rule_store: RuleStore, firewall_engine: FirewallEngine,
                 prompt_timeout_seconds: float = DEFAULT_PROMPT_TIMEOUT_SECONDS,
                 grab_focus_inbound: bool = True, grab_focus_outbound: bool = True):
        self.store = rule_store
        self.engine = firewall_engine
        self.prompt_timeout = prompt_timeout_seconds
        self.grab_focus_inbound = grab_focus_inbound
        self.grab_focus_outbound = grab_focus_outbound

        self._monitor = ConnectionMonitor(blocked_only=True)
        self._monitor.on_event(self._on_blocked_event)

        self._batch_lock = threading.Lock()
        self._batch_buffer: list[PendingDecision] = []
        self._batch_timer: Optional[threading.Timer] = None

        self._pending_by_id: dict[str, PendingDecision] = {}
        self._timeout_timers: dict[str, threading.Timer] = {}

        self._batch_callbacks: list[Callable[[PendingBatch], None]] = []
        self._focus_request_callbacks: list[Callable[[PendingBatch], None]] = []

    # ---------- wiring for the UI ----------

    def on_batch_ready(self, callback: Callable[[PendingBatch], None]) -> None:
        """UI registers here to receive grouped decisions to display."""
        self._batch_callbacks.append(callback)

    def on_focus_requested(self, callback: Callable[[PendingBatch], None]) -> None:
        """UI registers here specifically for 'please steal focus now' signals,
        separate from on_batch_ready so the UI can decide how aggressively
        to react (e.g. flash taskbar vs. actually pop the window forward)."""
        self._focus_request_callbacks.append(callback)

    def start(self) -> None:
        self.cleanup_session_rules()
        self._monitor.start()
        logger.info("NotificationManager started (prompt timeout: %ss).", self.prompt_timeout)

    def stop(self) -> None:
        self._monitor.stop()
        with self._batch_lock:
            if self._batch_timer:
                self._batch_timer.cancel()
        for timer in self._timeout_timers.values():
            timer.cancel()

    # ---------- event intake ----------

    def _on_blocked_event(self, event: ConnectionEvent) -> None:
        app_info = resolve_app(event.application_path)
        existing = self.store.find_existing_decision(
            app_path=app_info.original_path,
            direction=event.direction,
            remote_address=event.dest_address or "*",
        )
        if existing:
            self._apply_silently(event, app_info, existing)
            return

        decision_id = f"{app_info.original_path}|{event.direction}|{event.dest_address}|{event.dest_port}"
        if decision_id in self._pending_by_id:
            return  # Already awaiting a decision for this exact app+destination.

        pending = PendingDecision(
            id=decision_id,
            created_at=dt.datetime.utcnow(),
            event=event,
            app_info=app_info,
            service_label=describe_port(event.protocol_name, event.dest_port),
        )
        self._pending_by_id[decision_id] = pending
        self._schedule_timeout(pending)
        self._add_to_batch(pending)

    def _apply_silently(self, event: ConnectionEvent, app_info: AppInfo, decision: dict) -> None:
        """A previous 'always' decision already covers this -- enforce it
        without bothering the user again."""
        action = decision["action"]
        direction = Direction.IN if event.direction == "in" else Direction.OUT
        label = app_info.display_name or app_info.original_path
        if action == "allow" and app_info.resolved_path:
            self.engine.allow_application(app_info.resolved_path, label, directions=(direction,))
        # 'block' decisions generally need no rule under default-deny -- the
        # absence of an allow rule already blocks it; we just don't re-prompt.
        logger.debug("Applied existing '%s' decision silently for %s", action, label)

    # ---------- display batching ----------

    def _add_to_batch(self, pending: PendingDecision) -> None:
        with self._batch_lock:
            self._batch_buffer.append(pending)
            if self._batch_timer is None:
                self._batch_timer = threading.Timer(BATCH_WINDOW_SECONDS, self._flush_batch)
                self._batch_timer.daemon = True
                self._batch_timer.start()

    def _flush_batch(self) -> None:
        with self._batch_lock:
            if not self._batch_buffer:
                self._batch_timer = None
                return
            batch = PendingBatch(decisions=list(self._batch_buffer), created_at=dt.datetime.utcnow())
            self._batch_buffer.clear()
            self._batch_timer = None

        for cb in self._batch_callbacks:
            try:
                cb(batch)
            except Exception:
                logger.exception("on_batch_ready callback raised")

        wants_focus = any(
            (d.event.direction == "in" and self.grab_focus_inbound) or
            (d.event.direction == "out" and self.grab_focus_outbound)
            for d in batch.decisions
        )
        if wants_focus:
            for cb in self._focus_request_callbacks:
                try:
                    cb(batch)
                except Exception:
                    logger.exception("on_focus_requested callback raised")

    # ---------- timeout handling ----------

    def _schedule_timeout(self, pending: PendingDecision) -> None:
        timer = threading.Timer(self.prompt_timeout, self._on_timeout, args=(pending.id,))
        timer.daemon = True
        self._timeout_timers[pending.id] = timer
        timer.start()

    def _on_timeout(self, decision_id: str) -> None:
        pending = self._pending_by_id.get(decision_id)
        if pending is None:
            return  # Already resolved by the user.
        logger.info("Prompt timed out with no response -- auto-blocking once: %s", pending.summary)
        self.apply_decision(pending, action="block", scope="once")

    # ---------- applying decisions ----------

    def apply_decision(self, pending: PendingDecision, action: str, scope: str) -> None:
        """
        action: 'allow' or 'block'
        scope:  'once', 'always_app', or 'always_app_dest'
        """
        self._pending_by_id.pop(pending.id, None)
        timer = self._timeout_timers.pop(pending.id, None)
        if timer:
            timer.cancel()

        event = pending.event
        app_info = pending.app_info
        direction = Direction.IN if event.direction == "in" else Direction.OUT
        label = app_info.display_name or app_info.original_path or "Unknown app"
        is_session_only = (scope == "once")

        rule_name = None
        if action == "allow" and app_info.resolved_path:
            names = self.engine.allow_application(app_info.resolved_path, label, directions=(direction,))
            rule_name = names[0] if names else None
        # 'block' under default-deny needs no explicit rule -- recording the
        # decision (below) is what prevents future re-prompting.

        remote_scope_addr = event.dest_address if scope == "always_app_dest" else "*"
        decision_row_id = self.store.record_decision(
            app_path=app_info.original_path,
            direction=event.direction,
            action=action,
            scope=scope if scope != "once" else "once",  # stored as-is; 'once' rows are session markers
            remote_address=remote_scope_addr,
            remote_port=str(event.dest_port or "*"),
            rule_name=rule_name or "",
        )

        if is_session_only and rule_name:
            self.store.set_setting(f"session_rule::{decision_row_id}", rule_name)

        logger.info("Applied decision: %s %s for %s (scope=%s)", action, event.direction, label, scope)

    def apply_batch_decision(self, batch: PendingBatch, action: str, scope: str) -> None:
        """Convenience for a UI 'apply to all in this batch' bulk action."""
        for pending in batch.decisions:
            self.apply_decision(pending, action, scope)

    def dismiss_batch_without_deciding(self, batch: PendingBatch) -> None:
        """UI can call this if the user closes the dialog without choosing --
        leaves the timeout timers running so the fail-safe block-once still
        fires rather than leaving connections in limbo indefinitely."""
        pass  # Intentionally a no-op: timeout handling covers this case.

    # ---------- session-only rule cleanup ----------

    def cleanup_session_rules(self) -> None:
        """Removes any 'Allow/Block Once' rules left over from a previous
        run. Call this once at every app startup."""
        removed = 0
        for key, value in list(self._iter_session_rule_settings()):
            if self.engine.delete_rule(value):
                removed += 1
        if removed:
            logger.info("Cleaned up %d leftover session-only rule(s) from a previous run.", removed)

    def _iter_session_rule_settings(self):
        # Settings table doesn't currently support a prefix scan directly;
        # this pulls the small number of session_rule:: keys via a direct query.
        cur = self.store._conn.execute(
            "SELECT key, value FROM settings WHERE key LIKE 'session_rule::%'"
        )
        for row in cur.fetchall():
            yield row["key"], row["value"].strip('"')
        self.store._conn.execute("DELETE FROM settings WHERE key LIKE 'session_rule::%'")
        self.store._conn.commit()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    store = RuleStore()
    engine = FirewallEngine()
    manager = NotificationManager(store, engine, prompt_timeout_seconds=15)

    def _print_batch(batch: PendingBatch) -> None:
        print(f"\n=== New batch of {len(batch.decisions)} decision(s) needed ===")
        for d in batch.decisions:
            print(" -", d.summary)
            print(f"   Source: {d.event.source_address}:{d.event.source_port}  "
                  f"Protocol: {d.event.protocol_name}  Publisher: {d.app_info.publisher or 'Unknown'}")
        print("(auto-resolving to Block Once in 15s if no simulated response)")

    def _print_focus_request(batch: PendingBatch) -> None:
        print(f"[FOCUS REQUEST] Would steal focus now for {len(batch.decisions)} decision(s).")

    manager.on_batch_ready(_print_batch)
    manager.on_focus_requested(_print_focus_request)
    manager.start()

    print("Watching for blocked connections for 40 seconds (needs default outbound "
          "action set to Block to see anything -- otherwise nothing will be blocked yet)...")
    time.sleep(40)
    manager.stop()
    store.close()
