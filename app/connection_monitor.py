"""
core/connection_monitor.py

Detects new network connections in real time by:
  1. Enabling WFP ("Filtering Platform Connection") auditing via auditpol.
     One-time, admin-required, no kernel driver.
  2. Subscribing to the Security event log for Event ID 5156 (allowed) and/or
     5157 (blocked) using the *callback* model, matching how Minimal
     Firewall's .NET EventLogWatcher does it under the hood.
  3. Parsing each event into a plain ConnectionEvent and handing it to
     whatever callback(s) the UI / notification manager registered.

IMPORTANT gotcha (found via live testing with a real inbound ping):
The raw event XML does NOT contain literal text like "Inbound"/"Outbound"
for the Direction field. It contains an opaque placeholder code --
%%14592 for Inbound, %%14593 for Outbound -- that only gets translated to
readable text by a message-table lookup that tools like `wevtutil /f:text`
perform automatically. Since we render raw XML (EvtRenderEventXml), we must
map these codes ourselves. Checking for the literal substring "inbound"
against the raw code always fails and silently defaults to "out" for
every event, regardless of true direction -- exactly what happened during
testing until this was caught with a controlled inbound ping.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from typing import Callable, Optional

import win32evtlog

logger = logging.getLogger(__name__)

AUDIT_SUBCATEGORY = "Filtering Platform Connection"
SECURITY_CHANNEL = "Security"
EVENT_ID_ALLOWED = 5156
EVENT_ID_BLOCKED = 5157

_EVT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# WFP Direction field placeholder codes (raw XML form -- NOT localized text).
DIRECTION_CODE_INBOUND = "%%14592"
DIRECTION_CODE_OUTBOUND = "%%14593"

DEDUP_WINDOW_SECONDS = 2.0

# Common IANA protocol numbers, for friendlier display later (UI layer can use this).
PROTOCOL_NAMES = {"1": "ICMP", "6": "TCP", "17": "UDP"}


@dataclasses.dataclass(frozen=True)
class ConnectionEvent:
    timestamp: dt.datetime
    event_id: int  # 5156 = allowed, 5157 = blocked
    application_path: Optional[str]
    direction: str  # 'in', 'out', or 'unknown'
    protocol: Optional[str]
    source_address: Optional[str]
    source_port: Optional[str]
    dest_address: Optional[str]
    dest_port: Optional[str]

    @property
    def was_allowed(self) -> bool:
        return self.event_id == EVENT_ID_ALLOWED

    @property
    def protocol_name(self) -> str:
        return PROTOCOL_NAMES.get(self.protocol or "", self.protocol or "?")

    def dedup_key(self) -> tuple:
        return (self.application_path, self.direction, self.dest_address, self.dest_port)


class AuditPolError(RuntimeError):
    pass


def is_wfp_auditing_enabled() -> bool:
    try:
        result = subprocess.run(
            ["auditpol", "/get", f"/subcategory:{AUDIT_SUBCATEGORY}"],
            capture_output=True, text=True, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise AuditPolError(f"Could not query auditpol: {exc}") from exc
    output = result.stdout.lower()
    return "success and failure" in output or ("success" in output and "no auditing" not in output)


def enable_wfp_auditing() -> None:
    try:
        subprocess.run(
            ["auditpol", "/set", f"/subcategory:{AUDIT_SUBCATEGORY}",
             "/success:enable", "/failure:enable"],
            capture_output=True, text=True, check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise AuditPolError(
            "Failed to enable WFP auditing. Are you running as administrator? "
            f"Details: {exc.stderr}"
        ) from exc
    logger.info("WFP connection auditing enabled.")


def disable_wfp_auditing() -> None:
    subprocess.run(
        ["auditpol", "/set", f"/subcategory:{AUDIT_SUBCATEGORY}",
         "/success:disable", "/failure:disable"],
        capture_output=True, text=True,
    )


def _get_field(event_data_elems, name: str) -> Optional[str]:
    for elem in event_data_elems:
        if elem.get("Name") == name:
            return elem.text
    return None


def _decode_direction(raw: Optional[str]) -> str:
    if raw is None:
        return "unknown"
    raw = raw.strip()
    if raw == DIRECTION_CODE_INBOUND:
        return "in"
    if raw == DIRECTION_CODE_OUTBOUND:
        return "out"
    # Fallback for environments where the field IS literal text (seen in some
    # locales/tools) -- keep this as a safety net, not the primary path.
    lower = raw.lower()
    if "inbound" in lower:
        return "in"
    if "outbound" in lower:
        return "out"
    logger.warning("Unrecognized Direction field value: %r", raw)
    return "unknown"


def _parse_event_xml(xml_str: str) -> Optional[ConnectionEvent]:
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        logger.warning("Could not parse event XML")
        return None

    system = root.find(f"{_EVT_NS}System")
    event_id_elem = system.find(f"{_EVT_NS}EventID") if system is not None else None
    if event_id_elem is None or event_id_elem.text is None:
        return None
    event_id = int(event_id_elem.text)
    if event_id not in (EVENT_ID_ALLOWED, EVENT_ID_BLOCKED):
        return None

    time_elem = system.find(f"{_EVT_NS}TimeCreated")
    timestamp = dt.datetime.utcnow()
    if time_elem is not None and time_elem.get("SystemTime"):
        try:
            timestamp = dt.datetime.fromisoformat(
                time_elem.get("SystemTime").replace("Z", "+00:00")
            )
        except ValueError:
            pass

    event_data = root.find(f"{_EVT_NS}EventData")
    data_elems = event_data.findall(f"{_EVT_NS}Data") if event_data is not None else []

    direction = _decode_direction(_get_field(data_elems, "Direction"))

    return ConnectionEvent(
        timestamp=timestamp,
        event_id=event_id,
        application_path=_get_field(data_elems, "Application"),
        direction=direction,
        protocol=_get_field(data_elems, "Protocol"),
        source_address=_get_field(data_elems, "SourceAddress"),
        source_port=_get_field(data_elems, "SourcePort"),
        dest_address=_get_field(data_elems, "DestAddress"),
        dest_port=_get_field(data_elems, "DestPort"),
    )


class ConnectionMonitor:
    """
    Subscribes to Security-log connection events using the callback model
    and forwards parsed events to every registered handler.

    Usage:
        monitor = ConnectionMonitor(blocked_only=False)
        monitor.on_event(lambda evt: print(evt))
        monitor.start()
        ...
        monitor.stop()
    """

    def __init__(self, dedup_window_seconds: float = DEDUP_WINDOW_SECONDS,
                 blocked_only: bool = False):
        self._callbacks: list[Callable[[ConnectionEvent], None]] = []
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._dedup_window = dedup_window_seconds
        self._recent: dict[tuple, float] = {}
        self._blocked_only = blocked_only
        self._subscription = None
        self.last_error: Optional[str] = None
        self.subscribed_ok = False

    def on_event(self, callback: Callable[[ConnectionEvent], None]) -> None:
        self._callbacks.append(callback)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("ConnectionMonitor started.")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("ConnectionMonitor stopped.")

    def _emit(self, event: ConnectionEvent) -> None:
        now = time.monotonic()
        key = event.dedup_key()
        last_seen = self._recent.get(key)
        if last_seen is not None and (now - last_seen) < self._dedup_window:
            self._recent[key] = now
            return
        self._recent[key] = now
        for cb in self._callbacks:
            try:
                cb(event)
            except Exception:
                logger.exception("Connection event callback raised")

    def _on_evt_callback(self, action, _context, event_handle) -> int:
        if action == win32evtlog.EvtSubscribeActionError:
            logger.warning("Subscription callback reported an error (code: %s)", event_handle)
            return 0
        try:
            xml_str = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
            parsed = _parse_event_xml(xml_str)
            if parsed:
                self._emit(parsed)
        except Exception:
            logger.exception("Failed to process delivered event")
        return 0

    def _run(self) -> None:
        if self._blocked_only:
            query = f"*[System[(EventID={EVENT_ID_BLOCKED})]]"
        else:
            query = f"*[System[(EventID={EVENT_ID_ALLOWED} or EventID={EVENT_ID_BLOCKED})]]"

        try:
            self._subscription = win32evtlog.EvtSubscribe(
                SECURITY_CHANNEL,
                win32evtlog.EvtSubscribeToFutureEvents,
                Callback=self._on_evt_callback,
                Query=query,
            )
        except Exception as exc:
            self.last_error = str(exc)
            logger.error(
                "Failed to subscribe to Security log (need admin rights, and "
                "WFP auditing must be enabled): %s", exc
            )
            return

        self.subscribed_ok = True
        logger.info("Subscribed successfully (callback mode) -- waiting for live events...")

        while not self._stop_event.is_set():
            time.sleep(0.25)

        self._subscription = None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    if not is_wfp_auditing_enabled():
        print("WFP auditing is off -- enabling now (requires admin)...")
        enable_wfp_auditing()
    else:
        print("WFP auditing already enabled.")

    def _print_event(evt: ConnectionEvent) -> None:
        verdict = "ALLOWED" if evt.was_allowed else "BLOCKED"
        print(f"[{evt.timestamp}] {verdict} {evt.direction.upper()} "
              f"{evt.application_path} -> {evt.dest_address}:{evt.dest_port} "
              f"({evt.protocol_name})")

    monitor = ConnectionMonitor()
    monitor.on_event(_print_event)
    monitor.start()
    print("Watching for new connections for 20 seconds -- try pinging this "
          "PC from another device on your network to test inbound detection.")
    time.sleep(1)
    print(f"Subscribed OK: {monitor.subscribed_ok}, last_error: {monitor.last_error}")
    try:
        time.sleep(19)
    except KeyboardInterrupt:
        pass
    monitor.stop()
