"""
main.py

The real entry point -- launches the actual Qt UI.

Startup sequence:
  1. Self-elevate via UAC if not already running as admin.
  2. Initialize the backend: RuleStore, FirewallEngine, AppConfig.
  3. Enable WFP connection auditing automatically if it isn't already.
  4. Run the first-run wizard if this is the first launch on this
     machine (still a CLI prompt for now -- ui/first_run_wizard.py will
     replace run_first_run_wizard_cli() later). Choosing "block
     everything new" here now ALSO actually enables lockdown mode
     (flips the default outbound action to Block, via
     import_export.enable_lockdown_mode) -- previously this choice only
     set a settings flag and had no real effect, which meant outbound
     traffic from unknown apps flowed freely regardless of what you
     picked at first run. "Import existing as trusted" does NOT enable
     lockdown mode automatically -- it's meant to be a gentler baseline;
     you can turn lockdown mode on later from Settings once you've
     reviewed what's already trusted.
  5. Hide the console window.
  6. Build the NotificationManager (not started yet).
  7. Build the Qt application and the real ShellWindow.
  8. Start the NotificationManager, apply the saved theme, show the
     window, hand off to the Qt event loop.
"""

from __future__ import annotations

import ctypes
import logging
import sys
from pathlib import Path

# sagefw-restructure-v1
_APP_DIR = Path(__file__).resolve().parent / "app"
for _p in (_APP_DIR, _APP_DIR / "ui"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from PyQt6.QtWidgets import QApplication

from config import AppConfig
from connection_monitor import enable_wfp_auditing, is_wfp_auditing_enabled
from firewall_engine import FirewallEngine
from import_export import (
    first_run_block_everything, first_run_import_existing, is_first_run_completed,
    enable_lockdown_mode,
)
from notification_manager import NotificationManager
from rule_store import RuleStore

sys.path.append(str(Path(__file__).resolve().parent / "app" / "ui"))
from shell import ShellWindow, _make_app_icon  # noqa: E402  (import after sys.path append, by necessity)
from notification_popup import apply_fluent_theme  # noqa: E402

logger = logging.getLogger(__name__)

SW_HIDE = 0


# ---------- step 1: elevation ----------

def is_running_as_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> None:
    """Re-runs this exact script elevated via a UAC prompt, then exits the
    current non-elevated process. If the user clicks 'No' on the UAC
    prompt, ShellExecuteW simply doesn't launch anything and we exit."""
    params = " ".join(f'"{arg}"' for arg in sys.argv[1:])
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{sys.argv[0]}" {params}', None, 1
    )
    sys.exit(0)


def ensure_elevated() -> None:
    if not is_running_as_admin():
        logger.info("Not running as admin -- requesting elevation via UAC...")
        relaunch_as_admin()
    logger.info("Running with administrator privileges.")


# ---------- step 5: hide the console window ----------

def hide_console_window() -> None:
    """Hides (does not close) the console window backing this process."""
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, SW_HIDE)
    except Exception as exc:
        logger.debug("Could not hide console window (non-fatal): %s", exc)


# ---------- step 3: auditing setup ----------

def ensure_wfp_auditing(config: AppConfig) -> None:
    if config.wfp_auditing_enabled and is_wfp_auditing_enabled():
        logger.info("WFP connection auditing already enabled (per stored setting).")
        return
    if is_wfp_auditing_enabled():
        config.wfp_auditing_enabled = True
        logger.info("WFP connection auditing was already on at the OS level.")
        return
    logger.info("Enabling WFP connection auditing (one-time setup)...")
    enable_wfp_auditing()
    config.wfp_auditing_enabled = True


# ---------- step 4: first-run wizard ----------
# TEMPORARY CLI stand-in for ui/first_run_wizard.py.

def run_first_run_wizard_cli(engine: FirewallEngine, store: RuleStore) -> None:
    print("\n" + "=" * 60)
    print("Welcome! This is the first time running on this machine.")
    print("Choose a starting point:")
    print("  1) Import existing Windows Firewall rules as a trusted baseline")
    print("     (apps you've already allowed keep working; only genuinely")
    print("      new apps will prompt you going forward. Lockdown mode is")
    print("      NOT enabled automatically -- turn it on later from Settings")
    print("      once you've reviewed what's already trusted.)")
    print("  2) Start from zero -- block everything new by default")
    print("     (this ALSO enables lockdown mode right now: every app without")
    print("      an explicit allow rule will be blocked and prompt you. A")
    print("      safety snapshot is taken automatically first.)")
    print("=" * 60)
    choice = input("Enter 1 or 2: ").strip()

    if choice == "1":
        count = first_run_import_existing(engine, store)
        print(f"Imported metadata for {count} existing app(s) as trusted.")
        print("Lockdown mode is OFF -- enable it from Settings whenever you're ready.")
    else:
        first_run_block_everything(store)
        snapshot_id = enable_lockdown_mode(engine, store)
        print(f"Lockdown mode ENABLED. Safety snapshot #{snapshot_id} was created first.")
        print("You'll be prompted for new outbound apps as they connect from now on.")


# ---------- orchestration ----------

# sagefw-startup-v1
SINGLE_INSTANCE_NAME = "Global\\SageFW_SingleInstance"
_instance_handle = None


def _kernel32():
    import ctypes.wintypes as _wt
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenMutexW.argtypes = [_wt.DWORD, _wt.BOOL, _wt.LPCWSTR]
    k.OpenMutexW.restype = ctypes.c_void_p
    k.CreateMutexW.argtypes = [ctypes.c_void_p, _wt.BOOL, _wt.LPCWSTR]
    k.CreateMutexW.restype = ctypes.c_void_p
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    return k


def is_already_running() -> bool:
    # Check only (no creating): the real mutex is created by the elevated process, so the
    # un-elevated launcher must not hold it while it hands over to the UAC relaunch.
    try:
        k = _kernel32()
        handle = k.OpenMutexW(0x00100000, False, SINGLE_INSTANCE_NAME)  # SYNCHRONIZE
        if handle:
            k.CloseHandle(handle)
            return True
        return ctypes.get_last_error() == 5  # access denied: owned by an elevated instance
    except Exception:
        return False


def acquire_single_instance() -> bool:
    global _instance_handle
    try:
        k = _kernel32()
        handle = k.CreateMutexW(None, False, SINGLE_INSTANCE_NAME)
        err = ctypes.get_last_error()
        if not handle:
            return err != 5
        if err == 183:  # ERROR_ALREADY_EXISTS
            k.CloseHandle(handle)
            return False
        _instance_handle = handle  # held until the process exits
        return True
    except Exception:
        return True  # never block startup because of a failed check


def show_already_running_message() -> None:
    try:
        ctypes.windll.user32.MessageBoxW(
            None,
            "SageFW is already running.\n\nLook for its icon in the system tray "
            "(bottom-right of the taskbar; you may need to click the ^ arrow), "
            "then double-click it to open the window.",
            "SageFW", 0x40)
    except Exception:
        print("SageFW is already running (check the system tray).")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if is_already_running():
        show_already_running_message()
        return
    ensure_elevated()
    if not acquire_single_instance():
        show_already_running_message()
        return

    store = RuleStore()
    engine = FirewallEngine()
    config = AppConfig(store)

    ensure_wfp_auditing(config)

    if not is_first_run_completed(store):
        run_first_run_wizard_cli(engine, store)
    else:
        logger.info("First-run setup already completed (mode: %s).", config.first_run_mode)

    hide_console_window()

    manager = NotificationManager(
        store, engine,
        prompt_timeout_seconds=config.prompt_timeout_seconds,
        grab_focus_inbound=config.grab_focus_inbound,
        grab_focus_outbound=config.grab_focus_outbound,
    )

    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SageFW.App")
    except Exception:
        pass
    app = QApplication(sys.argv)
    app.setWindowIcon(_make_app_icon())
    apply_fluent_theme(dark=(config.theme == "dark"))

    window = ShellWindow(engine, store, manager, config)

    manager.start()
    window.show()

    logger.info("SageFW is running (console hidden). Close the window "
                "to minimize to tray; use the tray menu or Ctrl+Q to exit.")
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

# sagefw-patch-v1
