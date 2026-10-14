"""
config.py

Thin, typed wrapper around rule_store's generic key/value settings table.
Nothing here talks to the firewall or UI directly -- it just centralizes
default values and typed access so settings aren't scattered as magic
strings/numbers across main.py and the UI modules.

Usage:
    store = RuleStore()
    cfg = AppConfig(store)
    cfg.prompt_timeout_seconds        # reads with default fallback
    cfg.prompt_timeout_seconds = 30   # writes through to the store
"""

from __future__ import annotations

from rule_store import RuleStore

DEFAULTS = {
    "prompt_timeout_seconds": 25,
    "grab_focus_inbound": True,
    "grab_focus_outbound": True,
    "lockdown_mode_enabled": False,
    "first_run_completed": False,
    "first_run_mode": None,          # "import_existing" or "block_everything"
    "wfp_auditing_enabled": False,
    "theme": "dark",                 # UI theme, read by ui/shell.py later
}


class AppConfig:
    def __init__(self, store: RuleStore):
        self._store = store

    def _get(self, key: str):
        return self._store.get_setting(key, DEFAULTS.get(key))

    def _set(self, key: str, value) -> None:
        self._store.set_setting(key, value)

    @property
    def prompt_timeout_seconds(self) -> float:
        return self._get("prompt_timeout_seconds")

    @prompt_timeout_seconds.setter
    def prompt_timeout_seconds(self, value: float) -> None:
        self._set("prompt_timeout_seconds", value)

    @property
    def grab_focus_inbound(self) -> bool:
        return self._get("grab_focus_inbound")

    @grab_focus_inbound.setter
    def grab_focus_inbound(self, value: bool) -> None:
        self._set("grab_focus_inbound", value)

    @property
    def grab_focus_outbound(self) -> bool:
        return self._get("grab_focus_outbound")

    @grab_focus_outbound.setter
    def grab_focus_outbound(self, value: bool) -> None:
        self._set("grab_focus_outbound", value)

    @property
    def lockdown_mode_enabled(self) -> bool:
        return self._get("lockdown_mode_enabled")

    @property
    def first_run_completed(self) -> bool:
        return bool(self._get("first_run_completed"))

    @property
    def first_run_mode(self) -> str | None:
        return self._get("first_run_mode")

    @property
    def wfp_auditing_enabled(self) -> bool:
        return bool(self._get("wfp_auditing_enabled"))

    @wfp_auditing_enabled.setter
    def wfp_auditing_enabled(self, value: bool) -> None:
        self._set("wfp_auditing_enabled", value)

    @property
    def theme(self) -> str:
        return self._get("theme")

    @theme.setter
    def theme(self, value: str) -> None:
        self._set("theme", value)
