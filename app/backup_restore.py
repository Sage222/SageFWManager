"""
backup_restore.py -- full-fidelity backup and restore of Windows Firewall rules.

A SageFW backup is a JSON file holding EVERY rule with every setting SageFW can read (including
the advanced ones in FirewallRule.extra) plus the per-profile defaults (on/off, default inbound and
outbound action). A Windows-native .wfw policy file is saved beside it when possible.

Everything is stored under <app folder>/data/backups, so it travels with the app.
No Qt here: this module only needs a FirewallEngine.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from firewall_engine import FirewallRule

BACKUP_FORMAT = "sagefw-firewall-backup"
BACKUP_VERSION = 1
_FIELDS = {f.name for f in dataclasses.fields(FirewallRule)}


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def default_backup_dir() -> Path:
    path = app_dir() / "data" / "backups"
    path.mkdir(parents=True, exist_ok=True)
    return path


def rule_to_dict(rule: FirewallRule) -> dict:
    return dataclasses.asdict(rule)


def rule_from_dict(data: dict) -> FirewallRule:
    return FirewallRule(**{k: v for k, v in data.items() if k in _FIELDS})


def rule_key(rule: FirewallRule) -> str:
    return json.dumps(rule_to_dict(rule), sort_keys=True, default=str)


def _no_window() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)


def export_native(path) -> bool:
    try:
        result = subprocess.run(["netsh", "advfirewall", "export", str(path)], capture_output=True,
                                text=True, timeout=120, creationflags=_no_window())
        return result.returncode == 0 and Path(path).exists()
    except Exception:
        return False


def import_native(path) -> tuple[bool, str]:
    try:
        result = subprocess.run(["netsh", "advfirewall", "import", str(path)], capture_output=True,
                                text=True, timeout=180, creationflags=_no_window())
        return result.returncode == 0, (result.stdout or result.stderr or "").strip()
    except Exception as exc:
        return False, str(exc)


def create_backup(engine, directory=None, label: str = "", include_native: bool = True) -> dict:
    directory = Path(directory) if directory else default_backup_dir()
    directory.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    base = f"sagefw-{label + '-' if label else ''}backup-{stamp}"
    rules = engine.list_rules(ours_only=False, include_extra=True)
    payload = {
        "format": BACKUP_FORMAT,
        "version": BACKUP_VERSION,
        "created": dt.datetime.now().isoformat(timespec="seconds"),
        "computer": os.environ.get("COMPUTERNAME", ""),
        "defaults": engine.get_policy_defaults(),
        "rules": [rule_to_dict(r) for r in rules],
    }
    json_path = directory / f"{base}.json"
    tmp = json_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    tmp.replace(json_path)
    wfw_path = None
    if include_native:
        candidate = directory / f"{base}.wfw"
        wfw_path = candidate if export_native(candidate) else None
    return {"json": json_path, "wfw": wfw_path, "rules": len(rules)}


def load_backup(path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("format") != BACKUP_FORMAT:
        raise ValueError("This file is not a SageFW firewall backup.")
    if int(data.get("version", 0)) > BACKUP_VERSION:
        raise ValueError("This backup was made by a newer version of SageFW.")
    data["_rules"] = [rule_from_dict(d) for d in data.get("rules", [])]
    return data


def _group(rules) -> dict:
    groups = defaultdict(list)
    for rule in rules:
        groups[rule.name].append(rule)
    return groups


def plan_restore(current_rules, backup_rules, mode: str) -> list[dict]:
    """
    mode "missing": recreate backed-up rule names that do not exist now; touch nothing else.
    mode "replace": for every rule name whose rules differ from the backup, remove the current
                    rules with that name and create the backed-up ones (also removes names that
                    are not in the backup).
    Rules are handled per NAME because the firewall API can only delete by name.
    """
    cur, bak = _group(current_rules), _group(backup_rules)
    actions = []
    if mode == "missing":
        for name, rules in bak.items():
            if name not in cur:
                actions.append({"name": name, "delete": 0, "create": rules})
    else:
        for name in sorted(set(cur) | set(bak)):
            same = sorted(map(rule_key, cur.get(name, []))) == sorted(map(rule_key, bak.get(name, [])))
            if not same:
                actions.append({"name": name, "delete": len(cur.get(name, [])), "create": bak.get(name, [])})
    return actions


def summarize(actions) -> dict:
    return {"groups": len(actions), "create": sum(len(a["create"]) for a in actions),
            "delete": sum(a["delete"] for a in actions)}


def execute_restore(engine, actions) -> dict:
    created = deleted = 0
    failed = []
    for action in actions:
        try:
            if action["delete"]:
                tries = 0
                while tries < 500 and engine.delete_rule(action["name"]):
                    tries += 1
                deleted += action["delete"]
            for rule in action["create"]:
                engine.create_rule(rule, overwrite=False)
                created += 1
        except Exception as exc:
            failed.append((action["name"], str(exc)))
    return {"created": created, "deleted": deleted, "failed": failed}


def verify_restore(engine, actions, backup_rules) -> list[str]:
    """Names whose rules are still not identical to the backup after a restore."""
    cur = _group(engine.list_rules(ours_only=False, include_extra=True))
    bak = _group(backup_rules)
    return [a["name"] for a in actions
            if sorted(map(rule_key, cur.get(a["name"], []))) != sorted(map(rule_key, bak.get(a["name"], [])))]
