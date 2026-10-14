"""
core/import_export.py

Three related jobs:

1. FIRST-RUN BASELINE CHOICE
   - "Import existing rules as trusted baseline": pre-existing native
     Allow rules keep working exactly as before (Windows evaluates
     specific Allow rules before the default action, regardless of what
     we do later) -- so there's nothing to "import" for enforcement
     purposes. What we DO need is to record friendly metadata (name,
     icon, publisher) for the apps behind those existing rules, so the
     Rules Manager UI can display them nicely from day one instead of
     showing a blank list until each app happens to trigger a new event.
   - "Block everything new": skips that import step -- every app starts
     from zero and gets prompted the first time it tries to connect.

2. BACKUP / RESTORE (SNAPSHOTS)
   - take_snapshot() captures every current native rule PLUS the current
     default inbound/outbound action per profile -- both are needed to
     fully restore firewall state, not just the rule list.
   - restore_snapshot() puts default actions back, then removes any
     current [NFW]-prefixed rules and recreates exactly what was in the
     snapshot. Non-[NFW] rules (yours, Windows', or other software's) are
     never touched by restore -- we only ever created/manage rules
     carrying our prefix, so that's all we ever roll back.

3. ORPHANED RULE CLEANUP ("Tidy Up")
   - find_orphaned_rules() scans EVERY current rule (any origin -- ours,
     Windows', or other software's) that references an application path,
     and flags ones where that path no longer exists on disk. This is
     genuinely common cruft: Windows Firewall never automatically removes
     rules when you uninstall software, so systems accumulate dead rules
     referencing long-gone .exe paths over years.
   - Two specific cases are deliberately excluded from being flagged,
     found via real-world testing:
       a) ApplicationName == "System" -- Windows' kernel pseudo-process
          value, used by many built-in rules (Hyper-V, File and Printer
          Sharing, Remote Desktop, etc.). It's not a path to check for
          existence at all, and app_resolver.py already special-cases it
          the same way for the same reason.
       b) A bare filename with no path separator at all (e.g. just
          "svchost.exe") -- these are intentionally generic, "match this
          process regardless of location" rules, not a specific stale
          path. Treating them as orphaned would be a false positive: they
          were never pointing at one specific file to begin with.
   - Deleting a genuinely orphaned rule is safe regardless of who created
     it -- if the target application doesn't exist, the rule can't
     possibly still be doing anything useful. A safety snapshot is taken
     automatically before any tidy-up deletion regardless.

No UI dependency. This is the module you call right before flipping on
lockdown mode, the one you reach for if a lockdown session goes wrong,
and the one behind the "Tidy Up" button in the Rules page.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import os
from typing import Optional

from firewall_engine import (
    FirewallEngine, FirewallRule, RULE_PREFIX,
    PROFILE_DOMAIN, PROFILE_PRIVATE, PROFILE_PUBLIC,
    ACTION_ALLOW, ACTION_BLOCK,
)
from app_resolver import resolve_app, path_exists
from rule_store import RuleStore

logger = logging.getLogger(__name__)

_META_MARKER = "__nfw_snapshot_meta__"
ALL_PROFILES = (PROFILE_DOMAIN, PROFILE_PRIVATE, PROFILE_PUBLIC)
PROFILE_NAMES = {PROFILE_DOMAIN: "domain", PROFILE_PRIVATE: "private", PROFILE_PUBLIC: "public"}


# ---------- first-run baseline ----------

def first_run_import_existing(engine: FirewallEngine, store: RuleStore) -> int:
    """
    Walks every existing native rule that references an application, and
    caches friendly metadata (name/icon/publisher) for it via app_resolver,
    so the Rules Manager UI has something nice to show immediately.
    Existing rules are left completely untouched -- this only populates
    our local metadata cache, nothing about enforcement changes.
    Returns the number of apps that got metadata cached.
    """
    all_rules = engine.list_rules(ours_only=False)
    seen_paths = set()
    cached = 0
    for rule in all_rules:
        if not rule.application_path or rule.application_path in seen_paths:
            continue
        seen_paths.add(rule.application_path)
        info = resolve_app(rule.application_path)
        store.upsert_app_metadata(
            app_path=info.original_path,
            display_name=info.display_name,
            publisher=info.publisher,
            icon_cache_path=info.icon_path or "",
            is_uwp=info.is_uwp,
            package_family=info.package_family_name or "",
        )
        cached += 1

    store.set_setting("first_run_mode", "import_existing")
    store.set_setting("first_run_completed", True)
    logger.info("First-run import complete -- cached metadata for %d app(s).", cached)
    return cached


def first_run_block_everything(store: RuleStore) -> None:
    """
    The alternative first-run choice: don't pre-populate anything. Every
    app gets prompted fresh the first time it tries to connect. Actually
    flipping the default-outbound action to Block is a separate, explicit
    step -- see enable_lockdown_mode() -- so choosing this here does not
    immediately start blocking traffic.
    """
    store.set_setting("first_run_mode", "block_everything")
    store.set_setting("first_run_completed", True)
    logger.info("First-run set to 'block everything new' -- no baseline imported.")


def is_first_run_completed(store: RuleStore) -> bool:
    return bool(store.get_setting("first_run_completed", False))


# ---------- snapshots (backup / restore) ----------

def take_snapshot(engine: FirewallEngine, store: RuleStore, label: str) -> int:
    """
    Captures every current native rule plus the current default
    inbound/outbound action for every profile. Returns the snapshot id.
    Safe to call anytime -- purely a read operation against the firewall.
    """
    rules = engine.list_rules(ours_only=False)
    rule_dicts = [dataclasses.asdict(r) for r in rules]

    default_actions = {}
    for profile in ALL_PROFILES:
        default_actions[PROFILE_NAMES[profile]] = {
            "outbound": engine.get_default_outbound_action(profile),
            "inbound": engine.get_default_inbound_action(profile),
        }

    meta_entry = {
        _META_MARKER: True,
        "captured_at": dt.datetime.utcnow().isoformat(),
        "default_actions": default_actions,
        "rule_count": len(rule_dicts),
    }

    snapshot_id = store.save_snapshot(label, [meta_entry] + rule_dicts)
    logger.info("Snapshot '%s' captured: %d rule(s), id=%d", label, len(rule_dicts), snapshot_id)
    return snapshot_id


def list_snapshots(store: RuleStore) -> list[dict]:
    return store.list_snapshots()


def _split_snapshot_payload(payload: list[dict]) -> tuple[Optional[dict], list[dict]]:
    if payload and isinstance(payload[0], dict) and payload[0].get(_META_MARKER):
        return payload[0], payload[1:]
    return None, payload  # Older/plain snapshot with no meta entry.


def restore_snapshot(engine: FirewallEngine, store: RuleStore, snapshot_id: int,
                      restore_default_actions: bool = True) -> dict:
    """
    Restores firewall state from a snapshot:
      1. Puts default inbound/outbound actions back (if the snapshot has
         them and restore_default_actions=True).
      2. Removes every CURRENT rule carrying our [NFW] prefix.
      3. Recreates every [NFW]-prefixed rule exactly as captured in the
         snapshot.
    Non-[NFW] rules are never touched -- restore only ever affects rules
    this app itself created.

    Returns a small summary dict for the UI to display/log.
    """
    payload = store.load_snapshot(snapshot_id)
    meta, rule_dicts = _split_snapshot_payload(payload)

    restored_defaults = False
    if restore_default_actions and meta:
        for profile in ALL_PROFILES:
            profile_name = PROFILE_NAMES[profile]
            actions = meta.get("default_actions", {}).get(profile_name)
            if not actions:
                continue
            try:
                if actions["outbound"] == ACTION_BLOCK:
                    engine._policy.DefaultOutboundAction[profile] = ACTION_BLOCK
                else:
                    engine._policy.DefaultOutboundAction[profile] = ACTION_ALLOW
                if actions["inbound"] == ACTION_BLOCK:
                    engine._policy.DefaultInboundAction[profile] = ACTION_BLOCK
                else:
                    engine._policy.DefaultInboundAction[profile] = ACTION_ALLOW
            except Exception as exc:
                logger.warning("Could not restore default action for %s profile: %s", profile_name, exc)
        restored_defaults = True

    current_ours = engine.list_rules(ours_only=True)
    removed = engine.delete_rules(r.name for r in current_ours)

    recreated = 0
    for rule_dict in rule_dicts:
        if not rule_dict.get("is_ours", rule_dict.get("name", "").startswith(RULE_PREFIX)):
            continue  # Safety net -- only ever recreate our own rules.
        try:
            rule = FirewallRule(**{k: v for k, v in rule_dict.items() if k in FirewallRule.__dataclass_fields__})
            engine.create_rule(rule, overwrite=True)
            recreated += 1
        except Exception as exc:
            logger.warning("Could not recreate rule '%s' from snapshot: %s", rule_dict.get("name"), exc)

    summary = {
        "snapshot_id": snapshot_id,
        "defaults_restored": restored_defaults,
        "rules_removed": removed,
        "rules_recreated": recreated,
    }
    logger.info("Restore complete: %s", summary)
    return summary


def delete_snapshot(store: RuleStore, snapshot_id: int) -> None:
    store.delete_snapshot(snapshot_id)


# ---------- lockdown mode switch (uses snapshots as a safety net) ----------

def enable_lockdown_mode(engine: FirewallEngine, store: RuleStore) -> int:
    """
    Takes an automatic safety snapshot labeled 'pre-lockdown-baseline',
    THEN sets the default outbound action to Block on every profile.
    Always call this rather than engine.block_all_outbound_default()
    directly, so there's always a one-click way back.
    Returns the snapshot id, for immediate display ("Undo available: #N").
    """
    snapshot_id = take_snapshot(engine, store, label="pre-lockdown-baseline")
    engine.block_all_outbound_default()
    store.set_setting("lockdown_mode_enabled", True)
    logger.info("Lockdown mode ENABLED. Safety snapshot id=%d.", snapshot_id)
    return snapshot_id


def disable_lockdown_mode(engine: FirewallEngine, store: RuleStore) -> None:
    """Reverts just the default outbound action to Allow. Does NOT remove
    any allow/block rules created while lockdown was on -- use
    restore_snapshot() if you want a full rollback instead."""
    engine.restore_default_outbound_allow()
    store.set_setting("lockdown_mode_enabled", False)
    logger.info("Lockdown mode DISABLED (default outbound action restored to Allow).")


# ---------- orphaned rule cleanup ("Tidy Up") ----------

_SYSTEM_PSEUDO_VALUES = {"system", ""}


def _looks_like_a_real_path(application_path: str) -> bool:
    """True only for values that could plausibly be a stale file path --
    excludes the 'System' kernel pseudo-process and bare filenames with
    no path separator (generic 'match this process anywhere' rules,
    which were never pointing at one specific file to begin with)."""
    normalized = application_path.strip().lower()
    if normalized in _SYSTEM_PSEUDO_VALUES:
        return False
    if "\\" not in application_path and "/" not in application_path:
        return False
    return True


def find_orphaned_rules(engine: FirewallEngine, ours_only: bool = False) -> list[FirewallRule]:
    """
    Scans current rules for ones referencing an application path that no
    longer exists on disk. Checks EVERY rule by default (ours_only=False)
    since Windows itself never cleans these up after you uninstall
    software -- pre-existing native rules go stale just as easily as
    ones we might create.

    Rules are skipped (never flagged) when application_path is empty,
    is the literal "System" kernel pseudo-value, or is a bare filename
    with no path at all -- see _looks_like_a_real_path().

    Paths are expanded (os.path.expandvars) before checking, since some
    native rules store paths like '%ProgramFiles%\\App\\app.exe' rather
    than a fully resolved path.
    """
    orphaned = []
    for rule in engine.list_rules(ours_only=ours_only):
        if not rule.application_path:
            continue
        if not _looks_like_a_real_path(rule.application_path):
            continue
        expanded = os.path.expandvars(rule.application_path)
        if not path_exists(expanded):
            orphaned.append(rule)
    return orphaned


def tidy_up_orphaned_rules(engine: FirewallEngine, store: RuleStore,
                            rule_names: list[str]) -> dict:
    """
    Deletes exactly the given rule names (expected to be a subset of --
    or equal to -- what find_orphaned_rules() returned; the caller, i.e.
    the UI, decides which ones the user actually confirmed). Takes an
    automatic safety snapshot first, consistent with every other
    destructive action here.

    Returns a summary dict: {snapshot_id, rules_removed}.
    """
    snapshot_id = take_snapshot(engine, store, label="pre-tidyup-cleanup")
    removed = engine.delete_rules(rule_names)
    logger.info("Tidy up complete: removed %d orphaned rule(s). Safety snapshot id=%d.",
                removed, snapshot_id)
    return {"snapshot_id": snapshot_id, "rules_removed": removed}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    engine = FirewallEngine()
    store = RuleStore()

    print("--- Taking a safety snapshot (non-destructive, just a backup) ---")
    snap_id = take_snapshot(engine, store, label="manual-test-snapshot")
    print(f"Snapshot id: {snap_id}")

    print("\n--- All snapshots on file ---")
    for s in list_snapshots(store):
        print(f"  #{s['id']}  {s['label']}  ({s['created_at']})")

    print("\n--- Simulating 'import existing rules' first-run choice ---")
    count = first_run_import_existing(engine, store)
    print(f"Cached metadata for {count} app(s) with existing rules.")
    print(f"first_run_completed = {is_first_run_completed(store)}")

    print("\n--- Scanning for orphaned rules (apps that no longer exist) ---")
    orphaned = find_orphaned_rules(engine)
    print(f"Found {len(orphaned)} orphaned rule(s):")
    for r in orphaned[:20]:
        print(f"  - {r.name}  ->  {r.application_path}")

    print("\nNOTE: enable_lockdown_mode()/restore_snapshot()/tidy_up_orphaned_rules() "
          "were NOT run in this smoke test -- they change live firewall state, so "
          "they're left for you to call deliberately once you're ready.")

    store.close()
