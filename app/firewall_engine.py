"""
core/firewall_engine.py

Thin, UI-agnostic wrapper around the native Windows Firewall COM API
(INetFwPolicy2 / INetFwRule2). No kernel driver, no core isolation impact --
this talks to the exact same engine that Windows Defender Firewall itself
uses (netsh advfirewall / wf.msc), just programmatically.

Every native firewall rule created here gets a name prefix (RULE_PREFIX) so
we can reliably tell "ours" apart from rules created by Windows, other apps,
or the user manually. This module has zero UI dependencies -- it can be
imported and exercised from a plain Python shell.

COM quirk (pywin32 dynamic dispatch): indexed properties like
FirewallEnabled and DefaultOutboundAction take a profile argument.
- READS must be called as a method:      policy.FirewallEnabled(profile)
- WRITES use bracket assignment:          policy.FirewallEnabled[profile] = value
Mixing these up raises "'method' object is not subscriptable".

Rules.Add() failure mode: the underlying Windows Firewall COM engine
returns a generic E_INVALIDARG (-2147024809) if ANY property on the rule
object is invalid -- it does not say which one, and critically, an
individual property *assignment* can succeed without error while still
being the actual reason Add() rejects the rule as a whole (validation is
deferred until Add() commits). Two things address this:
  1. Application paths are normalized via os.path.normpath() before being
     set -- Qt's QFileDialog can return forward-slash paths
     ("C:/Program Files/...") which Windows Firewall's COM engine can
     silently accept at assignment time but reject at Add() time.
  2. Every optional property set is individually wrapped, and any
     warnings are collected and included directly in the raised
     exception message -- not just logged -- so the actual cause is
     visible in a UI error dialog even when there's no visible console
     to check (e.g. once main.py has hidden it).
"""

from __future__ import annotations

import dataclasses
import enum
import logging
import os
from typing import Iterable, Optional

import win32com.client
import pythoncom

logger = logging.getLogger(__name__)

RULE_PREFIX = "[NFW] "  # "Nicer FireWall" -- change to taste, keep short.

# NET_FW_RULE_DIRECTION_
DIR_IN = 1
DIR_OUT = 2

# NET_FW_ACTION_
ACTION_BLOCK = 0
ACTION_ALLOW = 1

# NET_FW_PROFILE2_
PROFILE_DOMAIN = 1
PROFILE_PRIVATE = 2
PROFILE_PUBLIC = 4
PROFILE_ALL = PROFILE_DOMAIN | PROFILE_PRIVATE | PROFILE_PUBLIC

# NET_FW_IP_PROTOCOL_
PROTOCOL_TCP = 6
PROTOCOL_UDP = 17
PROTOCOL_ANY = 256


class Direction(enum.IntEnum):
    IN = DIR_IN
    OUT = DIR_OUT


class Action(enum.IntEnum):
    BLOCK = ACTION_BLOCK
    ALLOW = ACTION_ALLOW


# sagefw-fullrule-v1
# Settings beyond FirewallRule's named fields. They are read only on request (include_extra=True)
# because reading them for every rule on every refresh would slow the lists down.
EXTRA_PROPERTIES = (
    "LocalAddresses", "IcmpTypesAndCodes", "Interfaces", "LocalAppPackageId", "LocalUserOwner",
    "LocalUserAuthorizedList", "RemoteUserAuthorizedList", "RemoteMachineAuthorizedList",
    "SecureFlags", "EdgeTraversalOptions",
)


def read_extra_properties(com_rule) -> dict:
    out = {}
    for prop in EXTRA_PROPERTIES:
        try:
            value = getattr(com_rule, prop)
        except Exception:
            continue
        if isinstance(value, (tuple, list)):
            value = [str(v) for v in value]
        elif value is not None and not isinstance(value, (str, int, float, bool)):
            value = str(value)
        out[prop] = value
    return out


@dataclasses.dataclass
class FirewallRule:
    """Plain-data snapshot of a firewall rule. Safe to serialize / diff."""
    name: str
    description: str = ""
    application_path: Optional[str] = None
    service_name: Optional[str] = None
    protocol: int = PROTOCOL_ANY
    local_ports: str = "*"
    remote_ports: str = "*"
    remote_addresses: str = "*"
    direction: int = DIR_OUT
    action: int = ACTION_BLOCK
    enabled: bool = True
    profiles: int = PROFILE_ALL
    grouping: str = ""
    edge_traversal: bool = False
    interface_types: str = "All"
    is_ours: bool = False  # True if name starts with RULE_PREFIX
    extra: dict = dataclasses.field(default_factory=dict)  # advanced settings (include_extra=True)

    @classmethod
    def from_com(cls, com_rule, include_extra: bool = False) -> "FirewallRule":
        name = com_rule.Name or ""
        return cls(
            name=name,
            description=com_rule.Description or "",
            application_path=com_rule.ApplicationName or None,
            service_name=com_rule.ServiceName or None,
            protocol=com_rule.Protocol,
            local_ports=com_rule.LocalPorts or "*",
            remote_ports=com_rule.RemotePorts or "*",
            remote_addresses=com_rule.RemoteAddresses or "*",
            direction=com_rule.Direction,
            action=com_rule.Action,
            enabled=bool(com_rule.Enabled),
            profiles=com_rule.Profiles,
            grouping=com_rule.Grouping or "",
            edge_traversal=bool(getattr(com_rule, "EdgeTraversal", False)),
            interface_types=com_rule.InterfaceTypes or "All",
            is_ours=name.startswith(RULE_PREFIX),
            extra=(read_extra_properties(com_rule) if include_extra else {}),
        )


class FirewallEngineError(RuntimeError):
    """Raised when a COM call to the firewall fails."""


class BlockIncompatibleError(FirewallEngineError):
    """Raised when a rule cannot become a Block rule without clearing settings Windows forbids on Block rules."""

    def __init__(self, labels):
        super().__init__("Block rules cannot keep: " + "; ".join(labels))
        self.labels = list(labels)


class FirewallEngine:
    """
    Wraps HNetCfg.FwPolicy2. One instance per thread is recommended because
    COM apartment-threading rules apply -- if you use this from a worker
    thread (e.g. the connection monitor), call pythoncom.CoInitialize()
    in that thread first and construct a fresh FirewallEngine() there.
    """

    def __init__(self):
        pythoncom.CoInitialize()
        try:
            self._policy = win32com.client.Dispatch("HNetCfg.FwPolicy2")
        except Exception as exc:
            raise FirewallEngineError(
                "Could not connect to Windows Firewall COM interface. "
                "Is the 'Windows Defender Firewall' service running?"
            ) from exc

    # ---------- reads ----------

    def list_rules(self, ours_only: bool = False, include_extra: bool = False) -> list[FirewallRule]:
        rules = []
        for com_rule in self._policy.Rules:
            try:
                rule = FirewallRule.from_com(com_rule, include_extra)
            except Exception as exc:
                logger.warning("Skipping unreadable rule: %s", exc)
                continue
            if ours_only and not rule.is_ours:
                continue
            rules.append(rule)
        return rules

    def get_rule(self, name: str) -> Optional[FirewallRule]:
        for com_rule in self._policy.Rules:
            if com_rule.Name == name:
                return FirewallRule.from_com(com_rule)
        return None

    def is_firewall_enabled(self, profile: int = PROFILE_PRIVATE) -> bool:
        # Indexed property READ -> call as a method, not a subscript.
        return bool(self._policy.FirewallEnabled(profile))

    def get_default_outbound_action(self, profile: int = PROFILE_PRIVATE) -> int:
        return self._policy.DefaultOutboundAction(profile)

    def get_default_inbound_action(self, profile: int = PROFILE_PRIVATE) -> int:
        return self._policy.DefaultInboundAction(profile)

    def current_profile_types(self) -> int:
        """Bitmask of currently active profile(s), e.g. PROFILE_PRIVATE."""
        return self._policy.CurrentProfileTypes

    # ---------- writes ----------

    def create_rule(self, rule: FirewallRule, overwrite: bool = True) -> None:
        if overwrite:
            self.delete_rule(rule.name)

        com_rule = win32com.client.Dispatch("HNetCfg.FWRule")
        warnings: list[str] = []

        # --- Required core properties -- Windows Firewall needs these on
        # every rule, so these are set directly (no try/except) so a
        # failure here surfaces clearly rather than being silently skipped. ---
        com_rule.Name = rule.name
        com_rule.Direction = rule.direction
        com_rule.Action = rule.action
        com_rule.Enabled = rule.enabled
        com_rule.Profiles = rule.profiles

        # --- Optional/situational properties -- each wrapped individually.
        # Failures are both logged AND collected, so the actual cause is
        # visible in the final exception message too, not just the log. ---

        def _set(prop_name: str, value) -> None:
            try:
                setattr(com_rule, prop_name, value)
            except Exception as exc:
                msg = f"could not set '{prop_name}' = {value!r} ({exc})"
                logger.warning("Rule '%s': %s. Continuing without it.", rule.name, msg)
                warnings.append(msg)

        if rule.description:
            _set("Description", rule.description)
        if rule.application_path:
            # Normalize to native Windows backslash form -- Qt's file
            # dialogs can return forward-slash paths that the property
            # assignment accepts silently but Rules.Add() can reject.
            normalized_path = os.path.normpath(rule.application_path)
            _set("ApplicationName", normalized_path)
        if rule.service_name:
            _set("ServiceName", rule.service_name)

        _set("Protocol", rule.protocol)
        if rule.protocol in (PROTOCOL_TCP, PROTOCOL_UDP):
            _set("LocalPorts", rule.local_ports)
            _set("RemotePorts", rule.remote_ports)

        if rule.remote_addresses and rule.remote_addresses != "*":
            _set("RemoteAddresses", rule.remote_addresses)

        if rule.grouping:
            _set("Grouping", rule.grouping)
        if rule.interface_types and rule.interface_types != "All":
            _set("InterfaceTypes", rule.interface_types)
        if rule.direction == DIR_IN:
            # EdgeTraversal is only meaningful for inbound rules -- setting
            # it on an outbound rule can itself trigger rejection on some
            # Windows versions, so it's skipped entirely for outbound.
            _set("EdgeTraversal", rule.edge_traversal)

        for prop, value in (rule.extra or {}).items():
            if value in (None, "", [], 0, False) or (prop in ("LocalAddresses", "IcmpTypesAndCodes") and value == "*"):
                continue
            _set(prop, tuple(value) if isinstance(value, list) else value)

        try:
            self._policy.Rules.Add(com_rule)
        except Exception as exc:
            warning_text = ("\nProperty warnings before this failure:\n  - " + "\n  - ".join(warnings)
                             if warnings else "\nNo property warnings were logged -- the core "
                                               "Name/Direction/Action/Enabled/Profiles combination "
                                               "itself may be the issue.")
            raise FirewallEngineError(
                f"Failed to add rule '{rule.name}': {exc}{warning_text}"
            ) from exc

    # sagefw-blockfix-v1
    _BLOCK_BLOCKERS = (
        ("EdgeTraversal", False, "Allow edge traversal"),
        ("EdgeTraversalOptions", 0, "Edge traversal options"),
        ("SecureFlags", 0, "Require-secure-connection setting"),
        ("LocalUserAuthorizedList", "", "Authorized local users"),
        ("RemoteUserAuthorizedList", "", "Authorized remote users"),
        ("RemoteMachineAuthorizedList", "", "Authorized remote computers"),
    )

    def _block_blockers(self, com_rule) -> list:
        """Settings Windows does not allow on a Block rule (they only make sense on Allow rules)."""
        found = []
        for prop, clear_value, label in self._BLOCK_BLOCKERS:
            try:
                value = getattr(com_rule, prop)
            except Exception:
                continue
            if value in (None, "", 0, False, ()):
                continue
            shown = str(value)
            if len(shown) > 60:
                shown = shown[:60] + "..."
            found.append((prop, clear_value, f"{label}: {shown}"))
        return found

    def update_rule_in_place(self, old: "FirewallRule", new: "FirewallRule",
                             clear_incompatible: bool = False) -> list[str]:
        """
        Edit an existing rule by changing only what differs between `old` (as listed) and `new`
        (from the editor), directly on the live COM rule. Nothing is deleted or recreated, so every
        setting this wrapper does not model (local addresses, ICMP types, user/machine lists,
        interfaces...) is preserved. If any change fails, the ones already made are reverted.

        Changing Allow -> Block: Windows rejects Block rules that carry edge traversal, secure-
        connection or authorized user/computer settings. If the rule has any, BlockIncompatibleError
        is raised before anything is changed; call again with clear_incompatible=True to clear them.
        """
        target = None
        for com_rule in self._policy.Rules:
            if com_rule.Name != old.name:
                continue
            try:
                if FirewallRule.from_com(com_rule) == old:
                    target = com_rule
                    break
            except Exception:
                continue
        if target is None:
            raise FirewallEngineError(
                f"Could not find rule '{old.name}' in its listed state. It may have been changed "
                f"elsewhere - refresh the list and try again."
            )

        blockers = []
        if new.action == ACTION_BLOCK and old.action != ACTION_BLOCK:
            blockers = self._block_blockers(target)
            if blockers and not clear_incompatible:
                raise BlockIncompatibleError([label for _, _, label in blockers])

        applied: list[tuple[str, object]] = []

        def apply(prop: str, value) -> None:
            previous = getattr(target, prop)
            try:
                setattr(target, prop, value)
            except Exception as exc:
                raise FirewallEngineError(f"Windows rejected changing '{prop}' to {value!r}: {exc}") from exc
            applied.append((prop, previous))

        try:
            if (new.application_path or "") != (old.application_path or ""):
                apply("ApplicationName", os.path.normpath(new.application_path) if new.application_path else "")

            if old.protocol in (PROTOCOL_ANY, PROTOCOL_TCP, PROTOCOL_UDP):
                if new.protocol in (PROTOCOL_TCP, PROTOCOL_UDP):
                    if new.protocol != old.protocol:
                        apply("Protocol", new.protocol)
                    if new.local_ports != old.local_ports:
                        apply("LocalPorts", new.local_ports or "*")
                    if new.remote_ports != old.remote_ports:
                        apply("RemotePorts", new.remote_ports or "*")
                elif new.protocol != old.protocol:  # TCP/UDP -> Any: clear ports first
                    if old.local_ports != "*":
                        apply("LocalPorts", "*")
                    if old.remote_ports != "*":
                        apply("RemotePorts", "*")
                    apply("Protocol", new.protocol)

            if new.remote_addresses != old.remote_addresses:
                apply("RemoteAddresses", new.remote_addresses or "*")
            if new.direction != old.direction:
                apply("Direction", new.direction)
            if new.action != old.action:
                for prop, clear_value, _label in blockers:
                    apply(prop, clear_value)
                apply("Action", new.action)
            if new.enabled != old.enabled:
                apply("Enabled", new.enabled)
            if new.profiles != old.profiles:
                apply("Profiles", new.profiles)
            if new.name != old.name:
                apply("Name", new.name)
        except Exception as exc:
            for prop, previous in reversed(applied):
                try:
                    setattr(target, prop, previous)
                except Exception:
                    logger.warning("Could not revert '%s' on rule '%s'", prop, old.name)
            raise FirewallEngineError(
                f"Could not update rule '{old.name}': {exc}. Changes made so far were reverted."
            ) from exc
        return [prop for prop, _ in applied]

    # sagefw-fullrule-v1
    def replace_copies_with_one(self, rule: "FirewallRule") -> None:
        """
        Collapse several same-named identical rules into one, losslessly: build a verified copy
        under a temporary name, and only then remove the originals and rename the copy. If the
        copy is not exactly identical (every setting, including the extras), nothing is changed.
        `rule` should have been read with include_extra=True.
        """
        tmp_name = f"{rule.name} (SageFW temp)"
        expected = dataclasses.replace(rule, name=tmp_name, is_ours=tmp_name.startswith(RULE_PREFIX))
        self.create_rule(expected, overwrite=False)
        created = None
        for com_rule in self._policy.Rules:
            if com_rule.Name == tmp_name:
                created = FirewallRule.from_com(com_rule, include_extra=True)
                break
        if created != expected:
            self.delete_rule(tmp_name)
            raise FirewallEngineError(
                f"A recreated copy of '{rule.name}' was not identical to the original, so nothing was changed."
            )
        tries = 0
        while tries < 200 and self.delete_rule(rule.name):
            tries += 1
        for com_rule in self._policy.Rules:
            if com_rule.Name == tmp_name:
                com_rule.Name = rule.name
                break

    _PROFILE_KEYS = (("domain", PROFILE_DOMAIN), ("private", PROFILE_PRIVATE), ("public", PROFILE_PUBLIC))

    def get_policy_defaults(self) -> dict:
        out = {}
        for key, profile in self._PROFILE_KEYS:
            try:
                out[key] = {
                    "enabled": bool(self._policy.FirewallEnabled(profile)),
                    "inbound": int(self._policy.DefaultInboundAction(profile)),
                    "outbound": int(self._policy.DefaultOutboundAction(profile)),
                }
            except Exception as exc:
                logger.warning("Could not read defaults for %s profile: %s", key, exc)
        return out

    def set_policy_defaults(self, defaults: dict) -> list[str]:
        problems = []
        for key, profile in self._PROFILE_KEYS:
            data = (defaults or {}).get(key)
            if not data:
                continue
            for prop, value in (("DefaultInboundAction", data.get("inbound")),
                                ("DefaultOutboundAction", data.get("outbound")),
                                ("FirewallEnabled", data.get("enabled"))):
                if value is None:
                    continue
                try:
                    getattr(self._policy, prop)[profile] = value
                except Exception as exc:
                    problems.append(f"{key} {prop}: {exc}")
        return problems

    # sagefw-reset-v1
    def reset_to_defaults(self) -> None:
        """
        Restore the LOCAL firewall policy to Windows' out-of-box state for ALL profiles (Domain,
        Private and Public): custom rules are deleted, built-in rules are restored, and each
        profile's default actions and on/off state go back to the defaults. Uses the same function as
        wf.msc > Restore Default Policy; falls back to `netsh advfirewall reset`.
        """
        try:
            self._policy.RestoreLocalFirewallDefaults()
            return
        except Exception as com_exc:
            first_error = com_exc
        try:
            import subprocess
            result = subprocess.run(["netsh", "advfirewall", "reset"], capture_output=True, text=True,
                                    timeout=120, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if result.returncode == 0:
                return
            detail = (result.stdout or result.stderr or "").strip()
        except Exception as exc:
            detail = str(exc)
        raise FirewallEngineError(
            f"Windows could not restore the default firewall policy: {first_error}; netsh said: {detail}"
        ) from first_error

    def delete_rule(self, name: str) -> bool:
        try:
            self._policy.Rules.Remove(name)
            return True
        except Exception:
            return False  # Didn't exist, which is fine for overwrite semantics.

    def delete_rules(self, names: Iterable[str]) -> int:
        count = 0
        for name in names:
            if self.delete_rule(name):
                count += 1
        return count

    def set_rule_enabled(self, name: str, enabled: bool) -> bool:
        for com_rule in self._policy.Rules:
            if com_rule.Name == name:
                com_rule.Enabled = enabled
                return True
        return False

    def block_application(self, app_path: str, label: str,
                           directions: Iterable[Direction] = (Direction.OUT, Direction.IN)) -> list[str]:
        """Convenience: create block rules for an app in the given direction(s)."""
        created = []
        for d in directions:
            name = f"{RULE_PREFIX}Block {label} ({'out' if d == Direction.OUT else 'in'})"
            self.create_rule(FirewallRule(
                name=name,
                description=f"Auto-created block rule for {app_path}",
                application_path=app_path,
                direction=int(d),
                action=ACTION_BLOCK,
            ))
            created.append(name)
        return created

    def allow_application(self, app_path: str, label: str,
                           directions: Iterable[Direction] = (Direction.OUT,)) -> list[str]:
        created = []
        for d in directions:
            name = f"{RULE_PREFIX}Allow {label} ({'out' if d == Direction.OUT else 'in'})"
            self.create_rule(FirewallRule(
                name=name,
                description=f"Auto-created allow rule for {app_path}",
                application_path=app_path,
                direction=int(d),
                action=ACTION_ALLOW,
            ))
            created.append(name)
        return created

    def block_all_outbound_default(self) -> None:
        """
        Sets the *default* outbound action for all profiles to Block.
        This is the 'lockdown mode' switch -- combined with explicit allow
        rules for trusted apps, this is what gives per-app control.
        Requires admin privileges. Indexed property WRITE -> bracket
        assignment is correct here (unlike reads, which need method-call
        syntax -- see module docstring).
        """
        for profile in (PROFILE_DOMAIN, PROFILE_PRIVATE, PROFILE_PUBLIC):
            try:
                self._policy.DefaultOutboundAction[profile] = ACTION_BLOCK
            except Exception as exc:
                raise FirewallEngineError(
                    f"Could not set default outbound action (are you running as admin?): {exc}"
                ) from exc

    def restore_default_outbound_allow(self) -> None:
        for profile in (PROFILE_DOMAIN, PROFILE_PRIVATE, PROFILE_PUBLIC):
            self._policy.DefaultOutboundAction[profile] = ACTION_ALLOW


if __name__ == "__main__":
    # Quick manual smoke test -- run with: python firewall_engine.py
    # (run from an admin terminal for full functionality)
    logging.basicConfig(level=logging.INFO)
    engine = FirewallEngine()
    print(f"Firewall enabled (private profile): {engine.is_firewall_enabled(PROFILE_PRIVATE)}")
    print(f"Firewall enabled (public profile): {engine.is_firewall_enabled(PROFILE_PUBLIC)}")
    print(f"Current active profile bitmask: {engine.current_profile_types()}")
    print(f"Default outbound action (private): {engine.get_default_outbound_action(PROFILE_PRIVATE)} "
          f"(0=Block, 1=Allow)")
    ours = engine.list_rules(ours_only=True)
    print(f"Existing rules created by us: {len(ours)}")
    for r in ours[:10]:
        print(" -", r.name)

    print("\n--- Testing rule creation (with an application path, like the real UI does) ---")
    test_rule = FirewallRule(
        name=f"{RULE_PREFIX}Test Rule (smoke test)",
        description="Temporary rule created by firewall_engine.py's smoke test.",
        application_path="C:/Windows/System32/notepad.exe",  # deliberately forward-slash, to test normalization
        direction=DIR_OUT,
        action=ACTION_BLOCK,
        protocol=PROTOCOL_ANY,
    )
    try:
        engine.create_rule(test_rule)
        print(f"Created test rule successfully: {test_rule.name}")
        engine.delete_rule(test_rule.name)
        print("Cleaned up test rule.")
    except FirewallEngineError as exc:
        print(f"Test rule creation FAILED: {exc}")
