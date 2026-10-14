# SageFW

A portable, per-app control panel for **Windows Defender Firewall**. SageFW shows you what your PC is connecting to in real time, lets you turn any connection into an Allow or Block rule with a right-click, manages every existing firewall rule (inbound and outbound), backs the whole policy up and restores it, and can run in "lockdown" mode so that new, unknown apps are blocked and prompt you for a decision.

SageFW does **not** install a driver and does not replace the firewall. It talks to the same Windows Firewall engine that `wf.msc` and `netsh advfirewall` use, through the official COM API.

> **Important: rules apply to all network profiles by default.** Read [Profiles: Domain, Private and Public](#profiles-domain-private-and-public) before relying on SageFW for anything sensitive.

---

## Contents

1. [Features](#features)
2. [Requirements](#requirements)
3. [Install and run](#install-and-run)
4. [First run](#first-run)
5. [Using SageFW](#using-sagefw)
6. [How prompts work](#how-prompts-work)
7. [Profiles: Domain, Private and Public](#profiles-domain-private-and-public)
8. [Lockdown mode](#lockdown-mode)
9. [Backup, restore and reset](#backup-restore-and-reset)
10. [Where your data lives](#where-your-data-lives)
11. [Safety notes](#safety-notes)
12. [Project layout](#project-layout)
13. [Troubleshooting](#troubleshooting)
14. [Known limitations](#known-limitations)
15. [Uninstalling](#uninstalling)

---

## Features

- **Live Traffic view**: every connection (allowed and blocked) in a sortable, filterable table, colour-coded green and red. Shows time, app, direction, source, destination, service name, verdict and rule group. Keeps the latest 300 entries in memory only.
- **Pause and Resume**: freeze the table to read it. New events are held while paused (up to 300) and added when you resume, with a counter on the button.
- **Right-click to create rules**: from any traffic row, create an Allow or Block rule for that specific traffic (app, protocol, port and remote address pre-filled) or for the whole app. The rule editor opens pre-filled so you can review it before saving.
- **Right-click to search Google**: look up an unfamiliar process name in your browser. Available in both the Live Traffic and Rules tables.
- **Separate Inbound Rules and Outbound Rules pages**: every current Windows Firewall rule, searchable and sortable, with New, Edit and Delete. Columns include Action, Protocol, Local and Remote Ports, Enabled, Source, a colour-coded **Type** and the rule **Group**.
- **In-place editing**: editing a rule changes only the settings you change, directly on the live rule, so every other setting (local addresses, ICMP types, user and computer lists, interfaces, service, group, description) is kept exactly as it was.
- **Maintenance tools** (Settings): remove rules whose program no longer exists, and remove duplicate rules. Both show a review list first.
- **Backup & Restore** (Settings): full-fidelity backups of every rule and each profile's defaults, restore from a backup, and reset the firewall to Windows defaults.
- **Notification prompts**: when a new connection needs a decision, SageFW shows a prompt card with an automatic timeout that blocks the connection if you don't respond.
- **System tray**: pressing the window's X asks whether to minimise to the tray or exit. Exit also from the tray menu or with **Ctrl+Q**.
- **One copy at a time**: starting SageFW while it is already running shows a message pointing at the tray icon instead of opening a second copy.
- **Portable**: everything SageFW saves lives inside its own folder. Nothing is written to `%APPDATA%` by SageFW itself.

### Rule type colours (Rules pages)

The Type is worked out from the rule's application path.

| Type | Colour | Matches |
|---|---|---|
| System | Blue | Apps under the Windows folder, and built-in rules whose names start with `@` |
| Store app | Purple | Anything under `WindowsApps` |
| Installed | Green | Program Files, Program Files (x86) and ProgramData |
| User app | Orange | Anything under `C:\Users` (AppData, Downloads and so on) |
| Port / any app | Grey | Rules with no application (port or protocol only) |
| Other | Grey | Other drives or unusual locations |

---

## Requirements

- **Windows 10 or 11**, with the *Windows Defender Firewall* service running.
- **Administrator rights.** SageFW asks for elevation (UAC) on launch, because creating rules and changing firewall defaults require it.
- **Python 3.10 or newer.** (Pillow's current releases require 3.10+. SageFW has been run on Python 3.11 and 3.15 during development.)
- Python packages (minimum versions):

| Package | Minimum | Used for |
|---|---|---|
| `PyQt6` | 6.6 | The user interface |
| `PyQt6-Fluent-Widgets` | 1.6 | Windows 11 style controls and the sidebar (`qfluentwidgets`) |
| `pywin32` | 306 | Windows Firewall COM access and the event log (`win32com`, `win32evtlog`, `pythoncom`) |
| `psutil` | 5.9 | Process and connection information |
| `Pillow` | 10.0 | Converting extracted app icons to PNG (`PIL`) |

---

## Install and run

From the SageFW folder:

```bat
python -m pip install -r requirements.txt
python main.py
```

Notes:

- Install **`pywin32`**, not `win32evtlog`. `win32evtlog` is a module inside pywin32, not a separate package.
- Always use `python -m pip` so packages go into the same Python that runs SageFW.
- Accept the UAC prompt when SageFW starts. If you decline, SageFW exits.
- If your `requirements.txt` still lists `pyqtgraph`, it is no longer used and can be removed.

On startup SageFW also hides its console window and turns on **Windows connection auditing** (WFP auditing) if it isn't already on. This is a Windows setting and it stays on after you close or remove SageFW (see [Uninstalling](#uninstalling)).

---

## First run

On the very first launch, a prompt in the console asks how to start:

1. **Import existing Windows Firewall rules as a trusted baseline.** Apps you have already allowed keep working, and only genuinely new apps prompt you. Lockdown mode is **not** switched on automatically.
2. **Start from zero: block everything new by default.** This also switches on lockdown mode immediately. Every app without an explicit allow rule is blocked and prompts you. A safety snapshot is taken automatically first.

If you aren't sure, choose **1**. You can review what is already trusted before deciding on lockdown.

---

## Using SageFW

### Dashboard (Live Traffic)

- Click any column header to sort, drag column edges to resize, and type in the filter box to search by app, address, port or group.
- **Pause** freezes the table. The button changes to **Resume (N new)** while events queue up.
- **Right-click a row** for:
  - *Allow this traffic* or *Block this traffic*: opens the rule editor pre-filled with the app, direction, protocol, port and remote address.
  - *Allow* or *Block* the whole app: same, but for all traffic from that program.
  - *Search Google for "name"*: searches the program's file name (for example `svchost.exe`).
- The **Group** column shows the group(s) of your enabled rules that could cover that connection (same program, direction, protocol and port). It is an association, not proof of which rule actually allowed the traffic, and many rules have no group.

How the pre-filled traffic rule is built:

- **Application:** the program that made the connection.
- **Direction and protocol:** taken from the row (for example outbound TCP).
- **Port:** the destination port, as the remote port for outbound traffic or the local port for inbound traffic. The source port is not used, because it is a random temporary port that changes with every connection.
- **Address:** the other end of the connection (destination for outbound, source for inbound).
- **Profiles:** all three. See [Profiles](#profiles-domain-private-and-public).

Nothing is created until you press **Save** in the editor.

### Inbound Rules and Outbound Rules

- Each page lists only rules of its direction. Search by name, application path, type, group, protocol or ports.
- **New Rule** opens the editor with that page's direction already chosen.
- **Edit** (or double-click) changes only what you change, in place. If you change a rule to **Block** and it carries settings Windows does not allow on Block rules (authorized users or computers, "allow only if secure", edge traversal), SageFW lists them and asks before clearing them. If anything fails, changes already made are reverted.
- **Delete** asks for confirmation; for rules SageFW did not create the warning is stronger and the rule's details are first saved to `deleted_rules_log.jsonl`. SageFW refuses to delete a rule when several rules share its name, because Windows deletes by name; use `wf.msc` for those.
- Right-click a rule to search Google for its program.
- Rules you create always get the `[NFW]` name prefix so SageFW can recognise them later.
- Group names that Windows stores as resource codes (such as `@FirewallAPI.dll,-30502`) are translated to readable names where Windows allows; some may still appear as codes.

### Settings

- Auto-block prompt timeout (seconds).
- Whether new inbound and outbound prompts grab keyboard focus.
- Light or dark theme.
- **Maintenance**
  - *Remove rules for missing programs...* finds rules whose program no longer exists on disk and lets you review the list (all ticked) before removing. Skipped: rules whose application is not a normal drive path, rules on drives that are not connected, network paths, and rules sharing a name with a rule for a program that still exists.
  - *Remove duplicate rules...* groups rules that are identical in every setting except their name and removes the extras, keeping one copy of each. You review the list first. Same-name copies are collapsed by building a copy, checking it is identical, then removing the originals.
- **Backup & Restore**: see [Backup, restore and reset](#backup-restore-and-reset).

### Keyboard, tray and closing

- **Ctrl+Q** quits SageFW immediately from the main window.
- The **X** button asks whether to minimise to the tray or exit (or cancel).
- The tray icon menu has **Show** and **Exit**. Double-click the tray icon to reopen the window.
- The window opens at 1380 x 780 by default.

---

## How prompts work

- SageFW listens for **blocked** connections. Under default-deny (lockdown) a blocked connection is a new connection needing a decision. Under Windows' normal outbound default (Allow), only inbound connections that Windows blocks produce prompts.
- Near-simultaneous prompts for different connections are grouped into one card for readability. Nothing is suppressed.
- Choices are Allow or Block, and either **once**, **always for this app**, or **always for this app and destination**. "Once" creates a real rule tagged as session-only, and leftovers are cleaned up the next time SageFW starts.
- Ignoring a prompt auto-resolves it as *block once* after the timeout (25 seconds by default; adjustable in Settings), so an unanswered prompt fails safe without permanently blacklisting the app.
- Your "always" decisions are remembered in the database. If a remembered *allow* decision matches a connection that gets blocked, SageFW re-creates the allow rule silently instead of asking again.

---

## Profiles: Domain, Private and Public

Windows Firewall applies rules per network profile: **Domain** (joined to a business domain), **Private** (trusted home or work networks) and **Public** (cafes, airports and other untrusted networks).

**SageFW's default is to apply rules across all three profiles.**

What that means in practice:

- **New rules:** the rule editor starts with Domain, Private and Public all ticked. An Allow or Block rule you create, including one made from the Live Traffic right-click menu, therefore applies on every network type, whatever network you are connected to.
- **Editing existing rules:** the editor loads the rule's current profiles and keeps them unless you change them. Editing a built-in rule that only applies to Private networks will not widen it.
- **Lockdown mode:** switching it on sets the default outbound action to **Block on all three profiles**, and switching it off sets it back to **Allow on all three**. You cannot lock down only the Public profile.
- **Reset to Windows defaults:** resets all three profiles together.
- **Backups:** record each profile's on/off state and default inbound and outbound action as well as every rule's profiles.
- **No profile display:** SageFW does not show which profile is currently active, and the Rules pages have no Profile column. The profiles of a rule are visible only in the editor.
- **No per-profile traffic data:** connection events in the Live Traffic table do not record which profile was active.

Why this matters: an Allow rule made on a trusted home network will also let that traffic through when you are on public Wi-Fi. If you want a rule limited to certain networks, untick the profiles you don't want in the editor before saving.

---

## Lockdown mode

Lockdown mode flips the firewall's **default outbound action to Block**. Combined with explicit Allow rules for the apps you trust, it gives you per-app control and makes new apps prompt for a decision.

- Turning it on is available through the first-run choice (option 2).
- A safety snapshot is taken first.
- It applies to Domain, Private and Public together.
- Without lockdown mode, outbound traffic follows the Windows default (Allow), and only inbound traffic that Windows blocks itself will prompt you.
- *Reset to Windows defaults* ends lockdown mode, because it restores Windows' default actions.

Be aware that lockdown mode can stop software from reaching the internet, including updaters and sign-in services, until you allow them.

---

## Backup, restore and reset

Settings > **Backup & Restore**:

- **Back up now** saves every rule with all of its settings, plus each profile's on/off state and default inbound and outbound action, to a JSON file. A Windows policy file (`.wfw`, from `netsh advfirewall export`) is saved beside it when possible. Files are named `sagefw-backup-YYYYMMDD-HHMMSS` and live in `app\data\backups`.
- **Restore from backup...** accepts either file type:
  - A SageFW `.json` backup, in one of two modes. *Restore missing rules only* recreates rules that are in the backup but not on the PC and changes nothing else. *Make rules match the backup* removes rules added since and puts changed rules back to their backed-up settings. Optionally also restores each profile's on/off state and default actions. Afterwards SageFW compares the result with the backup and lists anything that did not come back identical.
  - A Windows `.wfw` policy file, which **replaces the entire Windows Firewall policy** (every rule and setting). It asks for a stronger confirmation.
- **Open backup folder** opens `app\data\backups`.
- **Reset to Windows defaults...** resets the local Windows Firewall policy for **all profiles** (the same function as wf.msc > Restore Default Policy): every custom rule is deleted, including SageFW's and those added by installed programs; Windows' built-in rules are restored; each profile's defaults and on/off state return to Windows' defaults. A ticked option also forgets SageFW's saved Allow/Block decisions so it cannot quietly recreate those rules later. Rules delivered by Group Policy are managed separately.
- Before any restore or reset, SageFW saves a backup of the current state first (labelled `pre-restore` or `pre-reset`), and cancels the operation if that backup fails.

---

## Where your data lives

SageFW is designed to be portable. Everything it saves stays inside the SageFW folder, under `app\data`:

| Path | What it holds |
|---|---|
| `app/data/nicerfirewall.db` | SQLite database: settings, saved decisions, snapshots and first-run data (the file keeps its original name for compatibility) |
| `app/data/icons/*.png` | Cached icons extracted from programs you have seen |
| `app/data/backups/` | Backups made from Settings > Backup & Restore (`.json` and `.wfw`) |
| `app/data/deleted_rules_log.jsonl` | A record of rules removed by Delete and by the maintenance tools, one JSON line each (created only when something is removed) |

Rules themselves are stored by **Windows**, not by SageFW. They remain in Windows Firewall if you delete the SageFW folder.

The database and icon folder are anchored to the SageFW folder, so they stay together wherever you launch the app from.

---

## Safety notes

- **Back up before bulk changes.** Use Settings > Backup & Restore > Back up now before cleaning up, resetting or restoring.
- **Editing or deleting rules SageFW didn't create** (Windows or other software) can break network features. Delete warns more strongly for these rules and logs them, but a deletion is not undone by a snapshot restore; restoring a SageFW backup is.
- Edits are made in place, so unmanaged settings are preserved. Changing a rule to **Block** may require clearing settings Windows does not allow on Block rules; SageFW tells you which and asks first.
- SageFW refuses to delete a rule when **several rules share the same name**, because the engine works by name and could remove the wrong rule. Use `wf.msc` for those.
- Duplicate removal keeps one copy of every group and never removes a rule if doing so would also remove a different rule with the same name.
- The **Remove rules for missing programs** tool skips drives that are not connected, so an unplugged USB drive does not get its rules removed.
- *Reset to Windows defaults* and restoring a `.wfw` file affect the whole firewall. Both save a backup first.
- Only turn on lockdown mode when you can easily recover, for example from a console you can still reach.

---

## Project layout

```
SageFW/
  main.py                      Entry point: single-instance check, elevation, setup, first-run, launch UI
  README.md                    This file
  requirements.txt             Python dependencies
  app/
    config.py                  Settings
    firewall_engine.py         Windows Firewall COM wrapper (rules, defaults, profiles, in-place edits, reset)
    rule_store.py              SQLite storage (app/data/nicerfirewall.db)
    connection_monitor.py      Reads connection events; enables WFP auditing
    notification_manager.py    Decides when to prompt, handles timeouts and remembered decisions
    app_resolver.py            Turns paths into names, icons and version info
    port_services.py           Port number to service name lookup
    import_export.py           Snapshots, lockdown mode, first-run import, tidy up
    backup_restore.py          Full-fidelity backup and restore logic
    data/                      Created on first run (database, icons, backups, logs)
    ui/
      shell.py                 Main window, sidebar, tray icon, settings page
      dashboard.py             Live Traffic table (plus a standalone dashboard window)
      rules_manager.py         Inbound/Outbound rules tables and the rule editor
      backup_restore_ui.py     Settings > Backup & Restore section
      notification_popup.py    Prompt cards and theme helper
```

Design notes:

- `firewall_engine.py` and the other core modules have no UI dependency and can be used from a plain Python shell.
- Rules created by SageFW are identified by the name prefix `[NFW] `.
- Application paths are normalised to Windows backslash form before being sent to Windows Firewall, because forward-slash paths can be accepted silently and rejected later.
- Connection events arrive on a background thread and are passed to the UI thread using Qt signals.
- Advanced rule settings are read only on request (`list_rules(include_extra=True)`), so normal refreshes stay fast.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `No matching distribution found for win32evtlog` | Install `pywin32` instead: `python -m pip install pywin32` |
| `No module named 'PIL'` | `python -m pip install Pillow` |
| Missing module after installing | You installed into a different Python. Use `python -m pip install ...` with the same `python` you run SageFW with. |
| Nothing happens, or SageFW exits immediately | You declined the UAC prompt, or SageFW is already running (check the system tray, you may need to click the ^ arrow). |
| "SageFW is already running" | Open it from the tray icon. If it is not there, end `python.exe` or `pythonw.exe` in Task Manager and start again. |
| Live Traffic stays empty | Connection auditing may not be enabled yet, or events aren't being generated. Restart SageFW as administrator and check the Windows Security event log is running. |
| New app prompts never appear for outbound traffic | Lockdown mode is off, so outbound traffic is allowed by default. See [Lockdown mode](#lockdown-mode). |
| A rule from Live Traffic doesn't match anything | Check the Application box in the rule editor holds a normal `C:\...` path and not a `\device\harddiskvolume...` path. |
| Can't delete a rule | Several rules share its name. Use `wf.msc`. |
| Changing a rule to Block says it cannot keep some settings | Windows does not allow authorized users or computers, "allow only if secure" or edge traversal on Block rules. Confirm to clear them, or cancel. |
| Some Group names show as codes like `@FirewallAPI.dll,-30502` | Windows could not translate them. This is cosmetic. |
| Can't find the window | It is minimised to the tray. Double-click the tray icon, or use the tray menu. |
| SageFW cannot move or update its files | Quit SageFW completely first; an open database cannot be moved. |

---

## Known limitations

- The Rules pages have no Profile column, and SageFW doesn't show the active network profile.
- Lockdown mode applies to all profiles together.
- Windows Firewall does not record when a rule was created, so SageFW cannot show a rule creation date.
- Windows Store (UWP) apps are identified through PowerShell, which can be slow the first time an app is seen.
- The first-run wizard is a console prompt, not a window.
- The standalone Tidy Up tool in the dashboard module is separate from the Settings maintenance tools.
- The Live Traffic **Group** column is an association based on your enabled rules, not a record of which rule applied.
- Group names that Windows stores as resource codes are translated where Windows allows; some cannot be.
- Snapshot restore (the original snapshot feature) recreates only rules SageFW created. Use Backup & Restore for full-fidelity restores.
- A restore may not reproduce every advanced setting if Windows refuses to set it on a new rule; SageFW lists any rule that came back different.
- Rules delivered by Group Policy are not affected by Reset to Windows defaults.

---

## Uninstalling

1. Quit SageFW from the tray menu or with **Ctrl+Q**.
2. Take a backup first if you want to keep your rules (Settings > Backup & Restore).
3. Delete the SageFW folder. That removes SageFW's own data.
4. Optional cleanup of changes SageFW made to Windows, which stay in place:
   - **Rules:** rules created by SageFW start with `[NFW]`. Remove them in `wf.msc` or the Rules pages before deleting the folder, if you want them gone.
   - **Default outbound action:** if lockdown mode is on, reset it in `wf.msc` (Windows Defender Firewall Properties, Outbound connections: Allow), or use Reset to Windows defaults.
   - **Connection auditing:** SageFW turned on connection auditing. To switch it off, run this in an administrator terminal: `auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:disable`

---

## Disclaimer

SageFW changes real firewall settings on your computer. Use it at your own risk, keep a way to recover, and don't rely on it as your only security control. Add your licence here.
