"""
core/app_resolver.py

Turns the raw application paths that come out of connection_monitor.py
(e.g. "\\device\\harddiskvolume2\\program files\\bravesoftware\\...\\brave.exe")
into something the UI can display nicely: a friendly display name,
publisher, and an extracted icon saved to a local cache folder.

Handles three distinct cases:
  1. Normal Win32 executables -- accessed directly via the NT device path
     using the "\\\\?\\GLOBALROOT" prefix (bypasses needing to guess which
     drive letter maps to which HarddiskVolumeN -- that guess turned out
     to be unreliable in testing, GLOBALROOT access is not).
  2. UWP / MSIX apps (path contains "\\windowsapps\\") -- the package
     folder name is parsed out of the path, then `Get-AppxPackage`
     (PowerShell) resolves the real display name and PublisherDisplayName.
  3. Kernel/system pseudo-processes (e.g. "System", empty path, PID 4) --
     handled as a fixed special case.

No UI dependency. Icons are cached to disk (data/icons/<hash>.png).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Optional

import win32api
import win32con
import win32gui
import win32ui
from PIL import Image

logger = logging.getLogger(__name__)

# sagefw-portable-icons-v1
import sys as _sys
_APP_DIR = (Path(_sys.executable).resolve().parent if getattr(_sys, "frozen", False)
            else Path(__file__).resolve().parent)
ICON_CACHE_DIR = _APP_DIR / "data" / "icons"
ICON_CACHE_DIR.mkdir(parents=True, exist_ok=True)

_GUID_RE = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")

# Note: a raw string literal can't end in a single backslash (it would
# escape the closing quote even in raw mode), so this prefix is built with
# a normal escaped string instead of r"\device\".
DEVICE_PATH_PREFIX = "\\device\\"


@dataclasses.dataclass
class AppInfo:
    original_path: str
    resolved_path: Optional[str] = None   # accessible path (GLOBALROOT-prefixed), if resolvable
    display_name: str = ""
    publisher: str = ""
    is_uwp: bool = False
    package_family_name: Optional[str] = None
    is_system: bool = False
    icon_path: Optional[str] = None
    resolution_ok: bool = True
    error: Optional[str] = None


# ---------- device path -> directly-accessible path ----------

def normalize_device_path(raw_path: Optional[str]) -> Optional[str]:
    """
    Converts an NT device path (as reported by WFP audit events) into a
    form Windows file APIs can open directly, using the GLOBALROOT
    namespace prefix -- this avoids the unreliable approach of guessing
    which drive letter a given HarddiskVolumeN corresponds to.
    """
    if not raw_path:
        return None
    if raw_path.strip().lower() == "system":
        return None  # handled separately

    if raw_path.lower().startswith(DEVICE_PATH_PREFIX):
        return "\\\\?\\GLOBALROOT" + raw_path
    return raw_path  # Already a normal path (e.g. came from another source).


# ---------- UWP / MSIX detection ----------

_UWP_PATH_RE = re.compile(r"windowsapps\\([^\\]+)\\", re.IGNORECASE)


def extract_package_family_hint(path: str) -> Optional[str]:
    """
    Pulls the package folder name (== PackageFullName) out of a
    WindowsApps path, e.g.
    'Shrimqy.Seki-PhoneLink_3.1.0.0_x64__9yhjgvpvzzxz2'.
    """
    match = _UWP_PATH_RE.search(path)
    return match.group(1) if match else None


def is_uwp_path(path: str) -> bool:
    return "windowsapps" in path.lower()


def resolve_uwp_display_name(package_folder_name: str) -> tuple[str, str]:
    """
    Calls Get-AppxPackage via PowerShell to resolve a friendly name and
    publisher for a UWP package. Uses PublisherDisplayName (a plain,
    human-readable field) rather than the raw X.500 Publisher string,
    which for many community/sideloaded apps is just a GUID and not
    useful to show in the UI.
    """
    name_hint = package_folder_name.split("_")[0]
    ps_command = (
        f"Get-AppxPackage | Where-Object {{$_.PackageFullName -eq '{package_folder_name}' "
        f"-or $_.Name -like '*{name_hint}*'}} | "
        "Select-Object -First 1 Name, PublisherDisplayName | ConvertTo-Json"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_command],
            capture_output=True, text=True, timeout=10,
        )
        if result.stdout.strip():
            data = json.loads(result.stdout)
            name = data.get("Name", name_hint)
            publisher = data.get("PublisherDisplayName", "") or ""
            if _GUID_RE.match(publisher.strip()):
                publisher = ""  # Not useful to show a bare GUID in the UI.
            return name, publisher
    except Exception as exc:
        logger.debug("UWP resolution via PowerShell failed for %s: %s", package_folder_name, exc)
    return name_hint, ""


# ---------- Win32 file version info ----------

def get_file_version_info(exe_path: str) -> tuple[str, str]:
    """Returns (display_name, publisher) from the .exe's embedded metadata,
    falling back to the filename if no metadata is present. `exe_path` may
    be a GLOBALROOT-prefixed path."""
    fallback_name = Path(exe_path).stem
    try:
        win32api.GetFileVersionInfo(exe_path, "\\")
        lang, codepage = win32api.GetFileVersionInfo(
            exe_path, "\\VarFileInfo\\Translation"
        )[0]
        str_info_path = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\"

        def _field(name: str) -> str:
            try:
                return win32api.GetFileVersionInfo(exe_path, str_info_path + name) or ""
            except Exception:
                return ""

        display_name = _field("FileDescription") or _field("ProductName") or fallback_name
        publisher = _field("CompanyName")
        return display_name, publisher
    except Exception as exc:
        logger.debug("No version info for %s: %s", exe_path, exc)
        return fallback_name, ""


def path_exists(path: str) -> bool:
    """os.path.exists doesn't reliably handle GLOBALROOT paths on all Python
    versions, so we go through win32api.GetFileAttributes, which does."""
    try:
        win32api.GetFileAttributes(path)
        return True
    except Exception:
        return False


# ---------- icon extraction ----------

def _cache_path_for(exe_path: str) -> Path:
    digest = hashlib.sha1(exe_path.lower().encode("utf-8")).hexdigest()[:16]
    return ICON_CACHE_DIR / f"{digest}.png"


def extract_icon(exe_path: str) -> Optional[str]:
    """
    Extracts the .exe's associated icon and saves it as a PNG in the
    cache folder. Returns the cache file path as a string, or None if
    extraction failed. `exe_path` may be a GLOBALROOT-prefixed path.
    """
    cache_path = _cache_path_for(exe_path)
    if cache_path.exists():
        return str(cache_path)

    try:
        large, small = win32gui.ExtractIconEx(exe_path, 0)
        icon_handle = (large or small)
        if not icon_handle:
            return None
        handle = icon_handle[0]

        ico_x = win32api.GetSystemMetrics(win32con.SM_CXICON)
        ico_y = win32api.GetSystemMetrics(win32con.SM_CYICON)

        hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
        hbmp = win32ui.CreateBitmap()
        hbmp.CreateCompatibleBitmap(hdc, ico_x, ico_y)
        hdc_mem = hdc.CreateCompatibleDC()
        hdc_mem.SelectObject(hbmp)
        hdc_mem.DrawIcon((0, 0), handle)

        bmp_info = hbmp.GetInfo()
        bmp_bits = hbmp.GetBitmapBits(True)
        img = Image.frombuffer(
            "RGBA", (bmp_info["bmWidth"], bmp_info["bmHeight"]), bmp_bits,
            "raw", "BGRA", 0, 1,
        )
        img.save(cache_path, "PNG")

        for h in (large or []):
            win32gui.DestroyIcon(h)
        for h in (small or []):
            win32gui.DestroyIcon(h)

        return str(cache_path)
    except Exception as exc:
        logger.debug("Icon extraction failed for %s: %s", exe_path, exc)
        return None


# ---------- top-level entry point ----------

SYSTEM_PSEUDO_PROCESS_NAMES = {"system", ""}


def resolve_app(raw_path: Optional[str]) -> AppInfo:
    """
    Main entry point. Give it whatever `application_path` a
    connection_monitor.ConnectionEvent contains, get back a fully
    populated AppInfo -- friendly name, publisher, icon path, UWP flag.
    """
    if not raw_path or raw_path.strip().lower() in SYSTEM_PSEUDO_PROCESS_NAMES:
        return AppInfo(
            original_path=raw_path or "",
            display_name="Windows System",
            publisher="Microsoft Corporation",
            is_system=True,
        )

    normalized = normalize_device_path(raw_path)
    if normalized is None:
        return AppInfo(
            original_path=raw_path,
            display_name=raw_path,
            resolution_ok=False,
            error="Could not normalize device path.",
        )

    exists = path_exists(normalized)

    if is_uwp_path(normalized):
        package_folder = extract_package_family_hint(normalized)
        if package_folder:
            display_name, publisher = resolve_uwp_display_name(package_folder)
            icon_path = extract_icon(normalized) if exists else None
            return AppInfo(
                original_path=raw_path,
                resolved_path=normalized,
                display_name=display_name,
                publisher=publisher,
                is_uwp=True,
                package_family_name=package_folder,
                icon_path=icon_path,
                resolution_ok=exists,
            )

    display_name, publisher = get_file_version_info(normalized)
    icon_path = extract_icon(normalized) if exists else None
    return AppInfo(
        original_path=raw_path,
        resolved_path=normalized,
        display_name=display_name,
        publisher=publisher,
        icon_path=icon_path,
        resolution_ok=exists,
        error=None if exists else "Resolved path does not exist on disk.",
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    test_paths = [
        "System",
        "\\device\\harddiskvolume2\\program files\\bravesoftware\\brave-browser\\application\\brave.exe",
        "\\device\\harddiskvolume2\\program files\\windowsapps\\shrimqy.seki-phonelink_3.1.0.0_x64__9yhjgvpvzzxz2\\sefirah.exe",
        "\\device\\harddiskvolume2\\windows\\system32\\svchost.exe",
    ]
    for p in test_paths:
        info = resolve_app(p)
        print(f"\nInput:       {p}")
        print(f"Resolved:    {info.resolved_path}")
        print(f"Display:     {info.display_name}")
        print(f"Publisher:   {info.publisher}")
        print(f"Is UWP:      {info.is_uwp}")
        print(f"Is system:   {info.is_system}")
        print(f"Icon cached: {info.icon_path}")
        print(f"OK:          {info.resolution_ok} ({info.error})")
