#!/usr/bin/env python3
"""Set up binoracle nvd-watch as a background service.

macOS: LaunchAgent plist at ~/Library/LaunchAgents/
Linux: systemd user unit at ~/.config/systemd/user/

Usage:
    python3 scripts/setup_nvd_watch_service.py install
    python3 scripts/setup_nvd_watch_service.py uninstall
    python3 scripts/setup_nvd_watch_service.py status
"""
from __future__ import annotations
import os
import platform
import subprocess
import sys
from pathlib import Path

SERVICE_NAME = "com.binoracle.nvd-watch"
SYSTEMD_NAME = "binoracle-nvd-watch"

# -- Env vars forwarded into the service (read from current shell) --
_FORWARDED_ENV = [
    "BINORACLE_BACKEND", "BINORACLE_WEBHOOK_URL",
    "BINORACLE_TELEGRAM_TOKEN", "BINORACLE_TELEGRAM_CHAT_ID",
    "BINORACLE_CACHE_DIR", "DOCKER_HOST",
]


def _binoracle_bin() -> str:
    import shutil
    b = shutil.which("binoracle")
    if not b:
        raise RuntimeError("'binoracle' not found in PATH — run: pip install -e .")
    return b


def _macos_plist(bin_path: str) -> str:
    env_vars = ""
    for key in _FORWARDED_ENV:
        val = os.environ.get(key, "")
        if val:
            env_vars += f"""
        <key>{key}</key>
        <string>{val}</string>"""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{SERVICE_NAME}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin_path}</string>
        <string>nvd-watch</string>
        <string>--interval</string>
        <string>3600</string>
        <string>--min-cvss</string>
        <string>7.0</string>
        <string>--retry</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>{env_vars}
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{Path.home()}/.cache/binoracle/nvd-watch.log</string>
    <key>StandardErrorPath</key>
    <string>{Path.home()}/.cache/binoracle/nvd-watch.err</string>
</dict>
</plist>
"""


def _systemd_unit(bin_path: str) -> str:
    env_lines = "\n".join(
        f"Environment={key}={os.environ.get(key, '')}"
        for key in _FORWARDED_ENV if os.environ.get(key)
    )
    cache = Path.home() / ".cache" / "binoracle"
    return f"""[Unit]
Description=binoracle NVD autonomous CVE watcher
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart={bin_path} nvd-watch --interval 3600 --min-cvss 7.0 --retry
Restart=on-failure
RestartSec=60
StandardOutput=append:{cache}/nvd-watch.log
StandardError=append:{cache}/nvd-watch.err
{env_lines}

[Install]
WantedBy=default.target
"""


def install():
    bin_path = _binoracle_bin()
    cache = Path.home() / ".cache" / "binoracle"
    cache.mkdir(parents=True, exist_ok=True)

    if platform.system() == "Darwin":
        plist_dir = Path.home() / "Library" / "LaunchAgents"
        plist_dir.mkdir(parents=True, exist_ok=True)
        plist_path = plist_dir / f"{SERVICE_NAME}.plist"
        plist_path.write_text(_macos_plist(bin_path))
        print(f"Wrote plist: {plist_path}")
        subprocess.run(["launchctl", "load", "-w", str(plist_path)], check=True)
        print(f"Service loaded: {SERVICE_NAME}")
        print(f"Logs: {cache}/nvd-watch.log")
    else:
        unit_dir = Path.home() / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True, exist_ok=True)
        unit_path = unit_dir / f"{SYSTEMD_NAME}.service"
        unit_path.write_text(_systemd_unit(bin_path))
        print(f"Wrote unit: {unit_path}")
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "--user", "enable", "--now",
                        f"{SYSTEMD_NAME}.service"], check=True)
        print(f"Service enabled: {SYSTEMD_NAME}")
        print(f"Logs: journalctl --user -u {SYSTEMD_NAME} -f")


def uninstall():
    if platform.system() == "Darwin":
        plist_path = Path.home() / "Library" / "LaunchAgents" / f"{SERVICE_NAME}.plist"
        if plist_path.exists():
            subprocess.run(["launchctl", "unload", str(plist_path)])
            plist_path.unlink()
            print(f"Service unloaded and plist removed: {plist_path}")
        else:
            print("Service not installed.")
    else:
        subprocess.run(["systemctl", "--user", "disable", "--now",
                        f"{SYSTEMD_NAME}.service"])
        unit_path = Path.home() / ".config" / "systemd" / "user" / f"{SYSTEMD_NAME}.service"
        if unit_path.exists():
            unit_path.unlink()
        subprocess.run(["systemctl", "--user", "daemon-reload"])
        print(f"Service disabled: {SYSTEMD_NAME}")


def status():
    if platform.system() == "Darwin":
        result = subprocess.run(["launchctl", "list", SERVICE_NAME],
                                capture_output=True, text=True)
        print(result.stdout or result.stderr or "not running")
    else:
        subprocess.run(["systemctl", "--user", "status", f"{SYSTEMD_NAME}.service"])


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    {"install": install, "uninstall": uninstall, "status": status}.get(
        cmd, lambda: print(__doc__))()
