"""Run-Snare-as-a-service installers for Linux (systemd), macOS (launchd), and
Windows (Scheduled Task at logon). Generates the unit/plist/script and prints the
exact install command; `--apply` attempts registration.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys

PY = sys.executable
LABEL = "digital.cognis.snare"


def _cmd(port, blockmap, upstream, doh, allowlist, host):
    parts = [PY, "-m", "snare", "resolve", "--blockmap", os.path.abspath(blockmap),
             "--port", str(port), "--host", host, "--upstream", upstream]
    if doh:
        parts += ["--doh", doh]
    if allowlist:
        parts += ["--allowlist", os.path.abspath(allowlist)]
    return parts


def systemd_unit(argv) -> str:
    return ("[Unit]\nDescription=Snare DNS firewall (Cognis Digital)\nAfter=network.target\n\n"
            "[Service]\nExecStart=" + " ".join(argv) + "\nRestart=always\nRestartSec=3\n\n"
            "[Install]\nWantedBy=default.target\n")


def launchd_plist(argv) -> str:
    args = "".join(f"    <string>{a}</string>\n" for a in argv)
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>\n'
            f"  <key>Label</key><string>{LABEL}</string>\n"
            f"  <key>ProgramArguments</key><array>\n{args}  </array>\n"
            "  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n</dict></plist>\n")


def windows_cmd(argv) -> str:
    return "@echo off\r\nset PYTHONUTF8=1\r\n" + " ".join(f'"{a}"' if " " in a else a for a in argv) + "\r\n"


def _refresh_argv(blockmap, categories):
    parts = [PY, "-m", "snare", "map", "--out", os.path.abspath(blockmap)]
    if categories:
        parts += ["--categories", categories]
    return parts


def install_refresh(blockmap="blockmap.json", categories=None, hours=12,
                    apply=False, outdir=".") -> dict:
    """Schedule periodic blockmap rebuilds so blocklists stay fresh automatically.

    systemd timer (Linux) / launchd StartInterval (macOS) / schtasks (Windows).
    """
    argv = _refresh_argv(blockmap, categories)
    system = platform.system()
    os.makedirs(outdir, exist_ok=True)
    result = {"system": system, "every_hours": hours}

    if system == "Linux":
        svc = os.path.join(outdir, "snare-refresh.service")
        tmr = os.path.join(outdir, "snare-refresh.timer")
        open(svc, "w").write("[Unit]\nDescription=Snare blocklist refresh\n\n[Service]\n"
                             "Type=oneshot\nExecStart=" + " ".join(argv) + "\n")
        open(tmr, "w").write("[Unit]\nDescription=Snare blocklist refresh timer\n\n[Timer]\n"
                             f"OnBootSec=5min\nOnUnitActiveSec={hours}h\nPersistent=true\n\n"
                             "[Install]\nWantedBy=timers.target\n")
        result.update(file=tmr, install=[
            f"cp {svc} {tmr} ~/.config/systemd/user/",
            "systemctl --user daemon-reload",
            "systemctl --user enable --now snare-refresh.timer"])

    elif system == "Darwin":
        label = LABEL + ".refresh"
        path = os.path.join(outdir, f"{label}.plist")
        args = "".join(f"    <string>{a}</string>\n" for a in argv)
        open(path, "w").write(
            '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>\n'
            f"  <key>Label</key><string>{label}</string>\n"
            f"  <key>ProgramArguments</key><array>\n{args}  </array>\n"
            f"  <key>StartInterval</key><integer>{hours * 3600}</integer>\n"
            "  <key>RunAtLoad</key><true/>\n</dict></plist>\n")
        result.update(file=path, install=[
            f"cp {path} ~/Library/LaunchAgents/{label}.plist",
            f"launchctl load ~/Library/LaunchAgents/{label}.plist"])

    else:  # Windows
        path = os.path.join(outdir, "snare_refresh.cmd")
        open(path, "w").write(windows_cmd(argv))
        task_cmd = (f'schtasks /create /tn "Snare-Refresh" /tr "\'{os.path.abspath(path)}\'" '
                    f'/sc HOURLY /mo {hours} /f')
        result.update(file=path, install=[task_cmd])

    if apply and result.get("install"):
        for c in result["install"]:
            subprocess.run(c if system == "Windows" else c.split(),
                           shell=(system == "Windows"), check=False)
        result["applied"] = True
    return result


def install(port=5353, blockmap="blockmap.json", upstream="1.1.1.1", doh=None,
            allowlist=None, host="127.0.0.1", apply=False, outdir=".") -> dict:
    argv = _cmd(port, blockmap, upstream, doh, allowlist, host)
    system = platform.system()
    os.makedirs(outdir, exist_ok=True)
    result = {"system": system}

    if system == "Linux":
        path = os.path.join(outdir, "snare.service")
        open(path, "w").write(systemd_unit(argv))
        result.update(file=path, install=[
            f"cp {path} ~/.config/systemd/user/snare.service",
            "systemctl --user daemon-reload",
            "systemctl --user enable --now snare.service"])
        if apply:
            dst = os.path.expanduser("~/.config/systemd/user/snare.service")
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            open(dst, "w").write(systemd_unit(argv))
            for c in ("systemctl --user daemon-reload", "systemctl --user enable --now snare.service"):
                subprocess.run(c.split(), check=False)
            result["applied"] = True

    elif system == "Darwin":
        path = os.path.join(outdir, f"{LABEL}.plist")
        open(path, "w").write(launchd_plist(argv))
        result.update(file=path, install=[
            f"cp {path} ~/Library/LaunchAgents/{LABEL}.plist",
            f"launchctl load ~/Library/LaunchAgents/{LABEL}.plist"])
        if apply:
            dst = os.path.expanduser(f"~/Library/LaunchAgents/{LABEL}.plist")
            open(dst, "w").write(launchd_plist(argv))
            subprocess.run(["launchctl", "load", dst], check=False)
            result["applied"] = True

    else:  # Windows
        path = os.path.join(outdir, "snare_service.cmd")
        open(path, "w").write(windows_cmd(argv))
        task_cmd = (f'schtasks /create /tn "Snare-DNS" /tr "\'{os.path.abspath(path)}\'" '
                    f'/sc ONLOGON /rl HIGHEST /f')
        result.update(file=path, install=[task_cmd])
        if apply:
            subprocess.run(task_cmd, shell=True, check=False)
            result["applied"] = True
    return result
