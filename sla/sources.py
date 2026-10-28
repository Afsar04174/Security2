"""Where the logs come from: files, rotated/gz files, journalctl, Windows Event Log, live tailing."""
from __future__ import annotations

import glob
import gzip
import os
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable, Iterator, Optional

from .parsers import WIN_EVENT_IDS, parse_line, parse_windows_xml

CANDIDATE_LOGS = [
    ("/var/log/auth.log", "SSH / sudo / accounts (Debian, Ubuntu, Kali)"),
    ("/var/log/secure", "SSH / sudo / accounts (RHEL, CentOS, Fedora)"),
    ("/var/log/ufw.log", "Firewall drops (UFW)"),
    ("/var/log/kern.log", "Firewall drops (kernel log)"),
    ("/var/log/nginx/access.log", "Nginx web requests"),
    ("/var/log/apache2/access.log", "Apache web requests (Debian/Ubuntu)"),
    ("/var/log/httpd/access_log", "Apache web requests (RHEL/CentOS)"),
]
JOURNAL_IDENTS = ["sshd", "ssh", "sudo", "su", "useradd", "usermod", "gpasswd", "kernel"]


# --------------------------------------------------------------------------- #
# discovery
# --------------------------------------------------------------------------- #
def discover_logs(include_rotated: bool = False) -> list[dict]:
    """Check the usual locations. status: ok | denied | missing."""
    found = []
    for path, what in CANDIDATE_LOGS:
        paths = [path]
        if include_rotated:
            paths += sorted(glob.glob(path + ".1")) + sorted(glob.glob(path + ".*.gz"))
        for p in paths:
            if not os.path.exists(p):
                if p == path:
                    found.append({"path": p, "what": what, "status": "missing"})
                continue
            status = "ok" if os.access(p, os.R_OK) else "denied"
            found.append({"path": p, "what": what, "status": status})
    return found


# --------------------------------------------------------------------------- #
# reading (batch)
# --------------------------------------------------------------------------- #
def open_text(path: Path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def read_text_any(path: Path) -> str:
    data = Path(path).read_bytes()
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16")
    return data.decode("utf-8-sig", errors="replace")


def collect_events(paths, now) -> tuple[list, int, list]:
    """Parse every file. Returns (events sorted by time, total lines, per-file info)."""
    events, total, info = [], 0, []
    for p in paths:
        p = Path(p)
        rec = {"path": str(p), "lines": 0, "events": 0, "error": None}
        evs = []
        try:
            if p.suffix.lower() == ".xml":
                evs = parse_windows_xml(read_text_any(p))
                rec["lines"] = len(evs)
            else:
                with open_text(p) as fh:
                    for line in fh:
                        rec["lines"] += 1
                        ev = parse_line(line, now)
                        if ev:
                            evs.append(ev)
        except (OSError, ET.ParseError) as exc:
            rec["error"] = str(exc)
        rec["events"] = len(evs)
        total += rec["lines"]
        events.extend(evs)
        info.append(rec)
    events.sort(key=lambda e: e.ts)
    return events, total, info


def journal_cmd(since: Optional[str] = None, follow: bool = False) -> list[str]:
    cmd = ["journalctl", "--no-pager", "-o", "short-iso"]
    for ident in JOURNAL_IDENTS:
        cmd += ["-t", ident]
    if follow:
        cmd += ["-f", "-n", "0"]
    elif since:
        cmd += ["--since", since]
    return cmd


def read_journal(since: str, now) -> tuple[list, int, list]:
    if not shutil.which("journalctl"):
        return [], 0, [{"path": "journalctl", "lines": 0, "events": 0, "error": "journalctl not found (not systemd Linux?)"}]
    res = subprocess.run(journal_cmd(since), capture_output=True, text=True, errors="replace")
    events, n = [], 0
    for line in res.stdout.splitlines():
        n += 1
        ev = parse_line(line, now)
        if ev:
            events.append(ev)
    err = res.stderr.strip() if res.returncode != 0 else None
    events.sort(key=lambda e: e.ts)
    return events, n, [{"path": f"journalctl (since {since})", "lines": n, "events": len(events), "error": err}]


# --------------------------------------------------------------------------- #
# Windows Event Log
# --------------------------------------------------------------------------- #
def _wevtutil(query_extra: str = "", count: int = 5000) -> str:
    ids = " or ".join(f"EventID={i}" for i in WIN_EVENT_IDS)
    q = f"*[System[({ids}){query_extra}]]"
    res = subprocess.run(["wevtutil", "qe", "Security", f"/q:{q}", "/f:xml", f"/c:{count}", "/rd:true"],
                         capture_output=True, text=True, errors="replace")
    if res.returncode != 0:
        raise OSError(res.stderr.strip() or "wevtutil failed (run the terminal as Administrator)")
    return res.stdout


def read_windows(now) -> tuple[list, int, list]:
    if not shutil.which("wevtutil"):
        return [], 0, [{"path": "Windows Security log", "lines": 0, "events": 0, "error": "wevtutil not found (not Windows?)"}]
    try:
        events = parse_windows_xml(_wevtutil())
        err = None
    except (OSError, ET.ParseError) as exc:
        events, err = [], str(exc)
    events.sort(key=lambda e: e.ts)
    return events, len(events), [{"path": "Windows Security log", "lines": len(events), "events": len(events), "error": err}]


def poll_windows(seen: set, lookback_ms: int = 60000) -> list:
    """Return Windows events from the last minute that were not returned before."""
    xml_text = _wevtutil(f" and TimeCreated[timediff(@SystemTime) <= {lookback_ms}]", count=1000)
    fresh = []
    for ev in parse_windows_xml(xml_text):
        key = (ev.ts, ev.kind, ev.user, ev.ip, ev.raw)
        if key not in seen:
            seen.add(key)
            fresh.append(ev)
    if len(seen) > 20000:
        seen.clear()
    return sorted(fresh, key=lambda e: e.ts)


# --------------------------------------------------------------------------- #
# live tailing
# --------------------------------------------------------------------------- #
class Tailer:
    """`tail -F` for one file: handles partial lines, truncation and log rotation."""

    def __init__(self, path: Path, from_start: bool = False):
        self.path = Path(path)
        self.fh = None
        self.ino = None
        self.buf = ""
        self._open(from_start)

    def _open(self, from_start: bool):
        if self.fh:
            self.fh.close()
        self.fh = open(self.path, "r", encoding="utf-8", errors="replace")
        self.ino = os.fstat(self.fh.fileno()).st_ino
        self.buf = ""
        if not from_start:
            self.fh.seek(0, os.SEEK_END)

    def poll(self) -> list[str]:
        lines = []
        while True:
            chunk = self.fh.readline()
            if not chunk:
                break
            self.buf += chunk
            if self.buf.endswith("\n"):
                lines.append(self.buf)
                self.buf = ""
        if not lines:
            try:
                st = os.stat(self.path)
                if (self.ino and st.st_ino != self.ino) or st.st_size < self.fh.tell():
                    self._open(from_start=True)  # rotated or truncated: read new file from its start
            except OSError:
                pass  # file briefly missing during rotation
        return lines

    def close(self):
        if self.fh:
            self.fh.close()


def follow_files(paths, on_line: Callable[[str], None], from_start=False,
                 on_idle: Optional[Callable[[], None]] = None, poll_interval=0.5):
    tailers = [Tailer(p, from_start) for p in paths]
    try:
        while True:
            got = False
            for t in tailers:
                for line in t.poll():
                    got = True
                    on_line(line)
            if not got:
                if on_idle:
                    on_idle()
                time.sleep(poll_interval)
    finally:
        for t in tailers:
            t.close()


def follow_journal(on_line: Callable[[str], None]):
    proc = subprocess.Popen(journal_cmd(follow=True), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, errors="replace")
    try:
        for line in proc.stdout:  # type: ignore[union-attr]
            on_line(line)
    finally:
        proc.terminate()
