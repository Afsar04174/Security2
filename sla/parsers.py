"""Log parsers: raw log lines / Windows XML  ->  normalized Event objects.

Supported inputs
  * Linux auth logs (/var/log/auth.log, /var/log/secure, journalctl short-iso)
      - OpenSSH: failed/accepted logins, invalid users, scanner banners
      - sudo / su: failures and executed commands
      - useradd / usermod / gpasswd: account creation and privilege changes
  * Firewall drops written by UFW / iptables (kernel log lines)
  * Apache / Nginx "combined" access logs
  * Windows Security events exported with wevtutil as XML
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import unquote  # noqa: F401  (re-exported for detectors)

from .models import Event

LOCAL_TZ = datetime.now().astimezone().tzinfo

PRIV_GROUPS = {"sudo", "wheel", "admin", "root", "docker", "shadow", "lxd"}
WIN_PRIV_GROUPS = {"administrators", "domain admins", "enterprise admins",
                   "remote desktop users", "backup operators"}

# --------------------------------------------------------------------------- #
# timestamps
# --------------------------------------------------------------------------- #
SYSLOG_TS = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$")
ISO_TS = re.compile(
    r"^(?P<d>\d{4}-\d{2}-\d{2})[T ](?P<t>\d{2}:\d{2}:\d{2})(?:[.,]\d+)?"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2})?\s+(?P<rest>.*)$")
HOST_PROC = re.compile(
    r"^(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")


def parse_timestamp(line: str, now: datetime):
    """Return (aware datetime, remaining text) or (None, line)."""
    m = ISO_TS.match(line)
    if m:
        tz = m.group("tz")
        try:
            if tz is None:
                ts = datetime.strptime(f"{m['d']} {m['t']}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=LOCAL_TZ)
            else:
                tz = "+0000" if tz == "Z" else tz.replace(":", "")
                ts = datetime.strptime(f"{m['d']} {m['t']} {tz}", "%Y-%m-%d %H:%M:%S %z")
            return ts, m.group("rest")
        except ValueError:
            return None, line
    m = SYSLOG_TS.match(line)
    if m:
        try:
            # Syslog has no year: assume current year, roll back if it would be in the future.
            ts = datetime.strptime(f"{now.year} {m['mon']} {m['day']} {m['time']}",
                                   "%Y %b %d %H:%M:%S").replace(tzinfo=LOCAL_TZ)
            if ts - now > timedelta(days=1):
                ts = ts.replace(year=ts.year - 1)
            return ts, m.group("rest")
        except ValueError:
            return None, line
    return None, line


def clean_ip(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    value = value.strip().strip("[]").rstrip(",;:")
    if value.lower().startswith("::ffff:"):
        value = value[7:]
    return None if value in ("", "-", "?", "unknown") else value


# --------------------------------------------------------------------------- #
# SSH
# --------------------------------------------------------------------------- #
SSH_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<inv>(?:invalid|illegal) user )?(?P<user>\S+) from (?P<ip>\S+)")
SSH_ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)")
SSH_INVALID = re.compile(r"^(?:Invalid|Illegal) user (?P<user>.*?) from (?P<ip>\S+)")
SSH_SCANNER = [
    (re.compile(r"Did not receive identification string from (?P<ip>\S+)"), "no SSH banner sent"),
    (re.compile(r"Bad protocol version identification .*? from (?P<ip>\S+)"), "non-SSH protocol / bad banner"),
    (re.compile(r"banner exchange: Connection from (?P<ip>\S+) port \d+"), "invalid banner exchange"),
    (re.compile(r"Unable to negotiate with (?P<ip>\S+) port"), "no matching algorithms (scanner/old client)"),
    (re.compile(r"Timeout before authentication for (?:connection from )?(?P<ip>\S+)"), "timeout before auth"),
]


def _ssh(ts, host, msg, raw) -> Optional[Event]:
    m = SSH_FAILED.match(msg)
    if m:
        return Event(ts, "AUTH_FAIL", "ssh", host, user=m["user"], ip=clean_ip(m["ip"]),
                     detail=f"Failed SSH {m['method']}" + (" (invalid user)" if m["inv"] else ""),
                     extra={"invalid_user": bool(m["inv"]), "method": m["method"]}, raw=raw)
    m = SSH_ACCEPTED.match(msg)
    if m:
        return Event(ts, "AUTH_OK", "ssh", host, user=m["user"], ip=clean_ip(m["ip"]),
                     detail=f"Accepted SSH {m['method']}", extra={"method": m["method"]}, raw=raw)
    m = SSH_INVALID.match(msg)
    if m:
        return Event(ts, "INVALID_USER", "ssh", host, user=m["user"], ip=clean_ip(m["ip"]),
                     detail="Login attempt for non-existent user", raw=raw)
    for rx, reason in SSH_SCANNER:
        m = rx.search(msg)
        if m:
            return Event(ts, "SSH_PROBE", "ssh", host, ip=clean_ip(m["ip"]), detail=reason, raw=raw)
    # NOTE: "pam_unix(sshd:auth): authentication failure" is deliberately ignored:
    # sshd logs it *in addition to* "Failed password", so counting both doubles every attempt.
    return None


# --------------------------------------------------------------------------- #
# PAM / sudo / su
# --------------------------------------------------------------------------- #
PAM_FAIL = re.compile(r"pam_unix\((?P<svc>[\w.-]+):auth\): authentication failure")
SUDO_LINE = re.compile(r"^\s*(?P<user>\S+)\s*:\s*(?P<body>.*)$")


def _pam(ts, host, msg, raw) -> Optional[Event]:
    m = PAM_FAIL.search(msg)
    if not m:
        return None
    svc = m["svc"].lower()
    if svc == "sshd":
        return None
    u = re.search(r"(?<![A-Za-z])user=(\S*)", msg)
    r = re.search(r"rhost=(\S*)", msg)
    user = (u.group(1) if u else "") or None
    if svc in ("sudo", "su", "su-l"):
        return Event(ts, "SUDO_FAIL", svc, host, user=user, detail=f"{svc} authentication failure", raw=raw)
    return Event(ts, "AUTH_FAIL", svc, host, user=user, ip=clean_ip(r.group(1) if r else None),
                 detail=f"PAM authentication failure ({svc})", raw=raw)


def _sudo(ts, host, msg, raw) -> Optional[Event]:
    if "COMMAND=" in msg:
        m = SUDO_LINE.match(msg)
        if not m:
            return None
        body = m["body"]
        cmd = body.split("COMMAND=", 1)[1].strip()
        target = re.search(r"USER=(\S+)", body)
        if "NOT in sudoers" in body:
            return Event(ts, "SUDO_FAIL", "sudo", host, user=m["user"],
                         detail="user not in sudoers tried: " + cmd, extra={"not_in_sudoers": True}, raw=raw)
        if "incorrect password" in body:
            return None  # the per-attempt pam_unix lines already count these
        return Event(ts, "PRIV_CMD", "sudo", host, user=m["user"], detail=cmd,
                     extra={"target": target.group(1) if target else "root", "cmd": cmd}, raw=raw)
    return _pam(ts, host, msg, raw)


# --------------------------------------------------------------------------- #
# account changes
# --------------------------------------------------------------------------- #
USERADD = re.compile(r"new user: name=(?P<user>[^,\s]+)")
GROUP_ADD = re.compile(r"add '(?P<user>[^']+)' to (?:shared )?group '(?P<group>[^']+)'")
GPASSWD_ADD = re.compile(r"user (?P<user>\S+) added by (?P<by>\S+) to group (?P<group>\S+)")


def _account(ts, host, proc, msg, raw) -> Optional[Event]:
    if proc == "useradd":
        m = USERADD.search(msg)
        if m:
            return Event(ts, "ACCOUNT_NEW", "system", host, user=m["user"],
                         detail=f"New local account '{m['user']}' created", raw=raw)
    m = GROUP_ADD.search(msg) or GPASSWD_ADD.search(msg)
    if m and m["group"].lower() in PRIV_GROUPS:
        return Event(ts, "ACCOUNT_PRIV", "system", host, user=m["user"],
                     detail=f"'{m['user']}' added to privileged group '{m['group']}'",
                     extra={"group": m["group"]}, raw=raw)
    return None


# --------------------------------------------------------------------------- #
# firewall (UFW / iptables via kernel log)
# --------------------------------------------------------------------------- #
FW_ACTION = re.compile(r"\b(BLOCK|DROP|REJECT|DENY)\b")


def _firewall(ts, host, msg, raw) -> Optional[Event]:
    if "SRC=" not in msg or not FW_ACTION.search(msg):
        return None
    src = re.search(r"SRC=(\S+)", msg)
    dpt = re.search(r"DPT=(\d+)", msg)
    dst = re.search(r"DST=(\S+)", msg)
    proto = re.search(r"PROTO=(\w+)", msg)
    return Event(ts, "FW_BLOCK", "firewall", host, ip=clean_ip(src.group(1)) if src else None,
                 detail=f"Firewall blocked {proto.group(1) if proto else '?'} to port {dpt.group(1) if dpt else '?'}",
                 extra={"dport": int(dpt.group(1)) if dpt else None,
                        "proto": proto.group(1) if proto else None,
                        "dst": dst.group(1) if dst else None}, raw=raw)


# --------------------------------------------------------------------------- #
# web access logs (Apache / Nginx combined format)
# --------------------------------------------------------------------------- #
WEB_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<authuser>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>[^"]*?)(?: HTTP/[\d.]+)?" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')


def _web(line: str) -> Optional[Event]:
    m = WEB_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    return Event(ts, "WEB_REQ", "web", user=None if m["authuser"] == "-" else m["authuser"],
                 ip=clean_ip(m["ip"]), detail=f"{m['method']} {m['path'][:120]} -> {m['status']}",
                 extra={"method": m["method"], "path": m["path"], "status": int(m["status"]),
                        "ua": m["ua"] or "", "ref": m["ref"] or ""}, raw=line)


# --------------------------------------------------------------------------- #
# entry point for text lines
# --------------------------------------------------------------------------- #
def parse_line(line: str, now: Optional[datetime] = None) -> Optional[Event]:
    """Parse one text log line. Returns None for lines that are not security relevant."""
    line = line.rstrip("\r\n")
    if not line.strip():
        return None
    now = now or datetime.now(LOCAL_TZ)

    ev = _web(line)
    if ev:
        return ev

    ts, rest = parse_timestamp(line, now)
    if ts is None:
        return None
    m = HOST_PROC.match(rest)
    if not m:
        return None
    host, proc, msg = m["host"], m["proc"].lower(), m["msg"]

    if proc in ("sshd", "ssh"):
        return _ssh(ts, host, msg, line)
    if proc == "sudo":
        return _sudo(ts, host, msg, line)
    if proc in ("useradd", "usermod", "gpasswd", "groupmod", "adduser"):
        return _account(ts, host, proc, msg, line)
    if proc == "kernel":
        return _firewall(ts, host, msg, line)
    if "pam_unix(" in msg:
        return _pam(ts, host, msg, line)
    return None


# --------------------------------------------------------------------------- #
# Windows Security log (wevtutil qe Security /f:xml)
# --------------------------------------------------------------------------- #
WIN_EVENT_IDS = (4624, 4625, 4720, 4728, 4732, 4756, 4740, 1102, 4698, 4697)
_SYSTIME = re.compile(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _win_ts(value: str) -> datetime:
    m = _SYSTIME.match(value or "")
    if not m:
        return datetime.now(LOCAL_TZ)
    utc = datetime.strptime(f"{m[1]} {m[2]}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    return utc.astimezone(LOCAL_TZ)


def _win_event(eid: int, d: dict, ts: datetime, host: str) -> Optional[Event]:
    user = d.get("TargetUserName") or None
    raw = f"WindowsEvent {eid} host={host} " + " ".join(
        f"{k}={d[k]}" for k in ("TargetUserName", "SubjectUserName", "IpAddress", "LogonType") if d.get(k))
    if eid == 4625:
        return Event(ts, "AUTH_FAIL", "windows", host, user=user, ip=clean_ip(d.get("IpAddress")),
                     detail=f"Failed Windows logon (type {d.get('LogonType', '?')})",
                     extra={"logon_type": d.get("LogonType")}, raw=raw)
    if eid == 4624:
        lt = d.get("LogonType", "")
        if lt not in {"2", "3", "7", "10", "11"}:
            return None
        if not user or user.endswith("$") or user.upper() in {"SYSTEM", "ANONYMOUS LOGON"}:
            return None
        return Event(ts, "AUTH_OK", "windows", host, user=user, ip=clean_ip(d.get("IpAddress")),
                     detail=f"Windows logon type {lt}", extra={"method": f"logon type {lt}"}, raw=raw)
    if eid == 4720:
        return Event(ts, "ACCOUNT_NEW", "windows", host, user=user,
                     detail=f"Account '{user}' created by {d.get('SubjectUserName', '?')}", raw=raw)
    if eid in (4728, 4732, 4756):
        group = (d.get("TargetUserName") or "").lower()
        member = d.get("MemberName") or d.get("MemberSid") or "?"
        if group in WIN_PRIV_GROUPS:
            return Event(ts, "ACCOUNT_PRIV", "windows", host, user=member,
                         detail=f"'{member}' added to '{d.get('TargetUserName')}' by {d.get('SubjectUserName', '?')}",
                         extra={"group": d.get("TargetUserName")}, raw=raw)
        return None
    if eid == 4740:
        return Event(ts, "ACCOUNT_LOCKED", "windows", host, user=user,
                     detail=f"Account '{user}' locked out", raw=raw)
    if eid == 1102:
        return Event(ts, "LOG_CLEARED", "windows", host, user=d.get("SubjectUserName"),
                     detail="Security audit log was cleared", raw=raw)
    if eid in (4698, 4697):
        what = "scheduled task" if eid == 4698 else "service"
        return Event(ts, "PERSISTENCE", "windows", host, user=d.get("SubjectUserName"),
                     detail=f"New {what}: {d.get('TaskName') or d.get('ServiceName') or '?'}", raw=raw)
    return None


def parse_windows_xml(text: str) -> list[Event]:
    """Parse the concatenated <Event> documents that `wevtutil qe ... /f:xml` prints."""
    text = re.sub(r"<\?xml[^>]*\?>", "", text)
    root = ET.fromstring(f"<Events>{text}</Events>")
    out: list[Event] = []
    for ev in root:
        eid, ts_raw, host = None, "", ""
        data: dict = {}
        for node in ev.iter():
            tag = _local(node.tag)
            if tag == "EventID" and node.text:
                eid = int(node.text.strip())
            elif tag == "TimeCreated":
                ts_raw = node.get("SystemTime", "")
            elif tag == "Computer":
                host = (node.text or "").strip()
            elif tag == "Data" and node.get("Name"):
                data[node.get("Name")] = (node.text or "").strip()
            elif tag == "SubjectUserName" and node.text:  # UserData-style events (e.g. 1102)
                data.setdefault("SubjectUserName", node.text.strip())
        if eid is None:
            continue
        parsed = _win_event(eid, data, _win_ts(ts_raw), host)
        if parsed:
            out.append(parsed)
    return out
