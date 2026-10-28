"""Detection engine.

Events are fed one at a time (same code for batch reports and live --follow).
Every detector uses sliding time windows, so a slow trickle of old failures
does not trigger an alert but a real burst does.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Optional
from urllib.parse import unquote

from .models import SEV_RANK, Alert, Event

ROOT_NAMES = {"root", "administrator"}

# rule -> (default MITRE ATT&CK id, recommended response)
RULES = {
    "BRUTE_FORCE": ("T1110.001", "Block the source IP, disable SSH password logins (PasswordAuthentication no) or enforce MFA/lockout, "
                    "install fail2ban, and check whether any login from this IP succeeded."),
    "PASSWORD_SPRAY": ("T1110.003", "One source is trying many different usernames. Block the IP, disable unused/default accounts "
                       "(admin, test, oracle...), and verify no account accepted a login."),
    "DISTRIBUTED_BRUTE_FORCE": ("T1110", "Many IPs are hammering one account (botnet). Enforce key-only login or MFA for it, "
                                "rate-limit, and consider geo/ASN restrictions."),
    "SUCCESS_AFTER_FAILURES": ("T1078", "POSSIBLE ACCOUNT TAKEOVER. Confirm with the user, reset credentials, kill active sessions, "
                               "review what was run after the login (sudo/auth logs), and look for persistence (new users, SSH keys, cron)."),
    "ROOT_LOGIN": ("T1078.003", "Disable direct root/Administrator remote login (PermitRootLogin no) and use named accounts with sudo."),
    "NEW_SOURCE_IP": ("T1078", "Verify with the user that the new location/IP is legitimate."),
    "OFF_HOURS_LOGIN": ("T1078", "Verify with the user that this login was expected."),
    "SSH_SCAN": ("T1595", "Scanner/recon activity on SSH. Restrict SSH to known IPs/VPN, or move behind a firewall allow-list."),
    "PORT_SCAN": ("T1046", "Port scan against this host. Block the IP, close unneeded ports, and confirm exposed services are patched."),
    "SUDO_FAILURES": ("T1548.003", "Repeated privilege-escalation failures. Check whether the account is compromised or a user is probing for access."),
    "SUSPICIOUS_COMMAND": ("T1059", "Review the full session of this user; if not an approved admin action, isolate the host and investigate."),
    "ACCOUNT_CREATED": ("T1136.001", "Confirm the new account was approved; if not, disable it and investigate how it was created."),
    "PRIVILEGE_GRANTED": ("T1098", "Confirm the privilege change was approved; if not, revert it and investigate the actor."),
    "LOG_CLEARED": ("T1070.001", "Audit logs were cleared - classic cover-up step. Treat host as compromised until proven otherwise; forward logs off-host."),
    "ACCOUNT_LOCKOUT": ("T1110", "Account lockouts often indicate brute force. Check the source IPs of the preceding failures."),
    "PERSISTENCE": ("T1053", "Verify the new task/service is legitimate; remove it if not."),
    "BLOCKLISTED_IP": ("T1071", "This IP is on your blocklist. Block it and review what it accessed."),
    "WEB_SQLI": ("T1190", "SQL-injection attempt. Verify parameterized queries/WAF, check app and DB logs for success, block the IP."),
    "WEB_XSS": ("T1190", "XSS attempt. Verify output encoding/CSP; check whether payload was stored."),
    "WEB_TRAVERSAL": ("T1190", "Path traversal / local file inclusion attempt. Verify input validation; check for exposed files; block the IP."),
    "WEB_CMDI": ("T1190", "Command-injection/RCE attempt. Patch the target, check the host for unexpected processes, block the IP."),
    "WEB_LOG4SHELL": ("T1190", "Log4Shell (JNDI) exploit attempt. Verify Log4j >= 2.17.1, look for outbound LDAP/DNS callbacks, block the IP."),
    "WEB_SHELLSHOCK": ("T1190", "Shellshock-style payload. Verify bash is patched and CGI is not exposed."),
    "WEB_PROBE": ("T1595.002", "Probing for sensitive files/admin panels. Make sure none of these paths are publicly reachable."),
    "WEB_SCANNER_UA": ("T1595.002", "Known attack/scanning tool user-agent. Block the IP or UA at the proxy/WAF."),
    "WEB_BRUTE_FORCE": ("T1110", "Login brute force against the web app. Add rate limiting/CAPTCHA/MFA and lockout; block the IP."),
    "WEB_SCANNING": ("T1595.003", "Forced browsing / directory scanning. Rate-limit or block the IP."),
}

SUSPICIOUS_COMMANDS = [
    ("Reverse shell", "CRITICAL", "T1059.004",
     re.compile(r"/dev/tcp/|\bbash\s+-i\b|\b(?:nc|ncat|netcat)\b.*\s-[a-z]*[ec]\b|\bsocat\b.*exec|python\S*\s+-c\s+.*socket", re.I)),
    ("Download-and-execute", "HIGH", "T1105",
     re.compile(r"\b(?:curl|wget)\b[^|;]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b", re.I)),
    ("Credential file access", "HIGH", "T1003.008",
     re.compile(r"/etc/shadow|/etc/sudoers|\bvisudo\b|unshadow", re.I)),
    ("Log / history tampering", "HIGH", "T1070",
     re.compile(r"history\s+-c|rm\s+(?:-\w+\s+)*(?:/var/log|~?/?\.bash_history)|shred\b.*(?:log|history)|truncate\b.*log|>\s*/var/log", re.I)),
    ("Security control disabled", "HIGH", "T1562",
     re.compile(r"ufw\s+disable|iptables\s+-F|systemctl\s+(?:stop|disable|mask)\s+(?:ufw|firewalld|auditd|rsyslog|fail2ban|apparmor)|setenforce\s+0", re.I)),
    ("Dangerous permissions / SUID", "HIGH", "T1548.001",
     re.compile(r"chmod\s+(?:-R\s+)?(?:[0-7]?777|\+s|u\+s|[2467]\d{3})\b", re.I)),
    ("Persistence mechanism", "MEDIUM", "T1098.004",
     re.compile(r"authorized_keys|crontab\s+-|/etc/cron|/etc/rc\.local|systemctl\s+enable", re.I)),
    ("Offensive security tool", "MEDIUM", "T1588.002",
     re.compile(r"\b(?:nmap|masscan|hydra|john|hashcat|mimikatz|msfconsole|msfvenom|sqlmap|responder)\b", re.I)),
]

WEB_SIGNATURES = [
    ("WEB_SQLI", "HIGH", "SQL injection",
     re.compile(r"union(?:\s|/\*.*?\*/)+(?:all\s+)?select|select\s.+\sfrom\s|'\s*or\s*'?\d|\bor\s+1\s*=\s*1|information_schema"
                r"|sleep\s*\(\s*\d|benchmark\s*\(|waitfor\s+delay|;\s*drop\s+table|'\s*--", re.I)),
    ("WEB_XSS", "MEDIUM", "Cross-site scripting",
     re.compile(r"<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*svg[\s/]|<\s*img[\s/]|alert\s*\(", re.I)),
    ("WEB_TRAVERSAL", "HIGH", "Path traversal / file inclusion",
     re.compile(r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self|boot\.ini|win\.ini|c:\\windows", re.I)),
    ("WEB_CMDI", "HIGH", "Command injection / RCE",
     re.compile(r"(?:;|\||&&|`|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|powershell|cmd)\b|/bin/(?:ba)?sh|cmd\.exe", re.I)),
    ("WEB_PROBE", "MEDIUM", "Sensitive file / admin panel probe",
     re.compile(r"/\.env\b|/\.git(?:/|$)|/\.svn|/\.aws|/\.ssh|id_rsa|wp-config|phpmyadmin|/pma/|/server-status|/actuator(?:/|$)"
                r"|/\.ds_store|(?:backup|dump|database|db)\.(?:sql|zip|tar\.gz|bak)|/vendor/phpunit|eval-stdin\.php|/boaform|/hnap1", re.I)),
]
LOG4SHELL_RE = re.compile(r"\$\{\s*(?:jndi|lower|upper|env|sys)\s*:", re.I)
SHELLSHOCK_RE = re.compile(r"\(\)\s*\{")
SCANNER_UA_RE = re.compile(
    r"sqlmap|nikto|nmap|masscan|gobuster|dirbuster|dirb/|wpscan|acunetix|nessus|openvas|zgrab|havij|netsparker|feroxbuster|nuclei|whatweb", re.I)
LOGIN_PATH_RE = re.compile(r"wp-login\.php|xmlrpc\.php|/login|/signin|/admin|/user/login|/auth", re.I)

_PRIVATE_NETS = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]


def is_blockable(ip: Optional[str]) -> bool:
    """True for addresses where a firewall block makes sense (not LAN/loopback)."""
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return not any(addr in net for net in _PRIVATE_NETS)


# --------------------------------------------------------------------------- #
@dataclass
class Config:
    threshold: int = 5                    # failed logins per IP inside the window
    window: timedelta = timedelta(minutes=5)
    spray_users: int = 5                  # distinct usernames from one IP
    distributed_ips: int = 5              # distinct IPs against one username
    success_after_fail: int = 3           # failures before a success counts as suspicious
    probe_threshold: int = 5              # SSH scanner probes per IP
    scan_ports: int = 10                  # distinct firewall-blocked ports per IP
    sudo_fail: int = 3
    web_threshold: int = 10               # login POSTs per IP in window (4xx flood = 2x this)
    off_hours: Optional[tuple] = None     # e.g. (22, 6)
    allowlist: list = field(default_factory=list)
    blocklist: list = field(default_factory=list)
    corr_window: timedelta = timedelta(minutes=30)

    def __post_init__(self):
        self.corr_window = max(self.corr_window, self.window)

    @staticmethod
    def _in(nets, ip) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return False
        return any(addr in n for n in nets)

    def allowed(self, ip) -> bool:
        return bool(self.allowlist) and self._in(self.allowlist, ip)

    def blocklisted(self, ip) -> bool:
        return bool(self.blocklist) and self._in(self.blocklist, ip)


class Window:
    """Sliding time window of (timestamp, item)."""
    __slots__ = ("span", "q")

    def __init__(self, span: timedelta):
        self.span = span
        self.q: deque = deque()

    def add(self, ts, item=None):
        self.q.append((ts, item))
        self.trim(ts)

    def trim(self, now):
        while self.q and now - self.q[0][0] > self.span:
            self.q.popleft()

    def since(self, cutoff) -> list:
        return [item for ts, item in self.q if ts >= cutoff]


# --------------------------------------------------------------------------- #
class Engine:
    def __init__(self, cfg: Optional[Config] = None):
        self.cfg = cfg or Config()
        self.alerts: dict = {}
        self._win: dict = defaultdict(dict)
        self._known_ips: dict = defaultdict(set)
        self._count = 0
        self.stats = {
            "events": 0,
            "by_kind": Counter(),
            "fail_by_ip": Counter(), "fail_by_user": Counter(),
            "ok_by_ip": Counter(), "ok_by_user": Counter(),
            "web_by_ip": Counter(), "fw_by_ip": Counter(),
        }

    # -- helpers ----------------------------------------------------------- #
    def _w(self, name: str, key: str, span: Optional[timedelta] = None) -> Window:
        d = self._win[name]
        if key not in d:
            d[key] = Window(span or self.cfg.window)
        return d[key]

    @property
    def _mins(self) -> int:
        return max(1, int(self.cfg.window.total_seconds() // 60))

    def _alert(self, new, rule, key, ev, severity, title, desc, *, count=None, ip=None, user=None, mitre=None):
        default_mitre, rec = RULES[rule]
        k = (rule, key)
        line = (ev.raw or ev.detail)[:300]
        a = self.alerts.get(k)
        if a is None:
            a = Alert(rule=rule, title=title, severity=severity, key=key, first_seen=ev.ts, last_seen=ev.ts,
                      description=desc, mitre=mitre or default_mitre, recommendation=rec, ip=ip, user=user,
                      count=count or 1, evidence=[line] if line else [])
            self.alerts[k] = a
            new.append(a)
            return
        a.last_seen = ev.ts
        a.count = count if count is not None else a.count + 1
        a.description = desc
        if line and len(a.evidence) < 5 and line not in a.evidence:
            a.evidence.append(line)
        if SEV_RANK[severity] > SEV_RANK[a.severity]:
            a.severity, a.title = severity, title
            new.append(a)  # escalation is worth re-notifying

    # -- main entry -------------------------------------------------------- #
    def process(self, ev: Event) -> list:
        """Feed one event; returns alerts that are NEW or ESCALATED because of it."""
        s = self.stats
        s["events"] += 1
        s["by_kind"][ev.kind] += 1
        self._stats(ev)
        new: list = []
        if ev.ip and self.cfg.allowed(ev.ip):
            return new
        if ev.ip and self.cfg.blocklisted(ev.ip):
            self._alert(new, "BLOCKLISTED_IP", ev.ip, ev, "HIGH", f"Activity from blocklisted IP {ev.ip}",
                        f"{ev.service}: {ev.detail}", ip=ev.ip)
        handler = getattr(self, "_on_" + ev.kind.lower(), None)
        if handler:
            handler(ev, new)
        self._count += 1
        if self._count % 5000 == 0:
            self.prune(ev.ts)
        return new

    def prune(self, now):
        for name in list(self._win):
            for key in list(self._win[name]):
                w = self._win[name][key]
                w.trim(now)
                if not w.q:
                    del self._win[name][key]

    def _stats(self, ev: Event):
        s = self.stats
        if ev.kind == "AUTH_FAIL":
            if ev.ip:
                s["fail_by_ip"][ev.ip] += 1
            s["fail_by_user"][ev.user or "(unknown)"] += 1
        elif ev.kind == "AUTH_OK":
            if ev.ip:
                s["ok_by_ip"][ev.ip] += 1
            s["ok_by_user"][ev.user or "(unknown)"] += 1
        elif ev.kind == "WEB_REQ" and ev.ip:
            s["web_by_ip"][ev.ip] += 1
        elif ev.kind == "FW_BLOCK" and ev.ip:
            s["fw_by_ip"][ev.ip] += 1

    # -- authentication ---------------------------------------------------- #
    def _spray_check(self, ev, new):
        cfg = self.cfg
        if not ev.ip or not ev.user:
            return
        w = self._w("users_by_ip", ev.ip)
        w.add(ev.ts, ev.user.lower())
        users = set(w.since(ev.ts - cfg.window))
        if len(users) >= cfg.spray_users:
            sample = ", ".join(sorted(users)[:8])
            self._alert(new, "PASSWORD_SPRAY", ev.ip, ev, "HIGH",
                        f"Username enumeration / password spraying from {ev.ip}",
                        f"{len(users)} different usernames tried within {self._mins} min ({sample}...)",
                        ip=ev.ip, count=len(users))

    def _on_invalid_user(self, ev, new):
        self._spray_check(ev, new)

    def _on_auth_fail(self, ev, new):
        cfg = self.cfg
        user = ev.user or "(unknown)"
        if ev.ip:
            w = self._w("fail_by_ip", ev.ip, cfg.corr_window)
            w.add(ev.ts, user)
            n = len(w.since(ev.ts - cfg.window))
            if n >= cfg.threshold:
                sev = "HIGH" if n >= cfg.threshold * 2 else "MEDIUM"
                self._alert(new, "BRUTE_FORCE", ev.ip, ev, sev, f"Brute-force login attempts from {ev.ip}",
                            f"{n} failed {ev.service} logins within {self._mins} min "
                            f"({self.stats['fail_by_ip'][ev.ip]} failures in total)",
                            ip=ev.ip, count=self.stats["fail_by_ip"][ev.ip])
            self._spray_check(ev, new)
        if ev.user and ev.ip:
            w = self._w("ips_by_user", ev.user.lower())
            w.add(ev.ts, ev.ip)
            ips = set(w.since(ev.ts - cfg.window))
            if len(ips) >= cfg.distributed_ips:
                self._alert(new, "DISTRIBUTED_BRUTE_FORCE", ev.user.lower(), ev, "HIGH",
                            f"Distributed attack on account '{ev.user}'",
                            f"{len(ips)} different IPs failed to log in as '{ev.user}' within {self._mins} min",
                            user=ev.user, count=len(ips))

    def _on_auth_ok(self, ev, new):
        cfg = self.cfg
        user = ev.user or "(unknown)"
        if ev.ip:
            w = self._win["fail_by_ip"].get(ev.ip)
            if w:
                prior = w.since(ev.ts - cfg.corr_window)
                if len(prior) >= cfg.success_after_fail:
                    tried = ", ".join(sorted(set(prior))[:8])
                    self._alert(new, "SUCCESS_AFTER_FAILURES", f"{ev.ip}|{user}", ev, "CRITICAL",
                                f"Login SUCCEEDED for '{user}' from {ev.ip} after {len(prior)} failures",
                                f"{ev.ip} failed {len(prior)} times (users tried: {tried}) and then logged in as "
                                f"'{user}' via {ev.extra.get('method', ev.service)}",
                                ip=ev.ip, user=user, count=len(prior))
            known = self._known_ips[user.lower()]
            if known and ev.ip not in known:
                self._alert(new, "NEW_SOURCE_IP", f"{user}|{ev.ip}", ev, "LOW",
                            f"'{user}' logged in from a new IP {ev.ip}",
                            f"Previously seen IPs for this user: {', '.join(sorted(known)[:5])}", ip=ev.ip, user=user)
            known.add(ev.ip)
        if user.lower() in ROOT_NAMES and ev.service in ("ssh", "windows"):
            pw = "password" in str(ev.extra.get("method", "")).lower() or ev.service == "windows"
            self._alert(new, "ROOT_LOGIN", f"{user}|{ev.ip}", ev, "HIGH" if pw else "MEDIUM",
                        f"Direct {user} login from {ev.ip or 'local'}", f"{ev.detail}", ip=ev.ip, user=user)
        if cfg.off_hours:
            start, end = cfg.off_hours
            h = ev.ts.hour
            if (start <= h < end) if start <= end else (h >= start or h < end):
                self._alert(new, "OFF_HOURS_LOGIN", f"{user}|{ev.ts.date()}", ev, "MEDIUM",
                            f"Off-hours login by '{user}' at {ev.ts.strftime('%H:%M')}",
                            f"Login from {ev.ip or 'local'} outside normal hours ({start}:00-{end}:00)", ip=ev.ip, user=user)

    def _on_ssh_probe(self, ev, new):
        if not ev.ip:
            return
        w = self._w("probe_by_ip", ev.ip)
        w.add(ev.ts, ev.detail)
        n = len(w.since(ev.ts - self.cfg.window))
        if n >= self.cfg.probe_threshold:
            self._alert(new, "SSH_SCAN", ev.ip, ev, "MEDIUM", f"SSH scanning / reconnaissance from {ev.ip}",
                        f"{n} malformed/aborted SSH connections within {self._mins} min", ip=ev.ip, count=n)

    def _on_account_locked(self, ev, new):
        self._alert(new, "ACCOUNT_LOCKOUT", (ev.user or "?").lower(), ev, "MEDIUM",
                    f"Account '{ev.user}' locked out", ev.detail, user=ev.user)

    # -- privilege / persistence ------------------------------------------ #
    def _on_sudo_fail(self, ev, new):
        user = (ev.user or "(unknown)").lower()
        if ev.extra.get("not_in_sudoers"):
            self._alert(new, "SUDO_FAILURES", f"{user}|nosudo", ev, "MEDIUM",
                        f"'{user}' tried sudo but is not in sudoers", ev.detail, user=user)
            return
        w = self._w("sudo_fail", user)
        w.add(ev.ts)
        n = len(w.since(ev.ts - self.cfg.window))
        if n >= self.cfg.sudo_fail:
            self._alert(new, "SUDO_FAILURES", user, ev, "MEDIUM", f"Repeated {ev.service} failures for '{user}'",
                        f"{n} failed {ev.service} authentications within {self._mins} min", user=user, count=n)

    def _on_priv_cmd(self, ev, new):
        cmd = ev.extra.get("cmd", ev.detail)
        for label, sev, mitre, rx in SUSPICIOUS_COMMANDS:
            if rx.search(cmd):
                user = ev.user or "?"
                self._alert(new, "SUSPICIOUS_COMMAND", f"{user}|{label}", ev, sev,
                            f"{label} by '{user}' via sudo", f"Command: {cmd[:160]}", user=user, mitre=mitre)

    def _on_account_new(self, ev, new):
        self._alert(new, "ACCOUNT_CREATED", f"{ev.service}|{ev.user}", ev, "MEDIUM",
                    f"New account created: '{ev.user}'", ev.detail, user=ev.user)

    def _on_account_priv(self, ev, new):
        self._alert(new, "PRIVILEGE_GRANTED", f"{ev.user}|{ev.extra.get('group')}", ev, "HIGH",
                    f"Privilege granted to '{ev.user}'", ev.detail, user=ev.user)

    def _on_log_cleared(self, ev, new):
        self._alert(new, "LOG_CLEARED", f"{ev.host}|{ev.ts:%Y%m%d%H%M}", ev, "CRITICAL",
                    "Security audit log was CLEARED", f"Cleared by '{ev.user or '?'}' on {ev.host or 'this host'}", user=ev.user)

    def _on_persistence(self, ev, new):
        self._alert(new, "PERSISTENCE", f"{ev.user}|{ev.detail}", ev, "MEDIUM", ev.detail,
                    f"Created by '{ev.user or '?'}'", user=ev.user)

    # -- network ----------------------------------------------------------- #
    def _on_fw_block(self, ev, new):
        port = ev.extra.get("dport")
        if not ev.ip or port is None:
            return
        w = self._w("ports_by_ip", ev.ip)
        w.add(ev.ts, port)
        ports = set(w.since(ev.ts - self.cfg.window))
        if len(ports) >= self.cfg.scan_ports:
            self._alert(new, "PORT_SCAN", ev.ip, ev, "HIGH", f"Port scan from {ev.ip}",
                        f"{len(ports)} different ports probed within {self._mins} min "
                        f"(e.g. {', '.join(str(p) for p in sorted(ports)[:10])})", ip=ev.ip, count=len(ports))

    # -- web --------------------------------------------------------------- #
    def _on_web_req(self, ev, new):
        cfg = self.cfg
        ip, x = ev.ip, ev.extra
        path = unquote(unquote(x.get("path", ""))).replace("+", " ")
        ua, ref = x.get("ua", ""), x.get("ref", "")
        status = x.get("status", 0)
        blob = f"{path} {ua} {ref}"

        def hit(rule, sev, label):
            self._alert(new, rule, f"{ip}|{rule}", ev, sev, f"{label} attempt from {ip}",
                        f"{label} patterns in requests (last: {x.get('method')} {path[:100]} -> {status})", ip=ip)

        if LOG4SHELL_RE.search(blob):
            hit("WEB_LOG4SHELL", "CRITICAL", "Log4Shell (JNDI)")
        if SHELLSHOCK_RE.search(blob):
            hit("WEB_SHELLSHOCK", "HIGH", "Shellshock")
        for rule, sev, label, rx in WEB_SIGNATURES:
            if rx.search(path):
                hit(rule, sev, label)
        if ua and SCANNER_UA_RE.search(ua):
            self._alert(new, "WEB_SCANNER_UA", f"{ip}|ua", ev, "MEDIUM", f"Attack tool user-agent from {ip}",
                        f"User-Agent: {ua[:100]}", ip=ip)
        if ip and x.get("method") == "POST" and LOGIN_PATH_RE.search(path):
            w = self._w("weblogin_by_ip", ip)
            w.add(ev.ts)
            n = len(w.since(ev.ts - cfg.window))
            if n >= cfg.web_threshold:
                self._alert(new, "WEB_BRUTE_FORCE", ip, ev, "HIGH", f"Web login brute force from {ip}",
                            f"{n} POST requests to login endpoints within {self._mins} min", ip=ip, count=n)
        if ip and status in (401, 403, 404):
            w = self._w("web4xx_by_ip", ip)
            w.add(ev.ts)
            n = len(w.since(ev.ts - cfg.window))
            if n >= cfg.web_threshold * 2:
                self._alert(new, "WEB_SCANNING", ip, ev, "MEDIUM", f"Web scanning / forced browsing from {ip}",
                            f"{n} requests answered 401/403/404 within {self._mins} min", ip=ip, count=n)
