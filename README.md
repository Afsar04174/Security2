# Security Log Analyzer (v2) - detects real attack patterns in real logs

A defensive, dependency-free (Python 3.10+, standard library only) tool that reads **your own** system logs and
raises alerts for real attack behaviour: brute force, account takeover, password spraying, scanners, web exploits,
port scans, privilege escalation and persistence. It works on batch logs (reports) and live (`--follow`).

Use it only on systems and logs you own or are authorised to review.

## Web dashboard (new)

A local browser dashboard is included and connected to the same Python detection engine:

```bash
python web_app.py
```

Then open http://127.0.0.1:8000. The dashboard analyzes bundled sample logs on load, or you can upload a log file. It shows real detections, evidence, MITRE ATT&CK mapping, parsed events, and CSV/JSON/TXT exports. No extra packages are required. See `README_FRONTEND.md` for details.

## Quick start

```bash
python main.py                  # demo on bundled sample attack logs (sample_logs/)
python main.py --auto           # find and analyse THIS machine's own logs
python main.py --auto --follow  # live monitoring, alerts appear as attacks happen
```

| Situation | Command |
|---|---|
| Debian / Ubuntu / Kali | `sudo python3 main.py --auto` |
| RHEL / CentOS / Fedora | `sudo python3 main.py --auto` (uses `/var/log/secure`) |
| No `/var/log/auth.log` (modern systemd) | `sudo python3 main.py --journal --since "24 hours ago"` |
| Specific files (also `.gz` archives) | `python3 main.py --log /var/log/auth.log /var/log/nginx/access.log` |
| Windows Security log | Open terminal **as Administrator**: `python main.py --windows` |
| Windows exported XML | `wevtutil qe Security /f:xml /c:5000 /rd:true > sec.xml` then `python main.py --log sec.xml` |
| Live, existing + new lines | `python3 main.py --log /var/log/auth.log --follow --from-start` |

`sudo` is only needed to *read* protected logs; the tool never modifies logs, firewall rules or system settings.
Run `python main.py --auto` first: it prints which standard log files exist, which are unreadable, and what to do.

## What it detects

| Rule | Meaning | Severity | MITRE ATT&CK |
|---|---|---|---|
| SUCCESS_AFTER_FAILURES | A login succeeded from an IP that had just failed repeatedly (probable takeover) | CRITICAL | T1078 |
| BRUTE_FORCE | N failed logins from one IP inside the time window (SSH, Windows, PAM) | MEDIUM/HIGH | T1110.001 |
| PASSWORD_SPRAY | One IP trying many different usernames | HIGH | T1110.003 |
| DISTRIBUTED_BRUTE_FORCE | Many IPs attacking one account | HIGH | T1110 |
| ROOT_LOGIN | Direct root / Administrator remote login | MEDIUM/HIGH | T1078.003 |
| NEW_SOURCE_IP / OFF_HOURS_LOGIN | Known user from a new IP / login outside work hours (`--off-hours 22-6`) | LOW/MEDIUM | T1078 |
| SSH_SCAN | Scanner footprints (no banner, bad protocol, timeouts) | MEDIUM | T1595 |
| PORT_SCAN | One IP hitting many ports blocked by UFW/iptables | HIGH | T1046 |
| SUDO_FAILURES | Repeated sudo/su failures, or user not in sudoers | MEDIUM | T1548.003 |
| SUSPICIOUS_COMMAND | sudo commands: reverse shells, curl-pipe-sh, `/etc/shadow`, `history -c`, firewall/auditd off, SUID, tools like nmap/hydra | MEDIUM-CRITICAL | various |
| ACCOUNT_CREATED / PRIVILEGE_GRANTED | New user, user added to sudo/wheel/Administrators | MEDIUM/HIGH | T1136, T1098 |
| LOG_CLEARED | Windows audit log cleared | CRITICAL | T1070.001 |
| PERSISTENCE / ACCOUNT_LOCKOUT | New scheduled task/service, account lockouts (Windows) | MEDIUM | T1053, T1110 |
| WEB_SQLI / XSS / TRAVERSAL / CMDI | Injection and traversal patterns in Apache/Nginx access logs | MEDIUM/HIGH | T1190 |
| WEB_LOG4SHELL / SHELLSHOCK | JNDI and `() {` payloads in URL, user-agent or referer | CRITICAL/HIGH | T1190 |
| WEB_PROBE / SCANNER_UA / SCANNING / BRUTE_FORCE | `.env`, `.git`, phpMyAdmin probes; sqlmap/nikto UAs; 404 floods; login POST floods | MEDIUM/HIGH | T1595, T1110 |

Every alert carries evidence lines, a MITRE ATT&CK id and a recommended response.
Thresholds use **sliding time windows**, so a slow trickle of failures does not alert but a burst does.

## Output

Batch mode writes to `reports/`: `.txt` (full report), `.html` (readable dashboard), `.json` (for SIEM/scripts),
`.csv` (all parsed events). The report ends with **suggested** containment commands (ufw / iptables / netsh) for
attacker IPs. They are printed, never executed, and LAN/loopback addresses are skipped.
Live mode appends to `reports/live_alerts.log` and `reports/live_alerts.jsonl`, and can post to a webhook:
`--webhook https://hooks.slack.com/...` (Slack/Discord/Teams-style JSON, best-effort).

Automation: `--fail-on HIGH` makes the process exit with code 2 when an alert at that level exists (cron / CI).
Exit code 1 means nothing was analysed (missing/unreadable log) - never treat that as "clean".

## Tuning (reduce false positives)

```bash
python main.py --auto --threshold 8 --window-minutes 10
python main.py --auto --allowlist 192.168.1.0/24,203.0.113.7     # trusted: never alerted on (or a file, one per line)
python main.py --auto --blocklist bad_ips.txt                     # known-bad: always alerts
python main.py --auto --off-hours 22-6 --min-severity MEDIUM
```

Options: `--spray-users`, `--scan-ports`, `--web-threshold`, `--success-after-fail`.
Note: an allowlist suppresses events from those IPs only; actions by user (e.g. a reverse shell via sudo) still alert.

## Test the live detector safely

```bash
# terminal 1
python main.py --follow --log sample_logs/live_test.log
# terminal 2  (writes FAKE log lines to a local file only - no network traffic)
python tools/simulate_events.py --file sample_logs/live_test.log --scenario all
```

Run the unit tests: `python -m unittest discover -s tests -v`

## Layout

```
main.py              CLI (batch + live)
sla/parsers.py       log line / Windows XML -> normalized events
sla/detectors.py     detection rules (sliding windows, correlation)
sla/sources.py       file discovery, .gz, journalctl, wevtutil, tail -F with rotation handling
sla/reporting.py     console, TXT, CSV, JSON, HTML
sample_logs/         realistic attack scenarios + normal traffic
tools/               attack-log simulator
tests/               26 unit tests
```

## Limitations (please read)

- It can only detect what is **logged**. SSH, sudo, web server and firewall logging must be enabled
  (e.g. `sudo ufw logging on`). It is a log analyzer, not an IDS/IPS, EDR or antivirus, and it does not block anything.
- Rule/threshold based: an alert means "investigate", not "proven attack". NAT/VPN/proxy IPs can hide many users;
  legitimate admins also run commands like `nmap`. Tune with allowlists.
- Web detection matches common attack signatures in the request line; a 200 response does not prove an exploit worked.
  Encrypted or POST-body payloads are not visible in access logs.
- Verified in a Linux sandbox with simulated logs (parsers, detectors, live follow incl. log rotation, reports).
  `--journal` and `--windows` call `journalctl` / `wevtutil` and could not be run against a real system there; the
  Windows XML parser itself is tested with sample events. If either fails on your machine, the error is printed.
- Syslog timestamps have no year; the year is inferred (current year, rolled back if the date would be in the future).
