#!/usr/bin/env python3
"""Security Log Analyzer - detects real attack patterns in Linux, web, firewall and Windows logs.

Examples
  python main.py                              # demo on the bundled sample logs
  python main.py --auto                       # find and analyse this machine's own logs
  python main.py --log /var/log/auth.log /var/log/nginx/access.log
  python main.py --journal --since "24 hours ago"
  python main.py --windows                    # Windows Security log (run terminal as Administrator)
  python main.py --auto --follow              # live monitoring with real-time alerts
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

from sla import sources
from sla.detectors import Config, Engine
from sla.models import SEV_RANK, SEVERITIES
from sla.parsers import LOCAL_TZ, parse_line
from sla.reporting import alert_line, build_result, format_console, write_reports

import ipaddress

PROJECT_DIR = Path(__file__).resolve().parent
SAMPLE_DIR = PROJECT_DIR / "sample_logs"
DEFAULT_OUT = PROJECT_DIR / "reports"


# --------------------------------------------------------------------------- #
def parse_args(argv=None):
    p = argparse.ArgumentParser(prog="main.py", description="Detect real attacks in security logs.",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    s = p.add_argument_group("where to look")
    s.add_argument("--log", "-l", nargs="+", type=Path, help="one or more log files (.log, .gz, or Windows .xml)")
    s.add_argument("--auto", action="store_true", help="discover standard log locations on this machine")
    s.add_argument("--rotated", action="store_true", help="with --auto: also read auth.log.1 and *.gz archives")
    s.add_argument("--journal", action="store_true", help="read systemd journal (when /var/log/auth.log does not exist)")
    s.add_argument("--since", default="24 hours ago", help="with --journal: how far back (default: 24 hours ago)")
    s.add_argument("--windows", action="store_true", help="read the Windows Security event log (needs Administrator)")

    m = p.add_argument_group("mode")
    m.add_argument("--follow", "-f", action="store_true", help="live monitoring: alert as new events arrive")
    m.add_argument("--from-start", action="store_true", help="with --follow: process existing content first")

    t = p.add_argument_group("tuning")
    t.add_argument("--threshold", type=int, default=5, help="failed logins per IP inside the window (default 5)")
    t.add_argument("--window-minutes", type=int, default=5, help="detection window (default 5)")
    t.add_argument("--spray-users", type=int, default=5, help="distinct usernames from one IP = spraying (default 5)")
    t.add_argument("--scan-ports", type=int, default=10, help="distinct blocked ports from one IP = port scan (default 10)")
    t.add_argument("--web-threshold", type=int, default=10, help="web login POSTs per window (default 10)")
    t.add_argument("--success-after-fail", type=int, default=3, help="failures before a success is critical (default 3)")
    t.add_argument("--off-hours", metavar="START-END", help="flag logins in these hours, e.g. 22-6")
    t.add_argument("--allowlist", help="trusted IPs/CIDRs (comma list or file) that are never alerted on")
    t.add_argument("--blocklist", help="known-bad IPs/CIDRs (comma list or file) that always alert")

    o = p.add_argument_group("output")
    o.add_argument("--output-dir", type=Path, default=DEFAULT_OUT)
    o.add_argument("--min-severity", choices=SEVERITIES, default="LOW")
    o.add_argument("--fail-on", choices=SEVERITIES, help="exit code 2 if an alert at/above this level exists (for cron/CI)")
    o.add_argument("--webhook", help="POST live alerts (JSON) to this Slack/Discord/Teams-style webhook URL")
    o.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)
    for name in ("threshold", "window_minutes", "spray_users", "scan_ports", "web_threshold", "success_after_fail"):
        if getattr(args, name) < 1:
            p.error(f"--{name.replace('_', '-')} must be at least 1")
    return args


def load_networks(spec):
    """Comma-separated IPs/CIDRs, or a file with one per line (# comments allowed)."""
    if not spec:
        return []
    path = Path(spec)
    items = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                items.append(line)
    else:
        items = [x.strip() for x in spec.split(",") if x.strip()]
    nets = []
    for item in items:
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            print(f"WARNING: ignoring invalid IP/CIDR '{item}'", file=sys.stderr)
    return nets


def build_config(args) -> Config:
    off = None
    if args.off_hours:
        try:
            a, b = args.off_hours.split("-")
            off = (int(a), int(b))
            if not (0 <= off[0] <= 23 and 0 <= off[1] <= 24):
                raise ValueError
        except ValueError:
            sys.exit("--off-hours must look like 22-6")
    return Config(threshold=args.threshold, window=timedelta(minutes=args.window_minutes),
                  spray_users=args.spray_users, scan_ports=args.scan_ports, web_threshold=args.web_threshold,
                  success_after_fail=args.success_after_fail, off_hours=off,
                  allowlist=load_networks(args.allowlist), blocklist=load_networks(args.blocklist))


def use_color(args) -> bool:
    if args.no_color or os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        os.system("")  # enables ANSI escape codes in Windows 10+ terminals
    return True


def settings_text(args) -> str:
    return (f"threshold={args.threshold} window={args.window_minutes}min spray_users={args.spray_users} "
            f"scan_ports={args.scan_ports} web_threshold={args.web_threshold} "
            f"success_after_fail={args.success_after_fail}")


# --------------------------------------------------------------------------- #
def resolve_files(args) -> list[Path]:
    files: list[Path] = list(args.log or [])
    if args.auto:
        print("Looking for logs on this machine...")
        for rec in sources.discover_logs(args.rotated):
            mark = {"ok": "FOUND  ", "denied": "DENIED ", "missing": "absent "}[rec["status"]]
            print(f"  {mark} {rec['path']:<34} {rec['what']}")
            if rec["status"] == "ok":
                files.append(Path(rec["path"]))
        denied = [r for r in sources.discover_logs(args.rotated) if r["status"] == "denied"]
        if denied:
            print("  -> Some logs exist but are not readable. Run this script with sudo (it only READS), "
                  "or add your user to the 'adm' group.")
        if not files and not (args.journal or args.windows):
            print("  -> No readable log files found. Try --journal (systemd) or --windows (Windows).")
    if not files and not (args.journal or args.windows or args.auto):
        files = sorted(p for p in SAMPLE_DIR.iterdir() if p.is_file())
        print(f"No source selected -> DEMO MODE on bundled sample logs in {SAMPLE_DIR.name}/ "
              f"(use --auto for this machine's real logs)")
    return files


def run_batch(args, cfg, color) -> int:
    now = datetime.now(LOCAL_TZ)
    files = resolve_files(args)
    events, lines, info = sources.collect_events(files, now) if files else ([], 0, [])
    if args.journal:
        ev2, n2, i2 = sources.read_journal(args.since, now)
        events += ev2
        lines += n2
        info += i2
    if args.windows:
        ev3, n3, i3 = sources.read_windows(now)
        events += ev3
        lines += n3
        info += i3
    events.sort(key=lambda e: e.ts)

    engine = Engine(cfg)
    for ev in events:
        engine.process(ev)

    meta = {"files": info, "lines": lines, "events": events, "settings": settings_text(args)}
    result = build_result(engine, meta, args.min_severity)
    print(format_console(result, color))
    paths = write_reports(result, args.output_dir)
    if result["stats"]["events"] == 0:
        return 1  # nothing was analysed: do not let cron/CI believe the host is clean
    print("\nReports written:")
    for kind, path in paths.items():
        print(f"  {kind.upper():<5} {path}")
    print()
    if args.fail_on and any(SEV_RANK[a.severity] >= SEV_RANK[args.fail_on] for a in result["alerts"]):
        return 2
    return 0


# --------------------------------------------------------------------------- #
class Notifier:
    """Prints live alerts, appends them to files and optionally POSTs them to a webhook."""

    def __init__(self, out_dir: Path, min_sev: str, webhook, color: bool):
        out_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl = out_dir / "live_alerts.jsonl"
        self.text = out_dir / "live_alerts.log"
        self.min_rank = SEV_RANK[min_sev]
        self.webhook, self.color = webhook, color

    def notify(self, alert):
        if SEV_RANK[alert.severity] < self.min_rank:
            return
        line = alert_line(alert, self.color)
        print(line, flush=True)
        with self.text.open("a", encoding="utf-8") as fh:
            fh.write(alert_line(alert, False) + "\n")
        with self.jsonl.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(alert.to_dict()) + "\n")
        if self.webhook:
            msg = f"[{alert.severity}] {alert.title}\n{alert.description}\nAction: {alert.recommendation}"
            threading.Thread(target=self._post, args=(msg,), daemon=True).start()

    def _post(self, msg: str):
        try:
            body = json.dumps({"text": msg, "content": msg}).encode()
            req = urllib.request.Request(self.webhook, data=body, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5).close()
        except Exception as exc:  # never let a webhook problem stop monitoring
            print(f"(webhook failed: {exc})", file=sys.stderr)


def run_follow(args, cfg, color) -> int:
    engine = Engine(cfg)
    notifier = Notifier(args.output_dir, args.min_severity, args.webhook, color)
    last_beat = [time.time()]

    def handle_event(ev):
        for alert in engine.process(ev):
            notifier.notify(alert)

    def on_line(line):
        ev = parse_line(line, datetime.now(LOCAL_TZ))
        if ev:
            handle_event(ev)

    def heartbeat():
        if time.time() - last_beat[0] >= 60:
            last_beat[0] = time.time()
            print(f"[status] watching... {engine.stats['events']} events, {len(engine.alerts)} alerts so far", flush=True)

    print(f"LIVE MONITORING (Ctrl+C to stop)  {settings_text(args)}")
    print(f"Alerts are also saved to {notifier.text} and {notifier.jsonl}\n")
    try:
        if args.windows:
            seen: set = set()
            while True:
                try:
                    for ev in sources.poll_windows(seen):
                        handle_event(ev)
                except OSError as exc:
                    print(f"ERROR: {exc}")
                    return 1
                heartbeat()
                time.sleep(10)
        elif args.journal:
            sources.follow_journal(on_line)
        else:
            files = resolve_files(args)
            files = [f for f in files if f.suffix.lower() not in (".xml", ".gz")]
            if not files:
                print("ERROR: nothing to follow. Use --log FILE, --auto, --journal or --windows.")
                return 1
            print("Following: " + ", ".join(str(f) for f in files))
            try:
                sources.follow_files(files, on_line, from_start=args.from_start, on_idle=heartbeat)
            except OSError as exc:
                print(f"ERROR: cannot read log: {exc}  (try sudo, read-only, or --journal)")
                return 1
    except KeyboardInterrupt:
        print(f"\nStopped. {engine.stats['events']} events processed, {len(engine.alerts)} alerts raised.")
    return 0


def main(argv=None) -> int:
    args = parse_args(argv)
    cfg = build_config(args)
    color = use_color(args)
    return run_follow(args, cfg, color) if args.follow else run_batch(args, cfg, color)


if __name__ == "__main__":
    raise SystemExit(main())
