"""Turn engine results into console output and TXT / CSV / JSON / HTML reports."""
from __future__ import annotations

import csv
import html
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from .detectors import is_blockable
from .models import SEV_RANK, SEVERITIES

COLORS = {"CRITICAL": "1;97;41", "HIGH": "1;31", "MEDIUM": "33", "LOW": "36", "INFO": "37"}
HTML_COLORS = {"CRITICAL": "#b91c1c", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#0891b2", "INFO": "#6b7280"}
NETWORK_RULES = {"BRUTE_FORCE", "PASSWORD_SPRAY", "SUCCESS_AFTER_FAILURES", "SSH_SCAN", "PORT_SCAN", "BLOCKLISTED_IP",
                 "WEB_SQLI", "WEB_XSS", "WEB_TRAVERSAL", "WEB_CMDI", "WEB_LOG4SHELL", "WEB_SHELLSHOCK",
                 "WEB_SCANNER_UA", "WEB_BRUTE_FORCE", "WEB_SCANNING"}


def paint(text: str, sev: str, color: bool) -> str:
    return f"\033[{COLORS.get(sev, '0')}m{text}\033[0m" if color else text


def sort_alerts(alerts):
    return sorted(alerts, key=lambda a: (-SEV_RANK[a.severity], -a.count, a.first_seen))


def alert_line(alert, color=False) -> str:
    stamp = alert.last_seen.strftime("%H:%M:%S")
    tag = paint(f"[{alert.severity}]", alert.severity, color)
    return f"{stamp} {tag} {alert.title} - {alert.description} ({alert.rule}, {alert.mitre})"


def build_result(engine, meta: dict, min_severity: str = "LOW") -> dict:
    alerts = [a for a in engine.alerts.values() if SEV_RANK[a.severity] >= SEV_RANK[min_severity]]
    alerts = sort_alerts(alerts)
    top = alerts[0].severity if alerts else "NONE"
    return {"meta": meta, "stats": engine.stats, "alerts": alerts, "top_severity": top, "events": meta.get("events", [])}


def attackers(alerts) -> list[dict]:
    """Group alerts by source IP: which rules fired, worst severity, total evidence count."""
    by_ip = defaultdict(lambda: {"rules": set(), "sev": "INFO", "count": 0})
    for a in alerts:
        if a.ip:
            rec = by_ip[a.ip]
            rec["rules"].add(a.rule)
            rec["count"] += a.count
            if SEV_RANK[a.severity] > SEV_RANK[rec["sev"]]:
                rec["sev"] = a.severity
    rows = [{"ip": ip, **rec, "rules": sorted(rec["rules"])} for ip, rec in by_ip.items()]
    return sorted(rows, key=lambda r: (-SEV_RANK[r["sev"]], -len(r["rules"]), -r["count"]))


def block_commands(alerts) -> list[str]:
    ips = []
    for a in alerts:
        if a.ip and a.rule in NETWORK_RULES and SEV_RANK[a.severity] >= SEV_RANK["HIGH"] and is_blockable(a.ip) and a.ip not in ips:
            ips.append(a.ip)
    cmds = []
    for ip in ips:
        cmds.append(f"Linux (ufw):      sudo ufw deny from {ip}")
        cmds.append(f"Linux (iptables): sudo iptables -I INPUT -s {ip} -j DROP")
        cmds.append(f"Windows:          netsh advfirewall firewall add rule name=\"SLA block {ip}\" dir=in action=block remoteip={ip}")
    return cmds


def _top(counter: Counter, n=10):
    return counter.most_common(n)


# --------------------------------------------------------------------------- #
def format_console(result: dict, color: bool = False) -> str:
    m, s, alerts = result["meta"], result["stats"], result["alerts"]
    out = ["", paint("=== Security Log Analyzer ===", "INFO", color)]
    for f in m["files"]:
        status = f"ERROR: {f['error']}" if f["error"] else f"{f['lines']} lines, {f['events']} security events"
        out.append(f"  source: {f['path']}  ->  {status}")
    out.append(f"Events analysed: {s['events']}   Failed logins: {sum(s['fail_by_ip'].values()) + 0}   "
               f"Successful logins: {sum(s['ok_by_ip'].values())}   Web requests: {sum(s['web_by_ip'].values())}   "
               f"Firewall drops: {sum(s['fw_by_ip'].values())}")
    if s["events"] == 0:
        out.append(paint("\nWARNING: 0 security events were analysed (file missing, unreadable, empty, or unknown format).", "HIGH", color))
        out.append("'No alerts' does NOT mean 'safe' here - nothing was inspected. Check the source paths/permissions above.")
        return "\n".join(out)
    counts = Counter(a.severity for a in alerts)
    summary = "  ".join(f"{paint(sev, sev, color)}: {counts[sev]}" for sev in reversed(SEVERITIES) if counts[sev])
    out.append(f"\nALERTS ({len(alerts)})  {summary}" if alerts else "\nALERTS: none - no attack patterns crossed the thresholds.")
    for a in alerts:
        out.append(f"  {paint(f'[{a.severity}]', a.severity, color)} {a.title}")
        out.append(f"      {a.description}   [{a.rule} / {a.mitre}]")
    rows = attackers(alerts)
    if rows:
        out.append("\nATTACKER IPs (worst first)")
        for r in rows[:10]:
            out.append(f"  {paint(r['sev'], r['sev'], color):<8} {r['ip']:<40} {', '.join(r['rules'])}")
    cmds = block_commands(alerts)
    if cmds:
        out.append("\nSUGGESTED CONTAINMENT (review before running - never block your own/office IP)")
        out.extend("  " + c for c in cmds[:9])
        if len(cmds) > 9:
            out.append(f"  ... {len(cmds) - 9} more in the TXT report")
    return "\n".join(out)


def write_reports(result: dict, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    paths = {
        "txt": out_dir / f"security_report_{stamp}.txt",
        "csv": out_dir / f"security_events_{stamp}.csv",
        "json": out_dir / f"security_alerts_{stamp}.json",
        "html": out_dir / f"security_report_{stamp}.html",
    }
    m, s, alerts = result["meta"], result["stats"], result["alerts"]
    paths["txt"].write_text(_txt(result), encoding="utf-8")

    with paths["csv"].open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp", "kind", "service", "host", "user", "ip", "detail"])
        for ev in result["events"]:
            w.writerow([ev.ts.isoformat(timespec="seconds"), ev.kind, ev.service, ev.host, ev.user or "", ev.ip or "", ev.detail])

    payload = {
        "generated": datetime.now().astimezone().isoformat(timespec="seconds"),
        "sources": m["files"], "top_severity": result["top_severity"],
        "settings": m["settings"],
        "summary": {"events": s["events"], "failed_logins": sum(s["fail_by_ip"].values()),
                    "successful_logins": sum(s["ok_by_ip"].values())},
        "alerts": [a.to_dict() for a in alerts], "attackers": attackers(alerts),
        "suggested_commands": block_commands(alerts),
    }
    paths["json"].write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    paths["html"].write_text(_html(result), encoding="utf-8")
    return paths


def _txt(result: dict) -> str:
    m, s, alerts = result["meta"], result["stats"], result["alerts"]
    L = ["SECURITY LOG ANALYZER REPORT", "=" * 29,
         f"Generated : {datetime.now().astimezone().isoformat(timespec='seconds')}",
         f"Overall   : {result['top_severity']}",
         f"Settings  : {m['settings']}", "", "SOURCES", "-------"]
    L += [f"{f['path']}: {f['lines']} lines, {f['events']} events" + (f"  ERROR: {f['error']}" if f["error"] else "") for f in m["files"]]
    L += ["", "SUMMARY", "-------",
          f"Events analysed: {s['events']}", f"Failed logins: {sum(s['fail_by_ip'].values())}",
          f"Successful logins: {sum(s['ok_by_ip'].values())}", f"Web requests: {sum(s['web_by_ip'].values())}",
          f"Firewall drops: {sum(s['fw_by_ip'].values())}", "", f"ALERTS ({len(alerts)})", "------"]
    if not alerts:
        L.append("No attack patterns crossed the configured thresholds.")
    for i, a in enumerate(alerts, 1):
        L += [f"{i}. [{a.severity}] {a.title}", f"   Rule: {a.rule}   MITRE ATT&CK: {a.mitre}   Count: {a.count}",
              f"   First: {a.first_seen.isoformat(timespec='seconds')}   Last: {a.last_seen.isoformat(timespec='seconds')}",
              f"   What: {a.description}", f"   Do:   {a.recommendation}"]
        L += [f"   Evidence: {e}" for e in a.evidence[:3]]
        L.append("")
    rows = attackers(alerts)
    if rows:
        L += ["ATTACKER IPs", "------------"]
        L += [f"{r['sev']:<8} {r['ip']:<40} {', '.join(r['rules'])}" for r in rows]
        L.append("")
    for title, key in (("TOP FAILED LOGINS BY IP", "fail_by_ip"), ("TOP FAILED LOGINS BY USERNAME", "fail_by_user"),
                       ("SUCCESSFUL LOGINS BY IP", "ok_by_ip"), ("TOP WEB CLIENTS", "web_by_ip"), ("FIREWALL DROPS BY IP", "fw_by_ip")):
        if s[key]:
            L += [title, "-" * len(title)] + [f"{k}: {v}" for k, v in _top(s[key])] + [""]
    cmds = block_commands(alerts)
    if cmds:
        L += ["SUGGESTED CONTAINMENT (review before running; do not block your own or shared/NAT IPs)", "-" * 70] + cmds + [""]
    L += ["LIMITATIONS", "-----------",
          "- Detection is rule/threshold based on the logs provided; it cannot see attacks that are not logged.",
          "- An alert means 'investigate', not proof of compromise. VPN/NAT/proxy IPs can hide many users.",
          "- The tool never changes firewall rules or system settings; commands above are suggestions only."]
    return "\n".join(L) + "\n"


def _html(result: dict) -> str:
    e = html.escape
    m, s, alerts = result["meta"], result["stats"], result["alerts"]
    top = result["top_severity"]
    rows = "".join(
        f"<tr><td><span class='b' style='background:{HTML_COLORS[a.severity]}'>{a.severity}</span></td>"
        f"<td><b>{e(a.title)}</b><br><small>{e(a.description)}</small><br><small class='m'>{e(a.rule)} · {e(a.mitre)} · "
        f"{a.first_seen:%Y-%m-%d %H:%M:%S} → {a.last_seen:%H:%M:%S} · count {a.count}</small>"
        f"<details><summary>Evidence &amp; response</summary><pre>{e(chr(10).join(a.evidence[:3]))}</pre>"
        f"<p>{e(a.recommendation)}</p></details></td></tr>" for a in alerts
    ) or "<tr><td colspan=2>No attack patterns crossed the thresholds.</td></tr>"
    att = "".join(f"<tr><td>{e(r['ip'])}</td><td>{r['sev']}</td><td>{e(', '.join(r['rules']))}</td></tr>" for r in attackers(alerts))
    cmds = e("\n".join(block_commands(alerts)))
    cards = "".join(f"<div class='c'><b>{v}</b><span>{k}</span></div>" for k, v in (
        ("events", s["events"]), ("failed logins", sum(s["fail_by_ip"].values())),
        ("successful logins", sum(s["ok_by_ip"].values())), ("alerts", len(alerts))))
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Security Report</title>
<style>body{{font-family:system-ui,sans-serif;margin:2rem auto;max-width:960px;padding:0 1rem;color:#111}}
.c{{display:inline-block;margin:0 1rem 1rem 0;padding:.8rem 1.2rem;border:1px solid #ddd;border-radius:8px}}
.c b{{display:block;font-size:1.6rem}} table{{border-collapse:collapse;width:100%;margin-bottom:1.5rem}}
td{{border-top:1px solid #eee;padding:.5rem;vertical-align:top}} .b{{color:#fff;padding:.15rem .5rem;border-radius:4px;font-size:.75rem}}
.m{{color:#666}} pre{{background:#f5f5f5;padding:.6rem;overflow:auto;white-space:pre-wrap}}</style></head><body>
<h1>Security Log Analyzer</h1><p>Overall: <b style="color:{HTML_COLORS.get(top, '#16a34a')}">{top}</b> · generated {datetime.now():%Y-%m-%d %H:%M:%S}</p>
{cards}<h2>Alerts</h2><table>{rows}</table>
<h2>Attacker IPs</h2><table>{att or '<tr><td>none</td></tr>'}</table>
<h2>Suggested containment (review first)</h2><pre>{cmds or 'none'}</pre>
<p><small>Alerts mean "investigate", not proof of compromise. This tool never changes your firewall.</small></p></body></html>"""
