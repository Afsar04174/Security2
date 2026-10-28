#!/usr/bin/env python3
"""Local web dashboard for Security Log Analyzer. Uses only Python stdlib."""
from __future__ import annotations
import gzip
import io
import json
import os
import tempfile
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from sla import sources
from sla.detectors import Config, Engine
from sla.models import SEV_RANK
from sla.parsers import LOCAL_TZ

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_DIR = BASE_DIR / "sample_logs"
MAX_UPLOAD = 5 * 1024 * 1024
MAX_DECOMPRESSED = 25 * 1024 * 1024  # guards against gzip bombs
PUBLIC_FILES = {"/index.html", "/app.js", "/style.css"}


def analyze_paths(paths, source_names=None):
    now = datetime.now(LOCAL_TZ)
    events, line_count, info = sources.collect_events(paths, now)
    engine = Engine(Config())
    for event in events:
        engine.process(event)
    alerts = sorted(engine.alerts.values(), key=lambda a: (-SEV_RANK[a.severity], -a.count, a.first_seen))
    kinds = dict(engine.stats["by_kind"])
    severity_counts = {sev: sum(1 for a in alerts if a.severity == sev) for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    serialized_alerts = []
    for idx, alert in enumerate(alerts, 1):
        d = alert.to_dict()
        d["id"] = idx
        d["time"] = alert.last_seen.strftime("%H:%M:%S")
        d["source_ip"] = alert.ip or "—"
        serialized_alerts.append(d)
    serialized_events = []
    for event in sorted(events, key=lambda e: e.ts, reverse=True)[:250]:
        serialized_events.append({
            "time": event.ts.strftime("%Y-%m-%d %H:%M:%S"),
            "type": event.kind,
            "message": event.detail or event.raw or "Security event",
            "source": event.service or "log",
            "ip": event.ip or "—",
            "user": event.user or "—",
            "result": "Failed" if event.kind in ("AUTH_FAIL", "INVALID_USER", "SUDO_FAIL") else ("Blocked" if event.kind == "FW_BLOCK" else "Observed"),
        })
    source_info = [{"path": Path(x["path"]).name, "lines": x["lines"], "events": x["events"], "error": x["error"]} for x in info]
    failed = sum(engine.stats["fail_by_ip"].values())
    success = sum(engine.stats["ok_by_ip"].values())
    unique_ips = len({e.ip for e in events if e.ip})
    return {
        "generated": datetime.now().astimezone().isoformat(timespec="seconds"),
        "mode": "python-analyzer",
        "summary": {"events": engine.stats["events"], "lines": line_count, "alerts": len(alerts), "critical": severity_counts["CRITICAL"], "high": severity_counts["HIGH"], "medium": severity_counts["MEDIUM"], "low": severity_counts["LOW"], "failed_logins": failed, "successful_logins": success, "unique_ips": unique_ips},
        "severity_counts": severity_counts,
        "event_types": kinds,
        "alerts": serialized_alerts,
        "events": serialized_events,
        "sources": source_info,
        "note": "Findings are rule-based indicators. Validate evidence before taking action; this tool does not block traffic or change system settings."
    }


def json_bytes(payload):
    return json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
        super().end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/analyze":
            files = sorted(p for p in SAMPLE_DIR.iterdir() if p.is_file())
            self._send_json(analyze_paths(files))
            return
        if path == "/health":
            self._send_json({"status": "ok"})
            return
        if path == "/":
            self.path = "/index.html"
        elif path.startswith("/api/") or path not in PUBLIC_FILES:
            self._send_json({"error": "Not found"}, 404)
            return
        super().do_GET()

    def do_POST(self):
        if urlparse(self.path).path != "/api/analyze":
            self._send_json({"error": "Unknown API endpoint"}, 404)
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            content_length = -1
        if content_length <= 0:
            self._send_json({"error": "Missing or invalid Content-Length."}, 400)
            return
        if content_length > MAX_UPLOAD + 1024 * 1024:
            self._send_json({"error": "Upload too large. Maximum file size is 5 MB."}, 413)
            return
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self._send_json({"error": "Choose a .log, .txt, .csv, or .xml file to analyze."}, 400)
            return
        body = self.rfile.read(content_length)
        # Parse multipart safely with the standard-library email parser.
        from email.parser import BytesParser
        from email.policy import default
        message = BytesParser(policy=default).parsebytes(
            (f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n").encode() + body
        )
        upload = None
        filename = "uploaded.log"
        if message.is_multipart():
            for part in message.iter_parts():
                if part.get_param("name", header="content-disposition") == "file":
                    upload = part.get_payload(decode=True) or b""
                    filename = Path(part.get_filename() or "uploaded.log").name
                    break
        if upload is None:
            self._send_json({"error": "No file was received. Select a log file and try again."}, 400)
            return
        if len(upload) > MAX_UPLOAD:
            self._send_json({"error": "Upload too large. Maximum file size is 5 MB."}, 413)
            return
        suffix = Path(filename).suffix.lower()
        if suffix not in (".log", ".txt", ".csv", ".xml", ".gz"):
            self._send_json({"error": "Unsupported file type. Use .log, .txt, .csv, .xml, or .gz."}, 400)
            return
        if suffix == ".gz":
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(upload)) as gz:
                    upload = gz.read(MAX_DECOMPRESSED + 1)
            except (OSError, EOFError):
                self._send_json({"error": "Invalid or corrupt .gz file."}, 400)
                return
            if len(upload) > MAX_DECOMPRESSED:
                self._send_json({"error": "Decompressed file is too large (max 25 MB)."}, 413)
                return
            suffix = ".log"
        if suffix == ".xml" and (b"<!DOCTYPE" in upload[:4096].upper() or b"<!ENTITY" in upload.upper()):
            self._send_json({"error": "XML with DOCTYPE/ENTITY declarations is not accepted."}, 400)
            return
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(prefix="sla_upload_", suffix=suffix, delete=False) as fh:
                fh.write(upload)
                temp_path = Path(fh.name)
            result = analyze_paths([temp_path])
            result["sources"][0]["path"] = filename
            result["uploaded_filename"] = filename
            self._send_json(result)
        except Exception as exc:
            print(f"[web] analysis error: {exc!r}")
            self._send_json({"error": "Could not analyze this file. Check that it is a supported log format."}, 400)
        finally:
            if temp_path:
                try: temp_path.unlink(missing_ok=True)
                except OSError: pass

    def _send_json(self, payload, status=200):
        raw = json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *args):
        print("[web] " + (fmt % args))


def main():
    port = int(os.environ.get("PORT", "8000"))
    # Hosting platforms set PORT and need 0.0.0.0; locally we stay on 127.0.0.1.
    host = os.environ.get("HOST") or ("0.0.0.0" if "PORT" in os.environ else "127.0.0.1")
    server = ThreadingHTTPServer((host, port), Handler)
    print("\nSecurity Log Analyzer dashboard is ready")
    print(f"Open: http://{host}:{port}")
    print("Uses the actual Python detection engine on bundled sample logs or uploaded files.")
    print("Press Ctrl+C to stop. Locally it binds to 127.0.0.1; on a host it uses $PORT on 0.0.0.0.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
