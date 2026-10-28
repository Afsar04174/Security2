# Security Log Analyzer — Web Dashboard

This dashboard is connected to the project's **actual Python parsers and detection engine**. It does not use fabricated alert rows for its results.

## Run on Windows (VS Code)

1. Extract the project ZIP.
2. Open the `security_log_analyzer_real` folder in VS Code.
3. Make sure Python 3.10+ is installed.
4. Open the VS Code terminal in this folder.
5. Run:

   ```powershell
   python web_app.py
   ```

6. Open **http://127.0.0.1:8000** in Chrome or Edge.
7. The dashboard automatically analyzes the bundled `sample_logs` files. Use **Analyze log file** to upload a `.log`, `.txt`, `.csv`, `.xml`, or `.gz` file.
8. Use the alert search/filter and export buttons to inspect or save results.

No Flask, Node.js, API key, or extra Python package is required. Stop the server with `Ctrl+C` in the terminal.

## What is connected?

- Uses `sla.parsers`, `sla.sources`, and `sla.detectors.Engine` from this project.
- Shows the actual event count, parsed event types, unique source IPs, and alert severities.
- Alert details include rule name, severity, source IP, account when available, first/last seen, evidence, MITRE ATT&CK mapping, and recommended next steps.
- Uploaded files are analyzed locally and the temporary upload is deleted after analysis.
- Exports current results as CSV, JSON, or TXT from the browser.

## Important safety notes

- This server binds to `127.0.0.1` only; it is intended for the local computer, not public internet exposure.
- Upload only logs you own or are authorized to analyze. Maximum upload size is 5 MB.
- The app does not automatically monitor new log entries, block IP addresses, or change host settings. It performs a batch analysis when opened or when you upload a file.
- Alerts are rule-based indicators, not proof that an attack succeeded. Review evidence before responding.
- To analyze real protected system logs, use the command-line options documented in `README.md` with appropriate permissions. This browser dashboard currently accepts an uploaded file or runs the bundled sample logs.
