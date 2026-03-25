---

# 🚀 STRIGOTH LOG INVESTIGATOR TUI

> **Hacker Edition** — Modern cyberpunk-themed terminal UI for investigating web server logs with focus on **security analysis, anomaly detection, and fast filtering** — fully offline and developer-friendly.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  🛡️  STRIGOTH LOG INVESTIGATOR  │  v0.2 Hacker Edition                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  A sleek, modern TUI built with Textual + Rich for analyzing nginx logs     ║
║  with real-time security alerts, interactive filtering, and statistics.     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## 🎯 Purpose

Reading raw log files manually is time-consuming and error-prone.
**Log Investigator TUI** helps you:

* 🔍 Inspect large log files efficiently with modern DataTable
* 🚨 Detect suspicious patterns (bruteforce, scanning, anomalies)
* 🎛️ Filter and analyze logs interactively with modal dialogs
* 💻 Work fully offline without heavy stack (ELK / SIEM)
* 🎨 Enjoy a beautiful cyberpunk-inspired dark theme

---

## 🚀 Quick Start

### Installation

```bash
pip install -r requirements.txt
```

### Run the Application

```bash
# Using Python module
python -m tui.app <path-to-access.log>

# Or using the run script
python run.py <path-to-access.log>

# Or on Windows
run.bat <path-to-access.log>
```

### Example with Sample Log

```bash
python -m tui.app sample_logs/access.log
```

---

## 🎨 Features (v0.3 - Hacker Edition)

### Core Capabilities

* ✅ Load large log files (stream-based)
* ✅ Parse structured fields (IP, timestamp, method, path, status, user-agent)
* ✅ Interactive DataTable viewer with sorting
* ✅ **Color-coded status codes** (2xx=green, 3xx=cyan, 4xx=yellow, 5xx=red)
* ✅ Multi-criteria filtering (status, IP, method, path, search)
* ✅ Rule-based anomaly detection
* ✅ Real-time statistics dashboard
* ✅ Security alerts panel
* ✅ Export investigation reports (Markdown/JSON)
* ✅ Terminal-only (TUI)

### Supported Logs

* ✅ Nginx `access.log` (default format)

---

## 🖥️ UI Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  Log Investigator TUI                           [Header]        │
├──────────┬──────────────────────────────┬───────────┬───────────┤
│ Filters  │  DataTable (Log Viewer)      │ Statistics│  Alerts   │
│──────────│──────────────────────────────│───────────┼───────────┤
│ No active│  Time    IP      Method Path │ Total: 82 │ 🔴 HIGH   │
│ filters  │  10:15   192...  GET    /    │ Unique: 45│ • Brute   │
│          │  10:15   10...   POST   /log │ 4xx: 15%  │ 🟡 MEDIUM │
│          │                              │ 5xx: 5%   │ • /admin  │
│          │                              │           │           │
├──────────┴──────────────────────────────┴───────────┴───────────┤
│  Showing 82 of 82 entries | Errors: 12 (14.6%) | Alerts: 3     │
│  q:Quit  f:Filter  c:Clear  /:Search  s:Stats  a:Alerts  e:Export│
└─────────────────────────────────────────────────────────────────┘
```

---

## ⌨️ Keyboard Shortcuts

| Key       | Action                    |
| --------- | ------------------------- |
| `j` / `k` | Scroll down / up          |
| `g`       | Go to top                 |
| `G`       | Go to bottom              |
| `f`       | Open filter panel         |
| `c`       | Clear filters             |
| `/`       | Quick search              |
| `s`       | Toggle statistics panel   |
| `a`       | Toggle alerts panel       |
| `r`       | Reload log file           |
| `e`       | Export report (markdown)  |
| `?`       | Show help                 |
| `q`       | Quit application          |
| `Enter`   | Select row                |
| `Escape`  | Close modal / Cancel      |

---

## 🧠 Security Detection Rules

Rules are **simple, transparent, and configurable**.

### Active Rules

| Rule | Severity | Description | Threshold |
|------|----------|-------------|-----------|
| `brute_force` | 🔴 High | Excessive 401 responses from single IP | 10 attempts/min |
| `sensitive_path` | 🟡 Medium | Access to sensitive paths | Any match |
| `scanning` | 🟡 Medium | Many unique paths from same IP | 20 paths/5min |
| `high_rate` | 🟢 Low | High request rate | 100 requests/min |

### Sensitive Paths (Default)

* `/admin`, `/wp-admin`, `/wp-login.php`
* `/phpmyadmin`, `/pma`
* `/.env`, `/.git`, `/.htaccess`
* `/config`, `/backup`
* `/wp-config.php`, `/xmlrpc.php`

---

## 📁 Project Structure

```
strigoth/
├── core/
│   ├── __init__.py
│   ├── models.py          # LogEntry dataclass
│   ├── loader.py          # Log file loading (stream/batch)
│   ├── stats.py           # Statistics aggregation engine
│   └── filter_engine.py   # Filter logic and state
├── parser/
│   ├── __init__.py
│   └── nginx.py           # Nginx log parser with regex
├── rules/
│   ├── __init__.py
│   └── security.py        # Security rule engine
├── export/
│   ├── __init__.py
│   └── report.py          # Markdown/JSON export
├── tui/
│   ├── __init__.py
│   ├── app.py             # Main Textual TUI application
│   └── app.tcss           # TUI stylesheets
├── sample_logs/
│   └── access.log         # Sample log for testing
├── requirements.txt
├── run.py                 # Python entry point
├── run.bat                # Windows batch script
└── README.md
```

---

## 🔎 Filter Engine

### Supported Filters

* **Status Code** - Exact match (e.g., `200`, `401`, `500`)
* **IP Address** - Substring match (e.g., `192.168`)
* **HTTP Method** - Exact match (e.g., `GET`, `POST`, `PUT`)
* **Path** - Substring match (e.g., `/admin`, `/api`)
* **Search** - Full-text search across entire log line

### Filter Modal

Press `f` to open the filter modal dialog with input fields for each filter type.
Multiple filters can be active simultaneously (AND logic).

---

## 📝 Export Report

Generate comprehensive investigation reports in Markdown format.

### Report Contents

* Summary statistics (total requests, unique IPs, error rates)
* Time range of analyzed logs
* Top IPs by request count
* Top paths by request count
* Applied filters
* Security alerts (grouped by severity)
* Status code distribution
* HTTP method breakdown
* Appendix with recent log entries

### Output Location

Reports are saved to `reports/` directory with timestamped filenames:

```
reports/access_log_report_20260324_143022.md
```

---

## 🧪 Testing with Sample Logs

The project includes a sample `access.log` with:

* ✅ Normal traffic patterns
* ✅ Brute force attack simulation (12 failed logins from 10.0.0.50)
* ✅ Sensitive path scanning (172.16.0.200 accessing /admin, /wp-admin, etc.)
* ✅ High-rate requests (10.0.0.100 with 25 rapid requests)
* ✅ Various HTTP status codes (2xx, 3xx, 4xx, 5xx)

---

## 🗺️ Roadmap

### ✅ Roadmap 1 — MVP (v0.1-v0.2) - COMPLETED

* [x] Nginx log parsing
* [x] DataTable-based log viewer
* [x] Filter engine with modal UI
* [x] Statistics dashboard
* [x] Security rule engine
* [x] Markdown export
* [x] Keyboard-driven navigation

### ✅ Roadmap 2 — Usability (v0.3) - IN PROGRESS

* [x] Color highlighting by status code
* [ ] Live log mode (`tail -f` style)
* [ ] Multi-log file support
* [ ] Improved navigation (page up/down)
* [ ] Custom rule configuration (YAML)

### 🔮 Roadmap 3 — Analysis (v0.4)

* [ ] Time-based aggregation charts
* [ ] Request rate visualization
* [ ] JSON export format
* [ ] Rule severity levels customization
* [ ] Alert deduplication

### 🔮 Roadmap 4 — Extensibility (v0.5)

* [ ] Apache log parser
* [ ] Custom log format support
* [ ] Plugin system for rules
* [ ] GeoIP lookup (offline DB)

### 🔮 Roadmap 5 — Advanced (v1.0)

* [ ] Session correlation
* [ ] Threat scoring
* [ ] CI-friendly CLI mode
* [ ] Docker container support

---

## 🛠️ Development

### Requirements

* Python 3.10+
* textual >= 0.48.0

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Tests

```bash
# Syntax check
python -m py_compile tui/app.py

# Import test
python -c "from tui.app import LogInvestigatorApp; print('OK')"
```

### Code Style

Follows PEP 8 guidelines with type hints throughout the codebase.

---

## 📌 Philosophy

* **Offline-first** - No external dependencies or API calls
* **Explainable rules** - No black-box AI, transparent detection logic
* **Keyboard-driven UX** - Efficient terminal navigation
* **Readable code > fancy UI** - Clean, maintainable Python

---

## 🏁 Status

✅ **v0.3 Complete** - Color Highlighting Added!

Core features implemented:
- Nginx parser with regex
- DataTable-based TUI viewer
- Filter engine with modal UI
- Statistics dashboard
- Security rule engine (4 rules)
- Markdown/JSON export
- Sample log file for testing
- **NEW**: Color-coded status codes (2xx=green, 3xx=cyan, 4xx=yellow, 5xx=red)

Next: Live log mode and multi-log support.

---

## 📄 License

MIT License - See LICENSE file for details.

---
