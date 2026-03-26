# 🚀 STRIGOTH LOG INVESTIGATOR

> Modern terminal UI for investigating web server logs with focus on **security analysis, anomaly detection, and fast filtering** — fully offline and developer-friendly.

**Version:** v1.0

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

## 🎨 Features (v0.7)

### Core Capabilities

* ✅ Load large log files (stream-based)
* ✅ Parse structured fields (IP, timestamp, method, path, status, user-agent)
* ✅ Interactive DataTable viewer with sorting
* ✅ **Color-coded status codes** (2xx=green, 3xx=cyan, 4xx=yellow, 5xx=red)
* ✅ Multi-criteria filtering (status, IP, method, path, search)
* ✅ Rule-based anomaly detection
* ✅ Real-time statistics dashboard
* ✅ Security alerts panel
* ✅ Export investigation reports (**Markdown & JSON**)
* ✅ **Live log mode** (`tail -f` style) - Real-time monitoring
* ✅ **Time-based charts** - Traffic visualization with sparklines
* ✅ **Custom YAML configuration** - Customize rules without coding
* ✅ Terminal-only (TUI)

### Supported Logs

* ✅ Nginx `access.log` (default format)

---

## 🖥️ UI Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  STRIGOTH LOG INVESTIGATOR v1.0                [Header]         │
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
| `t`       | Show charts view          |
| `l`       | Toggle live mode (tail -f)|
| `o`       | Open/reload config (YAML) |
| `r`       | Reload log file           |
| `e`       | Export report (MD/JSON)   |
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

Generate comprehensive investigation reports in **Markdown** or **JSON** format.

### Export Formats

**Markdown (.md):**
- Human-readable report
- Formatted with headers, tables, and lists
- Perfect for documentation and sharing

**JSON (.json):**
- Machine-readable format
- Easy integration with other tools
- Structured data for automation

### Export Options

Press `e` to open export dialog and choose:
- 📄 **Markdown** - Standard text report
- 📋 **JSON** - Structured data format
- **Both** - Export both formats simultaneously

### Report Contents

* Summary statistics (total requests, unique IPs, error rates)
* Time range of analyzed logs
* Top IPs by request count
* Top paths by request count
* Applied filters
* Security alerts (grouped by severity)
* Status code distribution
* HTTP method breakdown
* Recent log entries (last 20)

### Output Location

Reports are saved to `reports/` directory with timestamped filenames:

```
reports/access_log_report_20260326_143022.md
reports/access_log_report_20260326_143022.json
```

### Example JSON Output

```json
{
  "generated_at": "2026-03-26T10:30:00",
  "version": "v0.7",
  "summary": {
    "Total Requests": "1,234",
    "Unique IPs": "45",
    "Error Rate": "14.6%"
  },
  "alerts_summary": {
    "total": 15,
    "high": 3,
    "medium": 7,
    "low": 5
  },
  "top_ips": [
    {"ip": "10.0.0.50", "count": 12},
    {"ip": "192.168.1.100", "count": 8}
  ],
  "status_codes": {
    "2xx": 750,
    "3xx": 50,
    "4xx": 300,
    "5xx": 134
  }
}
```

---

## ⚙️ YAML Configuration

Customize security rules and detection thresholds without modifying code.

### Quick Start

1. Edit `config.yaml` in the project root
2. Save changes
3. Press `o` in the app to reload config (or restart)

### Configuration Options

```yaml
rules:
  # Brute Force Detection
  brute_force:
    enabled: true           # Enable/disable rule
    threshold: 10           # Failed attempts to trigger
    time_window: 60         # Time window (seconds)
  
  # Sensitive Path Detection  
  sensitive_path:
    enabled: true
    paths:                  # Custom paths list
      - /admin
      - /wp-admin
      - /.env
      - /custom-path        # Add your own
  
  # Scanning Detection
  scanning:
    enabled: true
    threshold: 20           # Unique paths to trigger
    time_window: 300        # Time window (5 min)
  
  # High Request Rate
  high_rate:
    enabled: true
    threshold: 100          # Requests to trigger
    time_window: 60         # Time window (1 min)
```

### Examples

**Disable brute force detection:**
```yaml
brute_force:
  enabled: false
```

**Add custom sensitive paths:**
```yaml
sensitive_path:
  paths:
    - /admin
    - /my-secret-path
    - /internal-api
```

**Make scanning detection stricter:**
```yaml
scanning:
  threshold: 10      # Alert after 10 paths (default: 20)
  time_window: 60    # Within 1 minute (default: 300)
```

**Make brute force more sensitive:**
```yaml
brute_force:
  threshold: 5       # Alert after 5 attempts (default: 10)
  time_window: 120   # Within 2 minutes (default: 60)
```

### Config File Location

```
strigoth/
├── config.yaml          ← Edit this file
├── tui/
├── core/
└── ...
```

Press **`o`** in the app to view config file path and reload.

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

### ✅ v0.7 - COMPLETED

* [x] Nginx log parsing
* [x] DataTable-based log viewer
* [x] Filter engine with modal UI
* [x] Statistics dashboard
* [x] Security rule engine
* [x] **Markdown & JSON export**
* [x] Keyboard-driven navigation
* [x] Color-coded status codes
* [x] **Live log mode** (`tail -f` style)
* [x] **Time-based charts** - Traffic visualization
* [x] **Custom YAML configuration**

### 🔮 Future Releases

* [ ] Multi-log file support
* [ ] Request rate visualization
* [ ] Apache log parser
* [ ] GeoIP lookup

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

✅ **v0.7 Complete** - YAML Configuration Added!

Core features implemented:
- Nginx parser with regex
- DataTable-based TUI viewer
- Filter engine with modal UI
- Statistics dashboard
- Security rule engine (4 rules)
- **Markdown & JSON export** with format selection dialog
- Sample log file for testing
- Color-coded status codes (2xx=green, 3xx=cyan, 4xx=yellow, 5xx=red)
- Live log mode (`tail -f` style) with auto-refresh
- Time-based charts with hourly traffic & error rate sparklines
- **NEW**: Custom YAML configuration for rules customization

Next: Multi-log support and request rate visualization.

---

## 📄 License

MIT License - See LICENSE file for details.

---
