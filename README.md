# 🧛‍♂️ _STRIGOTH_ 🦇

> **Strigoth** derives its name from the **Strigoi**—the troubled, powerful vampires of Romanian mythology. Just as a **Strigoi** rises from the dark with supernatural senses to roam the night, Strigoth rises within your terminal to hunt through the dark, chaotic depths of system logs.!
>
>> Modern terminal UI for investigating web server logs with focus on **security analysis, anomaly detection, and fast filtering** — fully offline and developer-friendly.

---

## 🎯 Purpose

Reading raw log files manually is time-consuming and error-prone.
**Log Investigator TUI** helps you:

* 🔍 Inspect large log files efficiently with modern DataTable
* 🚨 Detect suspicious patterns (bruteforce, scanning, anomalies)
* 🎛️ Filter and analyze logs interactively with modal dialogs
* 💻 Work fully offline without heavy stack (ELK / SIEM)

---

## 🎬 Demo & Showcase

### **See Strigoth in Action!**

![Strigoth Demo](media/media.gif)

**Features shown in demo:**
- 📊 Interactive DataTable with color-coded status codes
- 🔍 Real-time filtering with modal dialog
- 📈 Live statistics dashboard
- 🚨 Security alerts detection
- ⌨️ Keyboard-driven navigation
- 📋 Export reports (Markdown/JSON)

**Try it yourself:**
```bash
python -m tui.app sample_logs/access.log
```

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

## 🎨 Features

### Core Capabilities

* ✅ Load large log files (stream-based)
* ✅ **Multi-log file support** - Load & merge multiple log files
* ✅ **Auto-detect log format** (Nginx or Apache)
* ✅ Parse structured fields (IP, timestamp, method, path, status, user-agent)
* ✅ Interactive DataTable viewer with sorting
* ✅ **Color-coded status codes** (2xx=green, 3xx=red, 4xx=yellow, 5xx=purple)
* ✅ Multi-criteria filtering (status, IP, method, path, search, **source**)
* ✅ Rule-based anomaly detection
* ✅ Real-time statistics dashboard
* ✅ Security alerts panel
* ✅ Export investigation reports (**Markdown & JSON**)
* ✅ **Live log mode** (`tail -f` style) - Real-time monitoring
* ✅ **Time-based charts** - Traffic visualization with sparklines
* ✅ **Request rate visualization** - Requests per minute with spike detection
* ✅ **Custom YAML configuration** - Customize rules without coding
* ✅ Terminal-only (TUI)

### Supported Logs

* ✅ Nginx `access.log` (default format)
* ✅ Apache `access.log` (Combined & Common formats)
* ✅ **Auto-detection** - No manual format selection needed

---

## 🖥️ UI Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  STRIGOTH LOG INVESTIGATOR v1.0.0              [Header]         │
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
│   ├── config.py          # Configuration loader for YAML-based rule customization.
│   ├── stats.py           # Statistics aggregation engine
│   └── filter_engine.py   # Filter logic and state
├── parser/
│   ├── __init__.py
│   └── nginx.py           # Nginx log parser with regex
│   └── apache.py          # Apache log parser with regex
│   └── detector.py        # Log parser with regex auto-detection
├── rules/
│   ├── __init__.py
│   └── security.py        # Security rule engine
├── reports/               # Generated Folder For Report File
├── export/
│   ├── __init__.py
│   └── report.py          # Markdown/JSON export
├── tui/
│   ├── modals/            # Modals Textual TUI
│   ├── __init__.py
│   ├── app.py             # Main Textual TUI application
│   └── app.tcss           # TUI stylesheets
├── sample_logs/
│   └── access.log         # Sample log for testing
├── requirements.txt
├── run.py                 # Python entry point
├── run.bat                # Windows batch script
├── config.yaml            # Configure YAML File
└── README.md
```

---

## 🔎 Filter Engine

### Supported Filters

* **Status Code** - Exact match (e.g., `200`, `401`, `500`)
* **IP Address** - Substring match (e.g., `192.168`)
* **HTTP Method** - Exact match (e.g., `GET`, `POST`, `PUT`)
* **Path** - Substring match (e.g., `/admin`, `/api`)
* **Source** - Substring match (e.g., `access`, `server2`) - **NEW in v0.8!**
* **Search** - Full-text search across entire log line

### Filter Modal

Press `f` to open the filter modal dialog with input fields for each filter type.
Multiple filters can be active simultaneously (AND logic).

### Multi-Log Filter Example

When loading multiple log files:

```bash
python -m tui.app server1.log server2.log server3.log
```

1. Press `f` to open filter
2. Enter `server2` in **Source** field
3. Press Enter or click **APPLY**
4. Only logs from `server2.log` are displayed

Clear filters by pressing `f` and clicking **CLEAR**.

---

## 📂 Multi-Log Support

Load and analyze multiple log files simultaneously with automatic merging and source tracking.

### Usage

```bash
# Load multiple log files
python -m tui.app server1.log server2.log server3.log

# Mix of access logs from different servers
python -m tui.app /var/log/nginx/server1.log /var/log/nginx/server2.log
```

### Features

* **Auto-merge** - Logs from all files are merged and sorted by timestamp
* **Source column** - Automatically shown when loading >1 file
* **Source tracking** - Each entry knows which file it came from
* **Filter by source** - Filter to show only logs from specific file
* **Per-source stats** - Statistics breakdown per loaded file

### DataTable Layout

**Single file** (no source column):
```
┌────────────────────────────────────────────────────────┐
│ Time    IP Address    Method  Path      Status  Size  │
├────────────────────────────────────────────────────────┤
│ 10:15   192.168.1.1   GET     /         200     5,432 │
└────────────────────────────────────────────────────────┘
```

**Multiple files** (with source column):
```
┌──────────────────────────────────────────────────────────────────┐
│ Time    Source      IP Address    Method  Path    Status  Size  │
├──────────────────────────────────────────────────────────────────┤
│ 10:15   server1     192.168.1.1   GET     /       200     5,432 │
│ 10:16   server2     10.0.0.50     POST    /login  401     123   │
│ 10:17   server3     172.16.0.1    GET     /api    200     8,765 │
└──────────────────────────────────────────────────────────────────┘
```

### Sample Log Files

The project includes sample logs for testing multi-log support:

* `sample_logs/access.log` - Server 1 (81 entries, 10:15-10:16)
* `sample_logs/server2.log` - Server 2 (40 entries, 11:00-11:00)
* `sample_logs/server3.log` - Server 3 (40 entries, 12:00-12:00)

Test multi-log with:
```bash
python -m tui.app sample_logs/access.log sample_logs/server2.log sample_logs/server3.log
```

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

## Status

### COMPLETED

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
* [x] **Multi-log file support** - Load & merge multiple files
* [x] **Apache log parser** - Auto-detect format
* [x] **Request rate visualization** - Requests per minute with spike detection
* [x] **PEP 8 compliant** code with comprehensive type hints
* [x] **Textual theme colors** (no hardcoded hex colors) 
* [x] **Row Detail Inspector**  Allow users to inspect **full log entry details** by selecting a row
    in the DataTable and pressing `Enter`, opening a **read-only modal view**.

### 🔮 Future Releases

* [ ] GeoIP lookup
* [ ] .PDF Convert Report
* [ ] Saved Filter Presets
* [ ] Mark / Bookmark Suspicious Entries
* [ ] Investigation Session Metadata
* [ ] Time Window Slider / Picker
* [ ] Rule Hit Heatmap (Text-based)
* [ ] IP Reputation Heuristic (Offline)
* [ ] Session Correlation (IP + UA + time window)

---

## 🛠️ Development

### Requirements

* Python 3.10+
* textual >= 0.48.0
* textual-dev>=1.0.0
* pyyaml>=6.0

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

## 📄 License

MIT License - See LICENSE file for details.

---
