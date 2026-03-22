"""
developer_tools.py
==================
Developer and admin tools for the Cyber Toolkit.

Functions:
  Scripting:
    - run_python_snippet(code, timeout)     → run Python code in subprocess, return stdout/stderr
    - run_powershell_snippet(code, timeout) → run PowerShell code in subprocess, return stdout/stderr

  Task Automation:
    - get_scheduled_tasks()                 → full schtasks dump, all tasks
    - set_scheduled_task(name, action)      → enable / disable / run a named task
    - get_script_manager_scripts()          → load saved scripts from JSON store
    - save_script(name, language, code)     → save a named script to JSON store
    - delete_script(name)                   → delete a saved script from JSON store
    - run_saved_script(name)                → run a saved script, store last output

  Logs:
    - get_event_log(log_name, max_events, level_filter)  → Windows Event Log via wevtutil
    - get_app_log(log_path, max_lines, search)           → read app/Flask log file
    - list_app_logs(log_dir)                             → list available log files
"""

# ─────────────────────────────────────────────
# Imports
# ─────────────────────────────────────────────

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

# Where named scripts are stored
SCRIPT_STORE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cache", "scripts.json")

# Where app logs live (Flask will write here if configured)
DEFAULT_LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs")


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 30, input_text: str | None = None) -> dict:
    """Run a subprocess and return structured stdout/stderr/returncode."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "error": None,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "", "returncode": -1, "error": f"Timed out after {timeout}s"}
    except FileNotFoundError as e:
        return {"stdout": "", "stderr": "", "returncode": -1, "error": f"Command not found: {e}"}
    except Exception as e:
        return {"stdout": "", "stderr": "", "returncode": -1, "error": str(e)}


def _load_script_store() -> dict:
    """Load the script store JSON. Returns empty store if missing or corrupt."""
    try:
        if os.path.exists(SCRIPT_STORE_PATH):
            with open(SCRIPT_STORE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except (json.JSONDecodeError, OSError):
        pass
    return {"scripts": {}}


def _save_script_store(store: dict) -> None:
    """Persist the script store JSON to disk."""
    os.makedirs(os.path.dirname(SCRIPT_STORE_PATH), exist_ok=True)
    with open(SCRIPT_STORE_PATH, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2)


# ─────────────────────────────────────────────
# 1. Python Snippet Runner
# ─────────────────────────────────────────────

def run_python_snippet(code: str, timeout: int = 10) -> dict:
    """
    Execute a Python code snippet in an isolated subprocess using the same
    Python interpreter as the app. Captures stdout and stderr separately.

    The code runs in a temporary file to support multi-line scripts.
    Timeout is enforced — long-running code is killed cleanly.

    Returns:
      {
        "stdout": str,
        "stderr": str,
        "returncode": int,
        "elapsed_ms": int,
        "error": str | None,
        "timestamp": str
      }
    """
    result = {
        "stdout": "",
        "stderr": "",
        "returncode": -1,
        "elapsed_ms": 0,
        "error": None,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "language": "python",
        "code": code,
    }

    if not code or not code.strip():
        result["error"] = "No code provided."
        return result

    # Write to a temp file so multi-line / indented code works correctly
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(code)
            tmp_path = tmp.name
    except Exception as e:
        result["error"] = f"Failed to write temp file: {e}"
        return result

    try:
        t0 = time.time()
        raw = _run([sys.executable, tmp_path], timeout=timeout)
        result["elapsed_ms"] = int((time.time() - t0) * 1000)
        result["stdout"]     = raw["stdout"]
        result["stderr"]     = raw["stderr"]
        result["returncode"] = raw["returncode"]
        result["error"]      = raw["error"]
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return result


# ─────────────────────────────────────────────
# 2. PowerShell Snippet Runner
# ─────────────────────────────────────────────

def run_powershell_snippet(code: str, timeout: int = 15) -> dict:
    """
    Execute a PowerShell code snippet via powershell.exe.
    Uses -NonInteractive -NoProfile for clean, fast execution.
    ExecutionPolicy is set to Bypass for the session only.

    Returns same structure as run_python_snippet.
    """
    result = {
        "stdout": "",
        "stderr": "",
        "returncode": -1,
        "elapsed_ms": 0,
        "error": None,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "language": "powershell",
        "code": code,
    }

    if not code or not code.strip():
        result["error"] = "No code provided."
        return result

    # Write to a .ps1 temp file
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ps1", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(code)
            tmp_path = tmp.name
    except Exception as e:
        result["error"] = f"Failed to write temp file: {e}"
        return result

    try:
        t0 = time.time()
        raw = _run(
            [
                "powershell.exe",
                "-NonInteractive",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", tmp_path,
            ],
            timeout=timeout,
        )
        result["elapsed_ms"] = int((time.time() - t0) * 1000)
        result["stdout"]     = raw["stdout"]
        result["stderr"]     = raw["stderr"]
        result["returncode"] = raw["returncode"]
        result["error"]      = raw["error"]
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return result


# ─────────────────────────────────────────────
# 3. Scheduled Tasks Inspector
# ─────────────────────────────────────────────

def get_scheduled_tasks() -> dict:
    """
    Returns all scheduled tasks (including Microsoft built-in tasks)
    parsed from schtasks /query /fo CSV /v output.

    Returns:
      {
        "tasks": [ { TaskName, Status, Next Run Time, Last Run Time,
                     Run As User, Task To Run, Scheduled Task State, ... } ],
        "count": int,
        "errors": []
      }
    """
    result = {"tasks": [], "count": 0, "errors": []}

    raw = _run(["schtasks", "/query", "/fo", "CSV", "/v"], timeout=30)

    if raw["error"]:
        result["errors"].append(raw["error"])
        return result

    if not raw["stdout"]:
        result["errors"].append("schtasks returned no output.")
        return result

    lines = raw["stdout"].splitlines()
    if not lines:
        return result

    # Parse CSV — first line is headers, may repeat on each page
    want = {
        "TaskName", "Status", "Next Run Time", "Last Run Time",
        "Run As User", "Task To Run", "Scheduled Task State",
        "Schedule Type", "Start Time", "Comment",
    }

    headers = [h.strip('"') for h in lines[0].split('","')]
    idx = {h: i for i, h in enumerate(headers) if h in want}

    seen_tasks = set()
    for line in lines[1:]:
        cols = [c.strip('"') for c in line.split('","')]
        if len(cols) < len(headers):
            continue

        task_name = cols[idx.get("TaskName", 0)] if "TaskName" in idx else ""

        # Skip repeated header rows
        if task_name.lower() in ("taskname", "task name", ""):
            continue

        # Deduplicate (schtasks repeats rows for multiple triggers)
        if task_name in seen_tasks:
            continue
        seen_tasks.add(task_name)

        task = {k: cols[v] for k, v in idx.items() if v < len(cols)}
        result["tasks"].append(task)

    result["count"] = len(result["tasks"])
    return result


def set_scheduled_task(name: str, action: str) -> dict:
    """
    Perform an action on a named scheduled task.

    action: "enable" | "disable" | "run"

    Returns:
      { "success": bool, "output": str, "error": str | None }
    """
    result = {"success": False, "output": "", "error": None}

    if not name:
        result["error"] = "No task name provided."
        return result

    if action == "run":
        raw = _run(["schtasks", "/run", "/tn", name], timeout=10)
    elif action == "enable":
        raw = _run(["schtasks", "/change", "/tn", name, "/enable"], timeout=10)
    elif action == "disable":
        raw = _run(["schtasks", "/change", "/tn", name, "/disable"], timeout=10)
    else:
        result["error"] = f"Unknown action: {action}"
        return result

    result["output"]  = (raw["stdout"] + raw["stderr"]).strip()
    result["success"] = raw["returncode"] == 0
    result["error"]   = raw["error"]
    return result


# ─────────────────────────────────────────────
# 4. Script Manager
# ─────────────────────────────────────────────

def get_script_manager_scripts() -> dict:
    """
    Load all saved scripts from the local JSON store.

    Returns:
      {
        "scripts": {
          "script_name": {
            "language": "python" | "powershell",
            "code": str,
            "created_at": str,
            "last_run_at": str | None,
            "last_output": { stdout, stderr, returncode, elapsed_ms } | None
          }
        }
      }
    """
    return _load_script_store()


def save_script(name: str, language: str, code: str) -> dict:
    """
    Save or update a named script in the local JSON store.

    language: "python" | "powershell"

    Returns:
      { "success": bool, "error": str | None }
    """
    result = {"success": False, "error": None}

    name = name.strip()
    if not name:
        result["error"] = "Script name cannot be empty."
        return result

    if language not in ("python", "powershell"):
        result["error"] = f"Unsupported language: {language}. Use 'python' or 'powershell'."
        return result

    if not code or not code.strip():
        result["error"] = "Script code cannot be empty."
        return result

    store = _load_script_store()
    existing = store["scripts"].get(name, {})

    store["scripts"][name] = {
        "language":    language,
        "code":        code,
        "created_at":  existing.get("created_at") or datetime.now().isoformat(timespec="seconds"),
        "updated_at":  datetime.now().isoformat(timespec="seconds"),
        "last_run_at": existing.get("last_run_at"),
        "last_output": existing.get("last_output"),
    }

    try:
        _save_script_store(store)
        result["success"] = True
    except Exception as e:
        result["error"] = str(e)

    return result


def delete_script(name: str) -> dict:
    """
    Delete a saved script by name.

    Returns:
      { "success": bool, "error": str | None }
    """
    result = {"success": False, "error": None}

    store = _load_script_store()
    if name not in store["scripts"]:
        result["error"] = f"Script '{name}' not found."
        return result

    del store["scripts"][name]
    try:
        _save_script_store(store)
        result["success"] = True
    except Exception as e:
        result["error"] = str(e)

    return result


def run_saved_script(name: str) -> dict:
    """
    Run a saved script by name. Updates last_run_at and last_output in the store.

    Returns the run output dict (same structure as run_python_snippet /
    run_powershell_snippet), plus "script_name".
    """
    store = _load_script_store()
    script = store["scripts"].get(name)

    if not script:
        return {
            "error": f"Script '{name}' not found.",
            "stdout": "", "stderr": "", "returncode": -1, "elapsed_ms": 0,
            "script_name": name,
        }

    language = script.get("language", "python")
    code     = script.get("code", "")

    if language == "python":
        output = run_python_snippet(code)
    elif language == "powershell":
        output = run_powershell_snippet(code)
    else:
        return {
            "error": f"Unknown language: {language}",
            "stdout": "", "stderr": "", "returncode": -1, "elapsed_ms": 0,
            "script_name": name,
        }

    # Persist last run metadata
    store["scripts"][name]["last_run_at"] = datetime.now().isoformat(timespec="seconds")
    store["scripts"][name]["last_output"] = {
        "stdout":      output.get("stdout", ""),
        "stderr":      output.get("stderr", ""),
        "returncode":  output.get("returncode", -1),
        "elapsed_ms":  output.get("elapsed_ms", 0),
        "error":       output.get("error"),
    }
    try:
        _save_script_store(store)
    except Exception:
        pass

    output["script_name"] = name
    return output


# ─────────────────────────────────────────────
# 5. Windows Event Log Viewer
# ─────────────────────────────────────────────

# wevtutil level codes
_LEVEL_MAP = {
    "Critical":    "1",
    "Error":       "2",
    "Warning":     "3",
    "Information": "4",
    "Verbose":     "5",
}

_LEVEL_LABELS = {
    "1": "Critical",
    "2": "Error",
    "3": "Warning",
    "4": "Information",
    "5": "Verbose",
    "0": "Unknown",
}


def get_event_log(
    log_name: str = "System",
    max_events: int = 200,
    level_filter: str | None = None,
    search: str | None = None,
) -> dict:
    """
    Query a Windows Event Log using wevtutil.

    log_name:     "System" | "Application" | "Security" | any valid log name
    max_events:   Maximum number of events to return (default 200)
    level_filter: "Critical" | "Error" | "Warning" | "Information" | "Verbose" | None (all)
    search:       Optional keyword to filter event messages (case-insensitive)

    Returns:
      {
        "log_name": str,
        "events": [
          {
            "time_created": str,
            "level":        str,
            "level_label":  str,
            "event_id":     str,
            "source":       str,
            "message":      str,
          }
        ],
        "count": int,
        "errors": []
      }
    """
    result = {
        "log_name": log_name,
        "events":   [],
        "count":    0,
        "errors":   [],
    }

    # Build XPath query
    xpath_conditions = []
    if level_filter and level_filter in _LEVEL_MAP:
        xpath_conditions.append(f"Level={_LEVEL_MAP[level_filter]}")

    if xpath_conditions:
        xpath = f"*[System[{' and '.join(xpath_conditions)}]]"
    else:
        xpath = "*"

    cmd = [
        "wevtutil", "qe", log_name,
        f"/count:{max_events}",
        "/rd:true",          # newest first
        "/format:text",
        f"/query:{xpath}",
    ]

    raw = _run(cmd, timeout=30)

    if raw["error"]:
        result["errors"].append(raw["error"])
        return result

    if raw["returncode"] != 0:
        err = (raw["stderr"] or "wevtutil returned non-zero exit code").strip()
        result["errors"].append(err)
        return result

    output = raw["stdout"]
    if not output.strip():
        return result

    # ── Parse wevtutil text format ────────────────────────────────────────────
    # Events are separated by blank lines. Each block looks like:
    # Event[N]:
    #   Log Name: System
    #   Source: ...
    #   Date: 2024-01-01T12:00:00.000Z
    #   Event ID: 7036
    #   Level: Information
    #   ...
    #   Description:
    #   The ... service ...

    blocks = re.split(r"\n\s*\n", output.strip())
    for block in blocks:
        if not block.strip():
            continue

        event = {
            "time_created": "—",
            "level":        "0",
            "level_label":  "Unknown",
            "event_id":     "—",
            "source":       "—",
            "message":      "",
        }

        in_description = False
        desc_lines = []

        for line in block.splitlines():
            stripped = line.strip()

            if in_description:
                desc_lines.append(stripped)
                continue

            if stripped.lower().startswith("date:"):
                event["time_created"] = stripped.split(":", 1)[-1].strip()
            elif stripped.lower().startswith("event id:"):
                event["event_id"] = stripped.split(":", 1)[-1].strip()
            elif stripped.lower().startswith("level:"):
                label = stripped.split(":", 1)[-1].strip()
                event["level_label"] = label
                # Map label back to numeric
                for num, lbl in _LEVEL_LABELS.items():
                    if lbl.lower() == label.lower():
                        event["level"] = num
                        break
            elif stripped.lower().startswith("source:"):
                event["source"] = stripped.split(":", 1)[-1].strip()
            elif stripped.lower().startswith("description:"):
                in_description = True

        event["message"] = " ".join(desc_lines).strip()[:500]

        # Apply keyword search filter
        if search:
            haystack = (
                event["message"] + event["source"] + event["event_id"]
            ).lower()
            if search.lower() not in haystack:
                continue

        result["events"].append(event)

    result["count"] = len(result["events"])
    return result


# ─────────────────────────────────────────────
# 6. App / Flask Log Viewer
# ─────────────────────────────────────────────

def list_app_logs(log_dir: str | None = None) -> dict:
    """
    List available log files in the app logs directory.

    Returns:
      {
        "log_dir": str,
        "files": [ { "name": str, "size_bytes": int, "modified": str } ],
        "error": str | None
      }
    """
    log_dir = log_dir or DEFAULT_LOG_DIR
    result  = {"log_dir": log_dir, "files": [], "error": None}

    if not os.path.isdir(log_dir):
        result["error"] = f"Log directory not found: {log_dir}"
        return result

    try:
        for fname in sorted(os.listdir(log_dir)):
            fpath = os.path.join(log_dir, fname)
            if os.path.isfile(fpath) and fname.endswith((".log", ".txt")):
                stat = os.stat(fpath)
                result["files"].append({
                    "name":       fname,
                    "size_bytes": stat.st_size,
                    "modified":   datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
                })
    except Exception as e:
        result["error"] = str(e)

    return result


def get_app_log(
    log_path: str,
    max_lines: int = 500,
    search: str | None = None,
    log_dir: str | None = None,
) -> dict:
    """
    Read lines from an app log file with optional keyword search.

    log_path:  Filename (e.g. 'app.log') relative to the log dir,
               OR a full absolute path.
    max_lines: Maximum number of lines to return (newest last).
    search:    Optional keyword filter (case-insensitive).

    Returns:
      {
        "log_path": str,
        "lines":    [ { "number": int, "text": str } ],
        "count":    int,
        "truncated": bool,
        "error":    str | None
      }
    """
    log_dir = log_dir or DEFAULT_LOG_DIR
    result  = {
        "log_path":  log_path,
        "lines":     [],
        "count":     0,
        "truncated": False,
        "error":     None,
    }

    # Resolve path — allow absolute or relative to log_dir
    if not os.path.isabs(log_path):
        log_path = os.path.join(log_dir, log_path)

    if not os.path.isfile(log_path):
        result["error"] = f"Log file not found: {log_path}"
        return result

    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()

        # Apply search filter
        if search:
            all_lines = [l for l in all_lines if search.lower() in l.lower()]

        total = len(all_lines)
        if total > max_lines:
            result["truncated"] = True
            # Return the most recent max_lines
            all_lines = all_lines[-max_lines:]

        result["lines"] = [
            {"number": i + 1, "text": line.rstrip("\n\r")}
            for i, line in enumerate(all_lines)
        ]
        result["count"] = len(result["lines"])

    except Exception as e:
        result["error"] = str(e)

    return result