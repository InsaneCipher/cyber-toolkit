"""
security_tools.py
=================
Windows-focused security analysis tools.
Pure Python / built-in modules only (subprocess, winreg, ctypes, os).

Tools:
  - persistence_detection()      → startup entries, scheduled tasks, suspicious services
  - firewall_rules_analyser()    → inbound/outbound rules via netsh
  - open_shares_checker()        → exposed SMB/network shares
  - privesc_checks()             → UAC, unquoted service paths, weak folder perms
"""

import ctypes
import http.client
import json
import os
import re
import socket
import sqlite3
import ssl
import subprocess
import time
import winreg
from ctypes import wintypes
from datetime import datetime

import psutil
import requests


# Helpers
def _run(cmd: list[str], timeout: int = 15) -> str:
    """Run a subprocess command and return stdout as a string."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW,  # Windows: no console popup
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except FileNotFoundError:
        return "[COMMAND NOT FOUND]"
    except Exception as e:
        return f"[ERROR: {e}]"


def _read_reg_key(hive, path: str) -> list[dict]:
    """Return list of {name, value} from a registry key (silently skips missing keys)."""
    entries = []
    try:
        with winreg.OpenKey(hive, path) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    entries.append({"name": name or "(Default)", "value": str(value)})
                    i += 1
                except OSError:
                    break
    except (FileNotFoundError, PermissionError):
        pass
    return entries


def _is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# Vulnerability Scanner
def run_vulnerability_scanner(
    installed_software: list | None = None,
    host: str = "127.0.0.1",
    max_ports: int = 200,
    banner_timeout: float = 1.5,
    cache_db_path: str = "cache/cve_cache.sqlite",
    use_nmap_if_available: bool = True,
    nvd_api_key: str | None = None,
) -> dict:

    """
    Windows-focused, practical vulnerability scanner.

    What it does:
    - Uses your installed software inventory (list of dicts) to perform CVE lookups (keyword-based).
    - Detects local listening services via psutil (PID, process path).
    - Grabs basic banners for common protocols (HTTP/HTTPS/SMTP/FTP/SSH).
    - Extracts Windows file version from process executable (best-effort).
    - Caches CVE lookups in SQLite.
    - Optional: if nmap.exe exists and enabled, can use it for richer version detection (not required).

    installed_software expected format (examples):
      [{"name":"Google Chrome","version":"122.0.6261.111","publisher":"Google LLC"}, ...]
      (Keys may vary; function tries common ones.)

    Returns dict with:
    - software_findings: per software CVE matches + confidence
    - service_findings: per listening service detection + matched CVEs
    - cache_stats, errors
    """

    print("Running Vulnerability Scan...")

    results = {
        "meta": {
            "host": host,
            "started_at": datetime.utcnow().isoformat() + "Z",
            "use_nmap_if_available": bool(use_nmap_if_available),
        },
        "software_findings": [],
        "service_findings": [],
        "cache_stats": {"hits": 0, "misses": 0, "writes": 0},
        "errors": [],
    }

    # -----------------------------
    # SQLite cache
    # -----------------------------
    def init_cache(db_path: str):
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cve_cache (
              cache_key TEXT PRIMARY KEY,
              source TEXT NOT NULL,
              query TEXT NOT NULL,
              response_json TEXT NOT NULL,
              created_utc INTEGER NOT NULL
            )
            """
        )
        con.commit()
        return con

    def cache_get(con, cache_key: str):
        cur = con.cursor()
        cur.execute("SELECT response_json, created_utc FROM cve_cache WHERE cache_key = ?", (cache_key,))
        row = cur.fetchone()
        return row

    def cache_put(con, cache_key: str, source: str, query: str, response_obj: dict):
        cur = con.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO cve_cache(cache_key, source, query, response_json, created_utc) VALUES(?,?,?,?,?)",
            (cache_key, source, query, json.dumps(response_obj), int(time.time())),
        )
        con.commit()

    con = None
    try:
        con = init_cache(cache_db_path)
    except Exception as e:
        results["errors"].append(f"Failed to init cache: {e}")

    # -----------------------------
    # Helpers: normalization & confidence
    # -----------------------------
    def norm_text(s: str) -> str:
        s = (s or "").strip().lower()
        s = re.sub(r"\s+", " ", s)
        return s

    def normalize_product(name: str) -> str:
        n = norm_text(name)
        # strip common noise tokens
        n = re.sub(r"\b(x64|x86|64-bit|32-bit|installer|setup|update|runtime|version)\b", "", n)
        n = re.sub(r"\s+", " ", n).strip()
        return n

    def parse_version(v: str) -> str:
        v = (v or "").strip()
        # keep digits and dots; drop trailing junk
        m = re.search(r"\d+(?:\.\d+){0,5}", v)
        return m.group(0) if m else v

    def confidence_score(match_mode: str) -> str:
        # simple, explicit labels for UI
        if match_mode == "exact":
            return "high"
        if match_mode == "partial":
            return "medium"
        return "low"

    # -----------------------------
    # Windows file version (ctypes)
    # -----------------------------
    def get_file_version_windows(exe_path: str) -> str | None:
        try:
            if not exe_path or not os.path.exists(exe_path):
                return None

            ver = ctypes.windll.version
            size = ver.GetFileVersionInfoSizeW(exe_path, None)
            if not size:
                return None

            res = ctypes.create_string_buffer(size)
            if not ver.GetFileVersionInfoW(exe_path, 0, size, res):
                return None

            u_len = wintypes.UINT()
            lp = ctypes.c_void_p()

            # VS_FIXEDFILEINFO at "\"
            if not ver.VerQueryValueW(res, "\\", ctypes.byref(lp), ctypes.byref(u_len)):
                return None

            class VS_FIXEDFILEINFO(ctypes.Structure):
                _fields_ = [
                    ("dwSignature", wintypes.DWORD),
                    ("dwStrucVersion", wintypes.DWORD),
                    ("dwFileVersionMS", wintypes.DWORD),
                    ("dwFileVersionLS", wintypes.DWORD),
                    ("dwProductVersionMS", wintypes.DWORD),
                    ("dwProductVersionLS", wintypes.DWORD),
                    ("dwFileFlagsMask", wintypes.DWORD),
                    ("dwFileFlags", wintypes.DWORD),
                    ("dwFileOS", wintypes.DWORD),
                    ("dwFileType", wintypes.DWORD),
                    ("dwFileSubtype", wintypes.DWORD),
                    ("dwFileDateMS", wintypes.DWORD),
                    ("dwFileDateLS", wintypes.DWORD),
                ]

            ffi = ctypes.cast(lp, ctypes.POINTER(VS_FIXEDFILEINFO)).contents

            def hiword(d): return (d >> 16) & 0xFFFF
            def loword(d): return d & 0xFFFF

            major = hiword(ffi.dwFileVersionMS)
            minor = loword(ffi.dwFileVersionMS)
            build = hiword(ffi.dwFileVersionLS)
            patch = loword(ffi.dwFileVersionLS)
            return f"{major}.{minor}.{build}.{patch}"
        except Exception:
            return None

    # -----------------------------
    # CVE lookup: OSV (easy) + NVD keyword fallback (best-effort)
    # -----------------------------
    def osv_query(keyword: str) -> dict:
        """
        OSV keyword/free-text query using the /v1/query endpoint.
        Falls back gracefully if the API is unavailable or rate-limited.
        """
        if not requests:
            return {"error": "requests not installed"}

        payload = {"query": keyword}

        try:
            r = requests.post(
                "https://api.osv.dev/v1/query",
                json=payload,
                timeout=10,
            )
            if r.status_code == 429:
                return {"error": "OSV rate-limited (429) — try again shortly"}
            if not r.ok:
                return {"error": f"OSV HTTP {r.status_code}: {r.text[:200]}"}
            return r.json()
        except requests.exceptions.Timeout:
            return {"error": "OSV request timed out"}
        except Exception as e:
            return {"error": str(e)}

    def nvd_keyword_query(keyword: str) -> dict:
        """
        NVD keyword search is noisy. We keep it best-effort.
        Note: NVD APIs and endpoints may change; handle errors.
        """
        if not requests:
            return {"error": "requests not installed"}

        # Modern NVD API uses CPE/CVE endpoints; keywordSearch exists on CVE endpoint.
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"keywordSearch": keyword, "resultsPerPage": 20}
        headers = {}
        if nvd_api_key:
            headers["apiKey"] = nvd_api_key

        r = requests.get(url, params=params, headers=headers, timeout=10)
        r.raise_for_status()
        return r.json()

    def cached_cve_lookup(source: str, keyword: str) -> dict:
        cache_key = f"{source}:{keyword}".lower()
        if con:
            row = cache_get(con, cache_key)
            if row:
                results["cache_stats"]["hits"] += 1
                return json.loads(row[0])

        results["cache_stats"]["misses"] += 1

        try:
            if source == "osv":
                data = osv_query(keyword)
            else:
                data = nvd_keyword_query(keyword)

            if con:
                cache_put(con, cache_key, source, keyword, data)
                results["cache_stats"]["writes"] += 1
            return data
        except Exception as e:
            return {"error": str(e)}

    def extract_cves_from_osv(osv_json: dict) -> list[dict]:
        vulns = []
        for v in (osv_json or {}).get("vulns", [])[:20]:
            vulns.append({
                "id": v.get("id"),
                "summary": v.get("summary"),
                "details": (v.get("details") or "")[:300],
                "references": [r.get("url") for r in (v.get("references") or [])[:5]],
            })
        return vulns

    def extract_cves_from_nvd(nvd_json: dict) -> list[dict]:
        vulns = []
        for item in (nvd_json or {}).get("vulnerabilities", [])[:20]:
            c = item.get("cve", {})
            cid = c.get("id")
            desc = ""
            for d in c.get("descriptions", []) or []:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            vulns.append({
                "id": cid,
                "summary": (desc or "")[:300],
                "references": [r.get("url") for r in (c.get("references") or [])[:5]],
            })
        return vulns

    # -----------------------------
    # Installed software -> CVEs (keyword-based)
    # -----------------------------
    if installed_software is None:
        installed_software = []

    def pick_name_ver(entry: dict) -> tuple[str, str, str]:
        name = entry.get("name") or entry.get("Name") or entry.get("display_name") or entry.get("DisplayName") or ""
        ver = entry.get("version") or entry.get("Version") or entry.get("display_version") or entry.get("DisplayVersion") or ""
        pub = entry.get("publisher") or entry.get("Publisher") or ""
        return name, ver, pub

    for sw in installed_software[:500]:
        name, ver, pub = pick_name_ver(sw)
        nname = normalize_product(name)
        nver = parse_version(ver)

        if not nname:
            continue

        # match mode heuristic
        match_mode = "keyword"
        if pub and nver:
            match_mode = "partial"
        if pub and nver and len(nname) > 5:
            # still not true CPE exact, but treat as better
            match_mode = "partial"

        query = f"{name} {nver}".strip()

        # OSV first (fast and good for open-source), then NVD keyword
        osv_data = {"vulns": []}
        osv_cves = []

        nvd_data = cached_cve_lookup("nvd", query)
        nvd_cves = extract_cves_from_nvd(nvd_data) if "error" not in nvd_data else []

        results["software_findings"].append({
            "software": {"name": name, "version": ver, "publisher": pub},
            "normalized": {"name": nname, "version": nver},
            "match_mode": match_mode,
            "confidence": confidence_score(match_mode),
            "osv": {"count": len(osv_cves), "cves": osv_cves, "error": osv_data.get("error") if isinstance(osv_data, dict) else None},
            "nvd": {"count": len(nvd_cves), "cves": nvd_cves, "error": nvd_data.get("error") if isinstance(nvd_data, dict) else None},
        })

    # -----------------------------
    # Local listening service detection (psutil)
    # -----------------------------
    def list_listening_services() -> list[dict]:
        seen = set()
        services = []
        for c in psutil.net_connections(kind="inet"):
            if c.status != psutil.CONN_LISTEN:
                continue
            if not c.laddr:
                continue
            ip = c.laddr.ip
            port = c.laddr.port
            pid = c.pid

            key = (ip, port, pid)
            if key in seen:
                continue
            seen.add(key)

            proc_name = None
            exe_path = None
            exe_ver = None

            try:
                if pid:
                    pr = psutil.Process(pid)
                    proc_name = pr.name()
                    exe_path = pr.exe()
                    exe_ver = get_file_version_windows(exe_path) or None
            except Exception:
                pass

            services.append({
                "listen_ip": ip,
                "port": port,
                "pid": pid,
                "process_name": proc_name,
                "exe_path": exe_path,
                "exe_version": exe_ver,
            })
        return services

    # -----------------------------
    # Banner grabbing (basic)
    # -----------------------------
    COMMON_PROTO = {
        21: "ftp",
        22: "ssh",
        25: "smtp",
        80: "http",
        443: "https",
        110: "pop3",
        143: "imap",
        3389: "rdp",
    }

    def grab_banner(ip: str, port: int) -> dict:
        proto = COMMON_PROTO.get(port, "tcp")
        out = {"proto": proto, "banner": None, "http_headers": None, "error": None}

        try:
            if proto in {"ftp", "ssh", "smtp", "pop3", "imap"}:
                with socket.create_connection((ip, port), timeout=banner_timeout) as s:
                    s.settimeout(banner_timeout)
                    data = s.recv(4096)
                    out["banner"] = data.decode(errors="ignore").strip()[:300]
                return out

            if proto == "http":
                conn = http.client.HTTPConnection(ip, port, timeout=banner_timeout)
                conn.request("HEAD", "/")
                resp = conn.getresponse()
                headers = {k: v for k, v in resp.getheaders()}
                out["http_headers"] = headers
                out["banner"] = headers.get("Server") or headers.get("X-Powered-By")
                conn.close()
                return out

            if proto == "https":
                ctx = ssl.create_default_context()
                with socket.create_connection((ip, port), timeout=banner_timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                        # do a minimal HTTP request over TLS
                        req = b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                        ssock.sendall(req)
                        data = ssock.recv(8192)
                        text = data.decode(errors="ignore")
                        # crude header parse
                        head = text.split("\r\n\r\n", 1)[0]
                        out["banner"] = head[:300]
                return out

            # default: just try to read something
            with socket.create_connection((ip, port), timeout=banner_timeout) as s:
                s.settimeout(banner_timeout)
                try:
                    data = s.recv(4096)
                    out["banner"] = data.decode(errors="ignore").strip()[:300] if data else None
                except Exception:
                    pass
            return out

        except Exception as e:
            out["error"] = str(e)
            return out

    # -----------------------------
    # Optional Nmap integration (user-installed)
    # -----------------------------
    def find_nmap() -> str | None:
        # Try PATH first
        for path_dir in os.environ.get("PATH", "").split(os.pathsep):
            exe = os.path.join(path_dir, "nmap.exe")
            if os.path.exists(exe):
                return exe
        # Common install location
        common = r"C:\Program Files (x86)\Nmap\nmap.exe"
        return common if os.path.exists(common) else None

    def nmap_version_scan(nmap_exe: str) -> list[dict]:
        """
        Runs nmap -sV on localhost only (safe-ish) and parses very roughly.
        This is optional; failures should not break the scanner.
        """
        findings = []
        try:
            # -Pn avoids host discovery delays on localhost
            cmd = [nmap_exe, "-sV", "-Pn", host]
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            out = cp.stdout or ""
            # Very rough parse of lines like: "80/tcp open  http  Microsoft IIS httpd 10.0"
            for line in out.splitlines():
                m = re.match(r"^(\d+)\/tcp\s+open\s+(\S+)\s+(.*)$", line.strip())
                if m:
                    port = int(m.group(1))
                    svc = m.group(2)
                    ver = m.group(3).strip()
                    findings.append({"port": port, "service": svc, "version": ver})
        except Exception as e:
            results["errors"].append(f"Nmap scan failed: {e}")
        return findings

    listening = list_listening_services()

    nmap_exe = find_nmap() if use_nmap_if_available else None
    nmap_findings = nmap_version_scan(nmap_exe) if nmap_exe else []

    # Index nmap findings by port
    nmap_by_port = {f["port"]: f for f in nmap_findings}

    for svc in listening:
        ip = svc["listen_ip"]
        port = svc["port"]
        pid = svc.get("pid")

        banner = grab_banner(ip, port)
        nmap_ver = nmap_by_port.get(port)

        # Create a keyword for CVE lookups for services, best-effort
        service_keyword = None
        if nmap_ver and nmap_ver.get("version"):
            service_keyword = nmap_ver["version"]
        elif banner.get("banner"):
            service_keyword = banner["banner"]

        service_cves_osv = []
        service_cves_nvd = []
        service_conf = "low"

        if service_keyword:
            # Keep queries short; banners can be huge/noisy
            q = service_keyword[:120]
            service_conf = "medium"

            osv_data = cached_cve_lookup("osv", q)
            service_cves_osv = extract_cves_from_osv(osv_data) if "error" not in osv_data else []

            nvd_data = cached_cve_lookup("nvd", q)
            service_cves_nvd = extract_cves_from_nvd(nvd_data) if "error" not in nvd_data else []

        results["service_findings"].append({
            "service": svc,
            "banner": banner,
            "nmap": nmap_ver,
            "match_mode": "partial" if service_keyword else "keyword",
            "confidence": service_conf if service_keyword else "low",
            "osv": {"count": len(service_cves_osv), "cves": service_cves_osv},
            "nvd": {"count": len(service_cves_nvd), "cves": service_cves_nvd},
        })

    results["meta"]["finished_at"] = datetime.utcnow().isoformat() + "Z"

    # Close cache
    try:
        if con:
            con.close()
    except Exception:
        pass

    return results


# Persistence Detection
def persistence_detection() -> dict:
    """
    Scans common Windows persistence mechanisms:
      - Registry Run keys (HKCU + HKLM)
      - Startup folders
      - Scheduled tasks
      - Suspicious / auto-start services
    """
    results = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "registry_run": [],
        "startup_folders": [],
        "scheduled_tasks": [],
        "suspicious_services": [],
        "errors": [],
    }

    # ── Registry Run keys ──────────────────────────────────────────────────────
    run_keys = [
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]
    for hive, path in run_keys:
        hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
        for entry in _read_reg_key(hive, path):
            results["registry_run"].append({
                "hive": hive_name,
                "key": path,
                "name": entry["name"],
                "value": entry["value"],
            })

    # ── Startup Folders ────────────────────────────────────────────────────────
    startup_dirs = []
    appdata = os.environ.get("APPDATA", "")
    programdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
    if appdata:
        startup_dirs.append(os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup"))
    startup_dirs.append(os.path.join(programdata, r"Microsoft\Windows\Start Menu\Programs\StartUp"))

    for folder in startup_dirs:
        if os.path.isdir(folder):
            try:
                for f in os.listdir(folder):
                    full = os.path.join(folder, f)
                    results["startup_folders"].append({
                        "folder": folder,
                        "file": f,
                        "size_bytes": os.path.getsize(full) if os.path.isfile(full) else None,
                    })
            except PermissionError as e:
                results["errors"].append(f"Startup folder access denied: {folder} — {e}")

    # ── Scheduled Tasks ────────────────────────────────────────────────────────
    raw = _run(["schtasks", "/query", "/fo", "CSV", "/v"], timeout=20)
    if raw and "[" not in raw[:5]:  # crude check it's not an error
        lines = raw.splitlines()
        if lines:
            headers = [h.strip('"') for h in lines[0].split('","')]
            want = {"TaskName", "Status", "Next Run Time", "Last Run Time", "Run As User", "Task To Run"}
            idx = {h: i for i, h in enumerate(headers) if h in want}
            for line in lines[1:]:
                cols = [c.strip('"') for c in line.split('","')]
                if len(cols) < len(headers):
                    continue
                task_name = cols[idx.get("TaskName", 0)] if "TaskName" in idx else ""
                # Skip repeated header rows (schtasks paginates and repeats headers)
                if task_name.lower() in ("taskname", "task name", ""):
                    continue
                if task_name.lower().startswith("\\microsoft\\windows\\"):
                    continue
    else:
        results["errors"].append("Could not query scheduled tasks (schtasks not available or access denied).")

    # ── Suspicious Services ────────────────────────────────────────────────────
    # Flag services that: are set to auto-start AND are currently stopped,
    # or whose binary path looks non-standard (not in System32/SysWOW64/Program Files)
    raw_svc = _run(["sc", "query", "type=", "all", "state=", "all"], timeout=20)
    # Parse service names from sc query output
    service_names = []
    for line in raw_svc.splitlines():
        line = line.strip()
        if line.startswith("SERVICE_NAME:"):
            service_names.append(line.split(":", 1)[1].strip())

    TRUSTED_PATHS = (
        "c:\\windows\\system32",
        "c:\\windows\\syswow64",
        "c:\\program files",
        "c:\\program files (x86)",
    )
    for svc in service_names[:200]:  # cap to avoid hanging
        info_raw = _run(["sc", "qc", svc], timeout=5)
        start_type, binary_path, state = "", "", ""
        for line in info_raw.splitlines():
            line = line.strip()
            if "START_TYPE" in line:
                start_type = line
            elif "BINARY_PATH_NAME" in line:
                binary_path = line.split(":", 1)[-1].strip()
            elif "STATE" in line and "WIN32_EXIT_CODE" not in line:
                state = line

        if not binary_path:
            continue

        bp_lower = binary_path.lower().strip('"').lstrip()
        is_trusted = any(bp_lower.startswith(p) for p in TRUSTED_PATHS)
        is_auto = "AUTO_START" in start_type

        if not is_trusted:
            results["suspicious_services"].append({
                "service": svc,
                "binary_path": binary_path,
                "start_type": start_type.split()[-1] if start_type else "UNKNOWN",
                "state": state.split()[-1] if state else "UNKNOWN",
                "flag": "Non-standard binary path",
            })
        elif is_auto and "STOPPED" in state:
            results["suspicious_services"].append({
                "service": svc,
                "binary_path": binary_path,
                "start_type": "AUTO_START",
                "state": "STOPPED",
                "flag": "Auto-start but stopped",
            })

    results["summary"] = {
        "registry_run_count": len(results["registry_run"]),
        "startup_files_count": len(results["startup_folders"]),
        "scheduled_tasks_count": len(results["scheduled_tasks"]),
        "suspicious_services_count": len(results["suspicious_services"]),
    }

    return results


# ─────────────────────────────────────────────
# 2. Firewall Rules Analyser
# ─────────────────────────────────────────────

def firewall_rules_analyser() -> dict:
    """
    Dumps Windows Firewall rules (inbound + outbound) using netsh advfirewall.
    Also checks whether the firewall is enabled per-profile.
    """
    results = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "profiles": {},
        "rules": [],
        "summary": {},
        "errors": [],
    }

    # ── Profile status ─────────────────────────────────────────────────────────
    for profile in ("domain", "private", "public"):
        raw = _run(["netsh", "advfirewall", "show", f"{profile}profile"])
        state = "unknown"
        for line in raw.splitlines():
            if "State" in line:
                state = "ON" if "ON" in line.upper() else "OFF"
                break
        results["profiles"][profile] = state

    # ── Rules ─────────────────────────────────────────────────────────────────
    raw_rules = _run(
        ["netsh", "advfirewall", "firewall", "show", "rule", "name=all", "verbose"],
        timeout=30,
    )

    if not raw_rules or "[ERROR" in raw_rules:
        results["errors"].append("Could not retrieve firewall rules via netsh.")
        return results

    # Parse blocks separated by blank lines
    blocks = raw_rules.strip().split("\n\n")
    for block in blocks:
        rule = {}
        for line in block.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                rule[k.strip()] = v.strip()
        if "Rule Name" in rule:
            results["rules"].append({
                "name": rule.get("Rule Name", ""),
                "enabled": rule.get("Enabled", ""),
                "direction": rule.get("Direction", ""),
                "action": rule.get("Action", ""),
                "protocol": rule.get("Protocol", ""),
                "local_port": rule.get("LocalPort", ""),
                "remote_port": rule.get("RemotePort", ""),
                "remote_address": rule.get("RemoteAddress", ""),
                "program": rule.get("Program", ""),
                "profiles": rule.get("Profiles", ""),
            })

    inbound  = [r for r in results["rules"] if r["direction"].lower() == "in"]
    outbound = [r for r in results["rules"] if r["direction"].lower() == "out"]
    enabled  = [r for r in results["rules"] if r["enabled"].lower() == "yes"]
    blocked  = [r for r in results["rules"] if r["action"].lower() == "block"]

    results["summary"] = {
        "total_rules": len(results["rules"]),
        "inbound": len(inbound),
        "outbound": len(outbound),
        "enabled": len(enabled),
        "blocking_rules": len(blocked),
    }

    return results


# ─────────────────────────────────────────────
# 3. Open Shares / SMB Checker
# ─────────────────────────────────────────────

def open_shares_checker() -> dict:
    """
    Enumerates local SMB shares and flags potentially exposed ones.
    Uses net share + registry for share permissions.
    """
    results = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "shares": [],
        "exposed": [],
        "errors": [],
    }

    raw = _run(["net", "share"])
    if not raw or "[ERROR" in raw:
        results["errors"].append("Could not enumerate shares via 'net share'.")
        return results

    # Skip header/footer lines
    lines = raw.splitlines()
    data_lines = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Skip separator and header
        if line.startswith("Share name") or line.startswith("-") or line.startswith("The command"):
            continue
        data_lines.append(line)

    ADMIN_SHARES = {"ADMIN$", "IPC$", "C$", "D$", "E$", "F$", "PRINT$"}

    for line in data_lines:
        parts = line.split(None, 2)  # ShareName  Path  Remark
        if not parts:
            continue
        share_name = parts[0]
        path = parts[1] if len(parts) > 1 else ""
        remark = parts[2] if len(parts) > 2 else ""

        is_admin = share_name.upper() in ADMIN_SHARES
        is_hidden = share_name.endswith("$")

        share_entry = {
            "name": share_name,
            "path": path,
            "remark": remark,
            "hidden": is_hidden,
            "admin_share": is_admin,
        }
        results["shares"].append(share_entry)

        # Flag non-hidden, non-admin shares with real paths as potentially exposed
        if not is_hidden and path and os.path.isdir(path):
            share_entry["flag"] = "Publicly visible share with accessible path"
            results["exposed"].append(share_entry)

    results["summary"] = {
        "total_shares": len(results["shares"]),
        "exposed_count": len(results["exposed"]),
        "admin_shares": sum(1 for s in results["shares"] if s["admin_share"]),
        "hidden_shares": sum(1 for s in results["shares"] if s["hidden"]),
    }

    return results


# ─────────────────────────────────────────────
# 4. Privilege Escalation Checks
# ─────────────────────────────────────────────

def privesc_checks() -> dict:
    """
    Checks common Windows privilege escalation vectors:
      - UAC status
      - AlwaysInstallElevated registry flag
      - Unquoted service paths
      - Writable directories in PATH
      - Current user privileges (whoami /priv)
    """
    results = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "is_admin": _is_admin(),
        "uac": {},
        "always_install_elevated": False,
        "unquoted_service_paths": [],
        "writable_path_dirs": [],
        "user_privileges": [],
        "findings": [],   # human-readable risk summary
        "errors": [],
    }

    # ── UAC ───────────────────────────────────────────────────────────────────
    uac_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    uac_values = {
        "EnableLUA": None,
        "ConsentPromptBehaviorAdmin": None,
        "PromptOnSecureDesktop": None,
    }
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, uac_key) as key:
            for vname in list(uac_values.keys()):
                try:
                    val, _ = winreg.QueryValueEx(key, vname)
                    uac_values[vname] = val
                except FileNotFoundError:
                    pass
    except (FileNotFoundError, PermissionError) as e:
        results["errors"].append(f"UAC registry read failed: {e}")

    results["uac"] = {
        "lua_enabled": uac_values["EnableLUA"],          # 0 = UAC off
        "consent_behavior": uac_values["ConsentPromptBehaviorAdmin"],
        "secure_desktop": uac_values["PromptOnSecureDesktop"],
    }
    if uac_values["EnableLUA"] == 0:
        results["findings"].append({
            "severity": "HIGH",
            "check": "UAC Disabled",
            "detail": "EnableLUA = 0. UAC is completely disabled on this system.",
        })

    # ── AlwaysInstallElevated ─────────────────────────────────────────────────
    aie_paths = [
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Policies\Microsoft\Windows\Installer"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Installer"),
    ]
    aie_set = []
    for hive, path in aie_paths:
        try:
            with winreg.OpenKey(hive, path) as key:
                val, _ = winreg.QueryValueEx(key, "AlwaysInstallElevated")
                if val == 1:
                    aie_set.append("HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM")
        except (FileNotFoundError, PermissionError):
            pass

    if len(aie_set) == 2:
        results["always_install_elevated"] = True
        results["findings"].append({
            "severity": "HIGH",
            "check": "AlwaysInstallElevated",
            "detail": "Both HKCU and HKLM AlwaysInstallElevated = 1. MSI files run as SYSTEM.",
        })

    # ── Unquoted Service Paths ────────────────────────────────────────────────
    raw_svc = _run(["sc", "query", "type=", "all", "state=", "all"], timeout=20)
    service_names = []
    for line in raw_svc.splitlines():
        line = line.strip()
        if line.startswith("SERVICE_NAME:"):
            service_names.append(line.split(":", 1)[1].strip())

    for svc in service_names[:200]:
        info = _run(["sc", "qc", svc], timeout=5)
        for line in info.splitlines():
            if "BINARY_PATH_NAME" in line:
                bp = line.split(":", 1)[-1].strip()
                # Unquoted = contains a space, doesn't start with a quote, has path separators
                if " " in bp and not bp.startswith('"') and "\\" in bp:
                    # Only flag if a plausible injection point exists
                    parts = bp.split("\\")
                    # Check each intermediate directory
                    for i in range(1, len(parts)):
                        segment = "\\".join(parts[:i])
                        if " " in os.path.basename(segment):
                            results["unquoted_service_paths"].append({
                                "service": svc,
                                "binary_path": bp,
                            })
                            break

    if results["unquoted_service_paths"]:
        results["findings"].append({
            "severity": "MEDIUM",
            "check": "Unquoted Service Paths",
            "detail": f"{len(results['unquoted_service_paths'])} service(s) have unquoted paths with spaces.",
        })

    # ── Writable PATH Directories ─────────────────────────────────────────────
    path_dirs = os.environ.get("PATH", "").split(";")
    for d in path_dirs:
        d = d.strip()
        if not d or not os.path.isdir(d):
            continue
        # Try creating a temp file
        test_file = os.path.join(d, "__privesc_test__.tmp")
        try:
            with open(test_file, "w") as f:
                f.write("test")
            os.remove(test_file)
            results["writable_path_dirs"].append(d)
        except (PermissionError, OSError):
            pass

    if results["writable_path_dirs"]:
        results["findings"].append({
            "severity": "MEDIUM",
            "check": "Writable PATH Directories",
            "detail": f"{len(results['writable_path_dirs'])} writable director(ies) found in PATH. DLL/binary planting possible.",
        })

    # ── Current User Privileges ───────────────────────────────────────────────
    raw_priv = _run(["whoami", "/priv"])
    DANGEROUS_PRIVS = {
        "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeTcbPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeCreateTokenPrivilege",
        "SeLoadDriverPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeDebugPrivilege",
    }
    for line in raw_priv.splitlines():
        for priv in DANGEROUS_PRIVS:
            if priv in line:
                enabled = "Enabled" in line
                results["user_privileges"].append({
                    "privilege": priv,
                    "enabled": enabled,
                    "risk": "HIGH" if enabled else "LOW",
                })
                if enabled:
                    results["findings"].append({
                        "severity": "HIGH",
                        "check": f"Dangerous Privilege: {priv}",
                        "detail": f"{priv} is Enabled for current user — potential escalation vector.",
                    })

    results["summary"] = {
        "is_admin": results["is_admin"],
        "uac_enabled": uac_values["EnableLUA"] != 0,
        "always_install_elevated": results["always_install_elevated"],
        "unquoted_paths_count": len(results["unquoted_service_paths"]),
        "writable_path_dirs_count": len(results["writable_path_dirs"]),
        "high_risk_findings": sum(1 for f in results["findings"] if f["severity"] == "HIGH"),
        "medium_risk_findings": sum(1 for f in results["findings"] if f["severity"] == "MEDIUM"),
    }

    return results