import pytsk3
import exifread
from Evtx.Evtx import Evtx
from Registry import Registry
import webview
import os
import pathlib
import hashlib
import math
import struct
import pefile
import os
import re
import json
import time
import sqlite3
import socket
import ssl
import http.client
import subprocess
from datetime import datetime
import psutil
import requests
import ctypes
from ctypes import wintypes


class Api:
    def pick_file(self):
        try:
            # Use the actual window instance (more reliable than module-level call)
            wnd = webview.windows[0]
            paths = wnd.create_file_dialog(webview.OPEN_DIALOG, allow_multiple=False)
            if not paths:
                return ""
            return paths[0]
        except Exception as e:
            return ""


def _bytes_to_gb(n: int) -> float:
    return round(n / (1024 ** 3), 2)


def _bytes_to_mb(n: int) -> float:
    return round(n / (1024 ** 2), 2)


def collect_forensics_results(target_path=None, evtx_path=None, registry_hive_path=None, disk_image_path=None):
    results = {
        "file_metadata": {},
        "ads_streams": [],
        "exif_metadata": {},
        "event_logs": [],
        "registry_artifacts": {},
        "suspicious_indicators": [],
        "disk_image_info": {}
    }

    # ------------------------------------------------------------
    # File metadata + attributes
    # ------------------------------------------------------------
    if target_path and os.path.exists(target_path):
        p = pathlib.Path(target_path)
        st = p.stat()

        # File attributes (Windows)
        FILE_ATTRIBUTE_HIDDEN = 0x2
        FILE_ATTRIBUTE_SYSTEM = 0x4

        GetFileAttributesW = ctypes.windll.kernel32.GetFileAttributesW
        attrs = GetFileAttributesW(str(p))

        results["file_metadata"] = {
            "path": str(p),
            "size_bytes": _bytes_to_mb(st.st_size),
            "created": datetime.fromtimestamp(st.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
            "accessed": datetime.fromtimestamp(st.st_atime).isoformat(),
            "hidden": bool(attrs & FILE_ATTRIBUTE_HIDDEN),
            "system": bool(attrs & FILE_ATTRIBUTE_SYSTEM),
        }

        if attrs & FILE_ATTRIBUTE_HIDDEN or attrs & FILE_ATTRIBUTE_SYSTEM:
            results["suspicious_indicators"].append("Hidden or system file")

    # ------------------------------------------------------------
    # NTFS Alternate Data Streams (ADS)
    # ------------------------------------------------------------
    if target_path:
        try:
            FindFirstStreamW = ctypes.windll.kernel32.FindFirstStreamW
            FindNextStreamW = ctypes.windll.kernel32.FindNextStreamW
            FindClose = ctypes.windll.kernel32.FindClose

            class WIN32_FIND_STREAM_DATA(ctypes.Structure):
                _fields_ = [
                    ("StreamSize", ctypes.c_longlong),
                    ("cStreamName", ctypes.c_wchar * 296)
                ]

            data = WIN32_FIND_STREAM_DATA()
            handle = FindFirstStreamW(
                str(target_path), 0, ctypes.byref(data), 0
            )

            if handle != -1:
                results["ads_streams"].append({
                    "name": data.cStreamName,
                    "size": _bytes_to_mb(data.StreamSize)
                })

                while FindNextStreamW(handle, ctypes.byref(data)):
                    results["ads_streams"].append({
                        "name": data.cStreamName,
                        "size": _bytes_to_mb(data.StreamSize)
                    })

                FindClose(handle)

            if len(results["ads_streams"]) > 1:
                results["suspicious_indicators"].append("Alternate Data Streams present")

        except Exception:
            pass  # ADS detection is best-effort

    # ------------------------------------------------------------
    # EXIF metadata (optional)
    # ------------------------------------------------------------
    if target_path:
        try:
            with open(target_path, "rb") as f:
                tags = exifread.process_file(f, details=False)
                results["exif_metadata"] = {k: str(v) for k, v in tags.items()}
                if "GPS GPSLatitude" in tags:
                    results["suspicious_indicators"].append("GPS metadata present")
        except Exception:
            pass

    # ------------------------------------------------------------
    # Windows Event Log (.evtx) parsing
    # ------------------------------------------------------------
    if evtx_path:
        try:
            with Evtx(evtx_path) as log:
                for i, record in enumerate(log.records()):
                    if i >= 1000:  # hard cap for safety
                        break
                    results["event_logs"].append({
                        "record_id": record.record_id(),
                        "timestamp": record.timestamp().isoformat(),
                        "xml": record.xml()
                    })
        except Exception:
            results["event_logs"].append({"error": "Failed to parse EVTX"})

    # ------------------------------------------------------------
    # Registry extraction (live or offline)
    # ------------------------------------------------------------
    if registry_hive_path:
        try:
            hive = Registry.Registry(registry_hive_path)

            artifacts = {}
            for key_path in [
                r"Microsoft\Windows\CurrentVersion\Run",
                r"Microsoft\Windows\CurrentVersion\Uninstall"
            ]:
                try:
                    key = hive.open(key_path)
                    artifacts[key_path] = {
                        v.name(): v.value() for v in key.values()
                    }
                except Exception:
                    pass

            results["registry_artifacts"] = artifacts

        except Exception:
            results["registry_artifacts"]["error"] = "Failed to parse registry hive"

    # ------------------------------------------------------------
    # Disk image (optional / best-effort)
    # ------------------------------------------------------------
    if disk_image_path:
        try:
            img = pytsk3.Img_Info(disk_image_path)
            results["disk_image_info"] = {
                "image_path": disk_image_path,
                "status": "Image opened successfully"
            }
        except Exception:
            results["disk_image_info"] = {
                "image_path": disk_image_path,
                "status": "pytsk3 not available or failed to open"
            }

    return results


def analyze_file(target_path: str) -> dict:
    results = {
        "path": target_path,
        "exists": False,
        "size_bytes": None,
        "extension": None,
        "detected_type": {"label": "unknown", "confidence": "low"},
        "extension_mismatch": None,
        "hashes": {"md5": None, "sha1": None, "sha256": None},
        "entropy": {"shannon": None, "label": None},
        "pe": {"is_pe": False, "available": False, "summary": {}, "sections": [], "imports": [], "exports": []},
        "heuristics": [],
        "errors": [],
    }

    p = pathlib.Path(target_path) if target_path else None
    if not p or not p.exists() or not p.is_file():
        results["errors"].append("Path does not exist or is not a file.")
        return results

    results["exists"] = True
    results["size_bytes"] = p.stat().st_size
    results["extension"] = p.suffix.lower()

    # ------------------------------------------------------------
    # Custom magic signature table (pure Python)
    # ------------------------------------------------------------
    # Each entry: (label, magic_bytes, offset, extensions_hint)
    MAGIC = [
        ("pe_executable", b"MZ", 0, {".exe", ".dll", ".sys", ".scr", ".cpl"}),
        ("pdf", b"%PDF-", 0, {".pdf"}),
        ("zip", b"PK\x03\x04", 0, {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"}),
        ("zip_empty", b"PK\x05\x06", 0, {".zip"}),
        ("zip_spanned", b"PK\x07\x08", 0, {".zip"}),
        ("png", b"\x89PNG\r\n\x1a\n", 0, {".png"}),
        ("jpg", b"\xFF\xD8\xFF", 0, {".jpg", ".jpeg"}),
        ("gif", b"GIF87a", 0, {".gif"}),
        ("gif89a", b"GIF89a", 0, {".gif"}),
        ("bmp", b"BM", 0, {".bmp"}),
        ("rar", b"Rar!\x1A\x07\x00", 0, {".rar"}),
        ("7z", b"7z\xBC\xAF\x27\x1C", 0, {".7z"}),
        ("gz", b"\x1F\x8B", 0, {".gz"}),
        ("mp3_id3", b"ID3", 0, {".mp3"}),
        ("wav", b"RIFF", 0, {".wav"}),  # needs "WAVE" at 8; handled below
        ("mp4", b"ftyp", 4, {".mp4", ".m4v", ".mov"}),  # ISO BMFF
        ("elf", b"\x7FELF", 0, {".elf"}),  # rare on Windows, but useful
    ]

    def detect_magic(header: bytes) -> tuple[str, str]:
        # Special RIFF/WAVE check
        if header[:4] == b"RIFF" and header[8:12] == b"WAVE":
            return ("wav", "high")

        for label, sig, off, _exts in MAGIC:
            if len(header) >= off + len(sig) and header[off:off + len(sig)] == sig:
                return (label, "high")
        return ("unknown", "low")

    # Read header bytes once
    try:
        with open(p, "rb") as f:
            header = f.read(4096)
    except Exception as e:
        results["errors"].append(f"Failed to read file header: {e}")
        return results

    detected_label, confidence = detect_magic(header)
    results["detected_type"] = {"label": detected_label, "confidence": confidence}

    # Extension mismatch check (simple + practical)
    expected_exts = set()
    for label, sig, off, exts in MAGIC:
        if label == detected_label:
            expected_exts = exts
            break

    if detected_label != "unknown" and expected_exts:
        results["extension_mismatch"] = (results["extension"] not in expected_exts)
        if results["extension_mismatch"]:
            results["heuristics"].append(
                f"Extension mismatch: ext '{results['extension']}' vs detected '{detected_label}'"
            )
    else:
        results["extension_mismatch"] = None

    # ------------------------------------------------------------
    # Hashes (streaming)
    # ------------------------------------------------------------
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    try:
        with open(p, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)  # 1MB
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        results["hashes"]["md5"] = md5.hexdigest()
        results["hashes"]["sha1"] = sha1.hexdigest()
        results["hashes"]["sha256"] = sha256.hexdigest()
    except Exception as e:
        results["errors"].append(f"Failed hashing file: {e}")

    # ------------------------------------------------------------
    # Shannon entropy (streaming byte histogram)
    # ------------------------------------------------------------
    try:
        counts = [0] * 256
        total = 0
        with open(p, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                for b in chunk:
                    counts[b] += 1

        if total > 0:
            ent = 0.0
            for c in counts:
                if c:
                    p_i = c / total
                    ent -= p_i * math.log2(p_i)
            results["entropy"]["shannon"] = round(ent, 6)

            # Practical labels (not definitive)
            if ent >= 7.3:
                results["entropy"]["label"] = "very_high (often packed/encrypted)"
                results["heuristics"].append("Very high entropy (packed/encrypted indicator)")
            elif ent >= 6.8:
                results["entropy"]["label"] = "high"
                results["heuristics"].append("High entropy (possible packing/obfuscation)")
            elif ent <= 3.5:
                results["entropy"]["label"] = "low"
            else:
                results["entropy"]["label"] = "normal"
    except Exception as e:
        results["errors"].append(f"Entropy calculation failed: {e}")

    # ------------------------------------------------------------
    # PE detection + analysis (pefile optional)
    # ------------------------------------------------------------
    def looks_like_pe(hdr: bytes) -> bool:
        # Minimal PE check: 'MZ' and PE signature offset points to 'PE\0\0'
        if len(hdr) < 0x40 or hdr[:2] != b"MZ":
            return False
        try:
            e_lfanew = struct.unpack_from("<I", hdr, 0x3C)[0]
            if e_lfanew <= 0 or e_lfanew + 4 > len(hdr):
                return False
            return hdr[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"
        except Exception:
            return False

    is_pe = looks_like_pe(header)
    results["pe"]["is_pe"] = is_pe

    if is_pe:
        try:
            results["pe"]["available"] = True

            pe = pefile.PE(str(p), fast_load=False)

            # Summary
            summary = {}
            try:
                summary["machine"] = hex(pe.FILE_HEADER.Machine)
                summary["timestamp"] = int(pe.FILE_HEADER.TimeDateStamp)
                summary["number_of_sections"] = int(pe.FILE_HEADER.NumberOfSections)
                summary["characteristics"] = hex(pe.FILE_HEADER.Characteristics)
                summary["entrypoint"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                summary["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)
                summary["subsystem"] = int(pe.OPTIONAL_HEADER.Subsystem)
                summary["dll_characteristics"] = hex(pe.OPTIONAL_HEADER.DllCharacteristics)
                summary["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
            except Exception:
                pass
            results["pe"]["summary"] = summary

            # Sections
            sections = []
            for s in pe.sections:
                name = s.Name.decode(errors="ignore").rstrip("\x00")
                sections.append({
                    "name": name,
                    "virtual_address": hex(s.VirtualAddress),
                    "virtual_size": int(s.Misc_VirtualSize),
                    "raw_size": int(s.SizeOfRawData),
                    "entropy": round(s.get_entropy(), 6),
                    "characteristics": hex(s.Characteristics),
                })
            results["pe"]["sections"] = sections

            # Imports
            imports = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode(errors="ignore") if entry.dll else ""
                    funcs = []
                    for imp in entry.imports[:500]:  # cap
                        if imp.name:
                            funcs.append(imp.name.decode(errors="ignore"))
                        else:
                            funcs.append(f"ordinal_{imp.ordinal}")
                    imports.append({"dll": dll, "functions": funcs})
            results["pe"]["imports"] = imports

            # Exports
            exports = []
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:1000]:  # cap
                    name = exp.name.decode(errors="ignore") if exp.name else None
                    exports.append({"name": name, "ordinal": int(exp.ordinal), "address": hex(exp.address)})
            results["pe"]["exports"] = exports

            # Heuristics from PE
            # 1) Suspicious section names
            suspicious_section_names = {".upx", "upx0", "upx1", ".aspack", ".themida", ".packed"}
            for s in sections:
                if s["name"].lower() in suspicious_section_names:
                    results["heuristics"].append(f"Suspicious section name: {s['name']} (packer indicator)")
                    break

            # 2) High-entropy section(s)
            high_ent_secs = [s for s in sections if s["entropy"] is not None and s["entropy"] >= 7.3]
            if high_ent_secs:
                results["heuristics"].append("PE contains very high-entropy section(s) (possible packing)")

            # 3) Suspicious imports (capability inference; not proof)
            suspicious_import_markers = {
                "WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx", "OpenProcess",
                "WinExec", "ShellExecuteA", "ShellExecuteW", "URLDownloadToFileA", "URLDownloadToFileW",
                "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
                "HttpSendRequestA", "HttpSendRequestW", "RegSetValueExA", "RegSetValueExW",
                "CreateServiceA", "CreateServiceW"
            }
            found = set()
            for lib in imports:
                for fn in lib.get("functions", []):
                    if fn in suspicious_import_markers:
                        found.add(fn)
                if len(found) >= 4:
                    break
            if found:
                results["heuristics"].append(f"Suspicious imports present: {', '.join(sorted(found))}")

        except ImportError:
            results["pe"]["available"] = False
            results["heuristics"].append("PE detected but 'pefile' not installed (PE details unavailable)")
        except Exception as e:
            results["errors"].append(f"PE analysis failed: {e}")

    # ------------------------------------------------------------
    # Generic heuristics (not definitive)
    # ------------------------------------------------------------
    try:
        low_ext = results["extension"] or ""
        if low_ext in {".exe", ".dll", ".scr", ".js", ".vbs", ".ps1", ".bat", ".cmd"}:
            # If it's executable/script and also high entropy, flag stronger
            if results["entropy"]["shannon"] is not None and results["entropy"]["shannon"] >= 7.0:
                results["heuristics"].append("Executable/script with high entropy (packing/obfuscation indicator)")

        # Common masquerading: .jpg/.png but actually PE
        if detected_label == "pe_executable" and low_ext in {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt"}:
            results["heuristics"].append("Masquerading indicator: PE executable with non-executable extension")
    except Exception:
        pass

    return results


def run_vulnerability_scanner(
    installed_software: list | None = None,
    host: str = "127.0.0.1",
    max_ports: int = 200,
    banner_timeout: float = 1.5,
    cache_db_path: str = "cve_cache.sqlite",
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
        if not requests:
            return {"error": "requests not installed"}
        url = "https://api.osv.dev/v1/query"
        payload = {"query": keyword}
        r = requests.post(url, json=payload, timeout=8)
        r.raise_for_status()
        return r.json()

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
        osv_data = cached_cve_lookup("osv", query)
        osv_cves = extract_cves_from_osv(osv_data) if "error" not in osv_data else []

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


