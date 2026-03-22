"""
forensics_tools.py
==================
Forensic analysis tools for the Cyber Toolkit.

Functions:
  - collect_forensics_results()  → file metadata, ADS streams, EXIF, event logs, registry, disk image
  - analyze_file()               → magic signature, hashes, entropy, PE analysis, heuristics
  - run_malware_sandbox()        → static-only malware analysis with quarantine
  - analyze_image()              → image format, hashes, entropy, EXIF metadata
"""

# ─────────────────────────────────────────────
# Imports
# ─────────────────────────────────────────────

import ctypes
import hashlib
import json
import math
import os
import pathlib
import re
import struct
import uuid
from datetime import datetime
from pathlib import Path

import exifread
import pefile
import pytsk3
from Evtx.Evtx import Evtx
from PIL import Image
from Registry import Registry


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _bytes_to_gb(n: int) -> float:
    return round(n / (1024 ** 3), 2)


def _bytes_to_mb(n: int) -> float:
    return round(n / (1024 ** 2), 2)


# ─────────────────────────────────────────────
# Forensics Collector
# ─────────────────────────────────────────────

def collect_forensics_results(
    target_path: str | None = None,
    evtx_path: str | None = None,
    registry_hive_path: str | None = None,
    disk_image_path: str | None = None,
) -> dict:
    """
    Collect forensic artefacts from one or more sources:
      - File metadata and Windows attributes (hidden, system)
      - NTFS Alternate Data Streams (ADS)
      - EXIF metadata (if applicable)
      - Windows Event Log (.evtx) parsing
      - Registry hive parsing (offline)
      - Disk image inspection via pytsk3

    All parameters are optional — pass only the sources you want to analyse.
    """
    print("Collecting Forensics Results...")

    results = {
        "file_metadata":         {},
        "ads_streams":           [],
        "exif_metadata":         {},
        "event_logs":            [],
        "registry_artifacts":    {},
        "suspicious_indicators": [],
        "disk_image_info":       {},
    }

    # ── File metadata + Windows attributes ───────────────────────────────────
    if target_path and os.path.exists(target_path):
        p  = pathlib.Path(target_path)
        st = p.stat()

        FILE_ATTRIBUTE_HIDDEN = 0x2
        FILE_ATTRIBUTE_SYSTEM = 0x4

        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(p))

        results["file_metadata"] = {
            "path":       str(p),
            "size_bytes": _bytes_to_mb(st.st_size),
            "created":    datetime.fromtimestamp(st.st_ctime).isoformat(),
            "modified":   datetime.fromtimestamp(st.st_mtime).isoformat(),
            "accessed":   datetime.fromtimestamp(st.st_atime).isoformat(),
            "hidden":     bool(attrs & FILE_ATTRIBUTE_HIDDEN),
            "system":     bool(attrs & FILE_ATTRIBUTE_SYSTEM),
        }

        if attrs & FILE_ATTRIBUTE_HIDDEN or attrs & FILE_ATTRIBUTE_SYSTEM:
            results["suspicious_indicators"].append("Hidden or system file")

    # ── NTFS Alternate Data Streams (ADS) ─────────────────────────────────────
    if target_path:
        try:
            class WIN32_FIND_STREAM_DATA(ctypes.Structure):
                _fields_ = [
                    ("StreamSize",  ctypes.c_longlong),
                    ("cStreamName", ctypes.c_wchar * 296),
                ]

            FindFirstStreamW = ctypes.windll.kernel32.FindFirstStreamW
            FindNextStreamW  = ctypes.windll.kernel32.FindNextStreamW
            FindClose        = ctypes.windll.kernel32.FindClose

            data   = WIN32_FIND_STREAM_DATA()
            handle = FindFirstStreamW(str(target_path), 0, ctypes.byref(data), 0)

            if handle != -1:
                results["ads_streams"].append({
                    "name": data.cStreamName,
                    "size": _bytes_to_mb(data.StreamSize),
                })
                while FindNextStreamW(handle, ctypes.byref(data)):
                    results["ads_streams"].append({
                        "name": data.cStreamName,
                        "size": _bytes_to_mb(data.StreamSize),
                    })
                FindClose(handle)

            if len(results["ads_streams"]) > 1:
                results["suspicious_indicators"].append("Alternate Data Streams present")

        except Exception:
            pass  # ADS detection is best-effort on non-NTFS filesystems

    # ── EXIF metadata ─────────────────────────────────────────────────────────
    if target_path:
        try:
            with open(target_path, "rb") as f:
                tags = exifread.process_file(f, details=False)
                results["exif_metadata"] = {k: str(v) for k, v in tags.items()}
                if "GPS GPSLatitude" in tags:
                    results["suspicious_indicators"].append("GPS metadata present")
        except Exception:
            pass

    # ── Windows Event Log (.evtx) parsing ────────────────────────────────────
    if evtx_path:
        try:
            with Evtx(evtx_path) as log:
                for i, record in enumerate(log.records()):
                    if i >= 1000:   # hard cap to avoid memory exhaustion
                        break
                    results["event_logs"].append({
                        "record_id": record.record_id(),
                        "timestamp": record.timestamp().isoformat(),
                        "xml":       record.xml(),
                    })
        except Exception:
            results["event_logs"].append({"error": "Failed to parse EVTX"})

    # ── Registry hive parsing (offline) ──────────────────────────────────────
    if registry_hive_path:
        try:
            hive      = Registry.Registry(registry_hive_path)
            artifacts = {}

            for key_path in [
                r"Microsoft\Windows\CurrentVersion\Run",
                r"Microsoft\Windows\CurrentVersion\Uninstall",
            ]:
                try:
                    key = hive.open(key_path)
                    artifacts[key_path] = {v.name(): v.value() for v in key.values()}
                except Exception:
                    pass

            results["registry_artifacts"] = artifacts

        except Exception:
            results["registry_artifacts"]["error"] = "Failed to parse registry hive"

    # ── Disk image inspection ─────────────────────────────────────────────────
    if disk_image_path:
        try:
            pytsk3.Img_Info(disk_image_path)
            results["disk_image_info"] = {
                "image_path": disk_image_path,
                "status":     "Image opened successfully",
            }
        except Exception:
            results["disk_image_info"] = {
                "image_path": disk_image_path,
                "status":     "pytsk3 not available or failed to open image",
            }

    return results


# ─────────────────────────────────────────────
# File Analyser
# ─────────────────────────────────────────────

# Magic signature table — (label, signature_bytes, byte_offset, expected_extensions)
_MAGIC_TABLE = [
    ("pe_executable", b"MZ",              0, {".exe", ".dll", ".sys", ".scr", ".cpl"}),
    ("pdf",           b"%PDF-",           0, {".pdf"}),
    ("zip",           b"PK\x03\x04",      0, {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"}),
    ("zip_empty",     b"PK\x05\x06",      0, {".zip"}),
    ("zip_spanned",   b"PK\x07\x08",      0, {".zip"}),
    ("png",           b"\x89PNG\r\n\x1a\n", 0, {".png"}),
    ("jpg",           b"\xFF\xD8\xFF",    0, {".jpg", ".jpeg"}),
    ("gif87a",        b"GIF87a",          0, {".gif"}),
    ("gif89a",        b"GIF89a",          0, {".gif"}),
    ("bmp",           b"BM",              0, {".bmp"}),
    ("rar",           b"Rar!\x1A\x07\x00", 0, {".rar"}),
    ("7z",            b"7z\xBC\xAF\x27\x1C", 0, {".7z"}),
    ("gz",            b"\x1F\x8B",        0, {".gz"}),
    ("mp3_id3",       b"ID3",             0, {".mp3"}),
    ("wav",           b"RIFF",            0, {".wav"}),   # confirmed with WAVE at offset 8
    ("mp4",           b"ftyp",            4, {".mp4", ".m4v", ".mov"}),
    ("elf",           b"\x7FELF",         0, {".elf"}),
]


def _detect_magic(header: bytes) -> tuple[str, str]:
    """Return (type_label, confidence) from the first 4096 bytes of a file."""

    # Special case: RIFF + WAVE check
    if header[:4] == b"RIFF" and header[8:12] == b"WAVE":
        return ("wav", "high")

    for label, sig, offset, _exts in _MAGIC_TABLE:
        end = offset + len(sig)
        if len(header) >= end and header[offset:end] == sig:
            return (label, "high")

    return ("unknown", "low")


def _looks_like_pe(header: bytes) -> bool:
    """Return True if the header contains a valid MZ + PE signature."""
    if len(header) < 0x40 or header[:2] != b"MZ":
        return False
    try:
        e_lfanew = struct.unpack_from("<I", header, 0x3C)[0]
        if e_lfanew <= 0 or e_lfanew + 4 > len(header):
            return False
        return header[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"
    except Exception:
        return False


def analyze_file(target_path: str) -> dict:
    """
    Static file inspection:
      - Magic signature detection with extension mismatch check
      - MD5 / SHA-1 / SHA-256 hashing (streaming)
      - Shannon entropy with risk label
      - PE header analysis (sections, imports, exports) via pefile
      - Heuristic flags (packing, suspicious imports, masquerading)
    """
    print("Running File Analyser...")

    results = {
        "path":             target_path,
        "exists":           False,
        "size_bytes":       None,
        "extension":        None,
        "detected_type":    {"label": "unknown", "confidence": "low"},
        "extension_mismatch": None,
        "hashes":           {"md5": None, "sha1": None, "sha256": None},
        "entropy":          {"shannon": None, "label": None},
        "pe": {
            "is_pe":    False,
            "available": False,
            "summary":  {},
            "sections": [],
            "imports":  [],
            "exports":  [],
        },
        "heuristics": [],
        "errors":     [],
    }

    p = pathlib.Path(target_path) if target_path else None
    if not p or not p.exists() or not p.is_file():
        results["errors"].append("Path does not exist or is not a file.")
        return results

    results["exists"]     = True
    results["size_bytes"] = p.stat().st_size
    results["extension"]  = p.suffix.lower()

    # ── Magic signature detection ─────────────────────────────────────────────
    try:
        with open(p, "rb") as f:
            header = f.read(4096)
    except Exception as e:
        results["errors"].append(f"Failed to read file header: {e}")
        return results

    detected_label, confidence = _detect_magic(header)
    results["detected_type"] = {"label": detected_label, "confidence": confidence}

    # Extension mismatch check
    expected_exts = set()
    for label, _sig, _off, exts in _MAGIC_TABLE:
        if label == detected_label:
            expected_exts = exts
            break

    if detected_label != "unknown" and expected_exts:
        mismatch = results["extension"] not in expected_exts
        results["extension_mismatch"] = mismatch
        if mismatch:
            results["heuristics"].append(
                f"Extension mismatch: extension '{results['extension']}' does not match detected type '{detected_label}'"
            )
    else:
        results["extension_mismatch"] = None

    # ── Hashing (streaming, 1 MB chunks) ─────────────────────────────────────
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()

    try:
        with open(p, "rb") as f:
            while chunk := f.read(1024 * 1024):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        results["hashes"]["md5"]    = md5.hexdigest()
        results["hashes"]["sha1"]   = sha1.hexdigest()
        results["hashes"]["sha256"] = sha256.hexdigest()
    except Exception as e:
        results["errors"].append(f"Hashing failed: {e}")

    # ── Shannon entropy ───────────────────────────────────────────────────────
    try:
        counts = [0] * 256
        total  = 0
        with open(p, "rb") as f:
            while chunk := f.read(1024 * 1024):
                total += len(chunk)
                for b in chunk:
                    counts[b] += 1

        if total > 0:
            ent = 0.0
            for c in counts:
                if c:
                    p_i = c / total
                    ent -= p_i * math.log2(p_i)
            ent = round(ent, 6)
            results["entropy"]["shannon"] = ent

            if ent >= 7.3:
                results["entropy"]["label"] = "very_high (often packed/encrypted)"
                results["heuristics"].append("Very high entropy — packed or encrypted indicator")
            elif ent >= 6.8:
                results["entropy"]["label"] = "high"
                results["heuristics"].append("High entropy — possible packing or obfuscation")
            elif ent <= 3.5:
                results["entropy"]["label"] = "low"
            else:
                results["entropy"]["label"] = "normal"
    except Exception as e:
        results["errors"].append(f"Entropy calculation failed: {e}")

    # ── PE analysis ───────────────────────────────────────────────────────────
    is_pe = _looks_like_pe(header)
    results["pe"]["is_pe"] = is_pe

    if is_pe:
        try:
            results["pe"]["available"] = True
            pe = pefile.PE(str(p), fast_load=False)

            # Summary fields
            summary = {}
            try:
                summary["machine"]           = hex(pe.FILE_HEADER.Machine)
                summary["timestamp"]         = int(pe.FILE_HEADER.TimeDateStamp)
                summary["number_of_sections"]= int(pe.FILE_HEADER.NumberOfSections)
                summary["characteristics"]   = hex(pe.FILE_HEADER.Characteristics)
                summary["entrypoint"]        = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                summary["image_base"]        = hex(pe.OPTIONAL_HEADER.ImageBase)
                summary["subsystem"]         = int(pe.OPTIONAL_HEADER.Subsystem)
                summary["dll_characteristics"]= hex(pe.OPTIONAL_HEADER.DllCharacteristics)
                summary["is_dll"]            = bool(pe.FILE_HEADER.Characteristics & 0x2000)
            except Exception:
                pass
            results["pe"]["summary"] = summary

            # Sections
            sections = []
            for s in pe.sections:
                name = s.Name.decode(errors="ignore").rstrip("\x00")
                sections.append({
                    "name":             name,
                    "virtual_address":  hex(s.VirtualAddress),
                    "virtual_size":     int(s.Misc_VirtualSize),
                    "raw_size":         int(s.SizeOfRawData),
                    "entropy":          round(s.get_entropy(), 6),
                    "characteristics":  hex(s.Characteristics),
                })
            results["pe"]["sections"] = sections

            # Imports
            imports = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll   = entry.dll.decode(errors="ignore") if entry.dll else ""
                    funcs = []
                    for imp in entry.imports[:500]:
                        if imp.name:
                            funcs.append(imp.name.decode(errors="ignore"))
                        else:
                            funcs.append(f"ordinal_{imp.ordinal}")
                    imports.append({"dll": dll, "functions": funcs})
            results["pe"]["imports"] = imports

            # Exports
            exports = []
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:1000]:
                    name = exp.name.decode(errors="ignore") if exp.name else None
                    exports.append({
                        "name":    name,
                        "ordinal": int(exp.ordinal),
                        "address": hex(exp.address),
                    })
            results["pe"]["exports"] = exports

            # ── PE heuristics ─────────────────────────────────────────────────
            # Known packer section names
            _PACKER_SECTIONS = {".upx", "upx0", "upx1", ".aspack", ".themida", ".packed"}
            for s in sections:
                if s["name"].lower() in _PACKER_SECTIONS:
                    results["heuristics"].append(
                        f"Suspicious section name: '{s['name']}' — known packer indicator"
                    )
                    break

            # High-entropy sections
            high_ent = [s for s in sections if s["entropy"] >= 7.3]
            if high_ent:
                results["heuristics"].append(
                    f"PE contains {len(high_ent)} very high-entropy section(s) — possible packing"
                )

            # Suspicious imports (capability inference — not proof of malice)
            _SUSPICIOUS_IMPORTS = {
                "WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx", "OpenProcess",
                "WinExec", "ShellExecuteA", "ShellExecuteW",
                "URLDownloadToFileA", "URLDownloadToFileW",
                "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
                "HttpSendRequestA", "HttpSendRequestW",
                "RegSetValueExA", "RegSetValueExW",
                "CreateServiceA", "CreateServiceW",
            }
            found_suspicious = set()
            for lib in imports:
                for fn in lib.get("functions", []):
                    if fn in _SUSPICIOUS_IMPORTS:
                        found_suspicious.add(fn)
            if found_suspicious:
                results["heuristics"].append(
                    f"Suspicious imports found: {', '.join(sorted(found_suspicious))}"
                )

        except ImportError:
            results["pe"]["available"] = False
            results["heuristics"].append("PE detected but 'pefile' is not installed")
        except Exception as e:
            results["errors"].append(f"PE analysis failed: {e}")

    # ── Generic heuristics ────────────────────────────────────────────────────
    try:
        ext = results["extension"] or ""

        # Executable/script with high entropy
        if ext in {".exe", ".dll", ".scr", ".js", ".vbs", ".ps1", ".bat", ".cmd"}:
            shannon = results["entropy"]["shannon"]
            if shannon is not None and shannon >= 7.0:
                results["heuristics"].append(
                    "Executable or script with high entropy — packing/obfuscation indicator"
                )

        # PE masquerading as image or document
        if detected_label == "pe_executable" and ext in {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt"}:
            results["heuristics"].append(
                "Masquerading indicator: PE executable with non-executable extension"
            )
    except Exception:
        pass

    return results


# ─────────────────────────────────────────────
# Malware Sandbox (Static)
# ─────────────────────────────────────────────

# Regex patterns for IOC extraction
_URL_RE    = re.compile(r"(https?://[^\s\"\'<>]{6,})", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b([a-z0-9-]{2,}\.)+[a-z]{2,}\b", re.IGNORECASE)
_IP_RE     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_REG_RE    = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER"
    r"|HKEY_CLASSES_ROOT|HKEY_USERS)\\[^\s\"\'<>]{3,}",
    re.IGNORECASE,
)
_CMD_RE = re.compile(
    r"\b(?:powershell|cmd\.exe|wscript|cscript|mshta|rundll32|reg\.exe"
    r"|schtasks|wmic|bitsadmin|certutil|curl|wget)\b",
    re.IGNORECASE,
)

# Keyword categories for capability inference
_SUS_KEYWORDS = {
    "persistence": [
        "runonce", "run\\", "startup", "schtasks", "schedule.service",
        "winlogon", "services\\", "currentversion\\run", "taskschd", "at.exe",
    ],
    "networking": [
        "http", "https", "user-agent", "socket", "connect", "recv", "send",
        "wininet", "winhttp", "urlmon", "ws2_32", "internetopen", "internetconnect",
    ],
    "injection": [
        "virtualalloc", "virtualallocex", "writeprocessmemory", "createremotethread",
        "ntmapviewofsection", "setthreadcontext", "queueuserapc",
        "openprocess", "suspendthread", "resumethread",
    ],
}


def run_malware_sandbox(
    uploaded_bytes: bytes,
    original_filename: str,
    quarantine_dir: str | Path,
    *,
    export_json_path: str | Path | None = None,
    max_bytes: int = 50 * 1024 * 1024,
    strings_min_len: int = 4,
    strings_max_count: int = 20000,
) -> dict:
    """
    Static-only malware analysis. Does NOT execute the file.

    Steps:
      1. Write sample to quarantine directory under a UUID-prefixed name
      2. Compute hashes (MD5, SHA-1, SHA-256)
      3. Extract ASCII and UTF-16LE strings
      4. Scan strings for IOCs (URLs, domains, IPs, registry paths, commands)
      5. Parse PE headers if applicable (sections, imports, exports)
      6. Infer capabilities (networking, persistence, injection) from strings + imports
      7. Optionally export JSON report

    The quarantined file is deleted after analysis.
    """
    print("Running Malware Sandbox (static)...")

    if not uploaded_bytes:
        raise ValueError("uploaded_bytes is required and cannot be empty.")
    if len(uploaded_bytes) > max_bytes:
        raise ValueError(f"File too large ({len(uploaded_bytes)} bytes); maximum is {max_bytes}.")

    # ── Quarantine ────────────────────────────────────────────────────────────
    q_dir = Path(quarantine_dir)
    q_dir.mkdir(parents=True, exist_ok=True)

    sample_id      = str(uuid.uuid4())
    safe_name      = _sanitize_filename(original_filename) or "sample.bin"
    quarantine_path = q_dir / f"{sample_id}__{safe_name}"
    quarantine_path.write_bytes(uploaded_bytes)

    try:
        # ── Metadata + hashes ─────────────────────────────────────────────────
        stat = quarantine_path.stat()
        meta = {
            "sample_id":         sample_id,
            "original_filename": original_filename,
            "quarantine_path":   str(quarantine_path),
            "size_bytes":        stat.st_size,
            "created_utc":       datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "mtime_utc":         datetime.utcfromtimestamp(stat.st_mtime).isoformat(timespec="seconds") + "Z",
        }
        hashes = {
            "md5":    hashlib.md5(uploaded_bytes).hexdigest(),
            "sha1":   hashlib.sha1(uploaded_bytes).hexdigest(),
            "sha256": hashlib.sha256(uploaded_bytes).hexdigest(),
        }

        # ── String extraction ─────────────────────────────────────────────────
        ascii_strings   = _extract_ascii_strings(uploaded_bytes, min_len=strings_min_len, max_count=strings_max_count)
        utf16le_strings = _extract_utf16le_strings(uploaded_bytes, min_len=strings_min_len, max_count=strings_max_count)

        # ── IOC extraction ────────────────────────────────────────────────────
        indicators = _highlight_indicators(ascii_strings, utf16le_strings)

        # ── PE analysis ───────────────────────────────────────────────────────
        pe_report = _analyze_pe_sandbox(quarantine_path)

        # ── Capability inference ──────────────────────────────────────────────
        capabilities = _infer_capabilities(
            ascii_strings=ascii_strings,
            utf16le_strings=utf16le_strings,
            pe_report=pe_report,
        )

        report = {
            "meta":    meta,
            "hashes":  hashes,
            "strings": {
                "ascii_count":    len(ascii_strings),
                "utf16le_count":  len(utf16le_strings),
                "ascii_preview":  ascii_strings[:300],
                "utf16le_preview": utf16le_strings[:300],
            },
            "indicators":   indicators,
            "pe":           pe_report,
            "capabilities": capabilities,
        }

        # ── Optional JSON export ──────────────────────────────────────────────
        if export_json_path is not None:
            export_path = Path(export_json_path)
            export_path.parent.mkdir(parents=True, exist_ok=True)
            export_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    finally:
        # Always remove the quarantined file after analysis
        try:
            quarantine_path.unlink()
        except Exception:
            pass

    return report


# ── Sandbox helper functions ──────────────────────────────────────────────────

def _sanitize_filename(name: str) -> str:
    """Strip path components and unsafe characters from a filename."""
    if not name:
        return ""
    base = os.path.basename(name)
    base = re.sub(r"[^a-zA-Z0-9._-]+", "_", base).strip("._")
    return base[:120]


def _extract_ascii_strings(data: bytes, *, min_len: int = 4, max_count: int = 20000) -> list[str]:
    """Extract printable ASCII strings of at least min_len characters."""
    pattern = rb"[ -~]{%d,}" % min_len
    out = []
    for m in re.finditer(pattern, data):
        out.append(m.group(0).decode("ascii", errors="ignore"))
        if len(out) >= max_count:
            break
    return out


def _extract_utf16le_strings(data: bytes, *, min_len: int = 4, max_count: int = 20000) -> list[str]:
    """Extract UTF-16LE strings of at least min_len characters."""
    pattern = rb"(?:[ -~]\x00){%d,}" % min_len
    out = []
    for m in re.finditer(pattern, data):
        s = m.group(0).decode("utf-16le", errors="ignore").strip("\x00")
        if s:
            out.append(s)
        if len(out) >= max_count:
            break
    return out


def _highlight_indicators(ascii_strings: list[str], utf16le_strings: list[str]) -> dict:
    """Extract IOCs from string lists using compiled regex patterns."""
    haystack = "\n".join(ascii_strings[:5000] + utf16le_strings[:5000])

    urls             = sorted(set(_URL_RE.findall(haystack)))[:2000]
    domains          = sorted(set(_DOMAIN_RE.findall(haystack)))[:2000]
    ips              = sorted(set(_IP_RE.findall(haystack)))[:2000]
    registry_paths   = sorted(set(_REG_RE.findall(haystack)))[:2000]
    commands         = sorted(set(_CMD_RE.findall(haystack)))[:2000]

    lowered = haystack.lower()
    suspicious_hits = []
    for category, keys in _SUS_KEYWORDS.items():
        for k in keys:
            if k in lowered:
                suspicious_hits.append({"category": category, "keyword": k})
    suspicious_hits = suspicious_hits[:5000]

    return {
        "urls":               urls,
        "domains":            domains,
        "ips":                ips,
        "registry_paths":     registry_paths,
        "commands":           commands,
        "suspicious_keywords": suspicious_hits,
    }


def _analyze_pe_sandbox(file_path: Path) -> dict:
    """Parse PE headers for the sandbox report. Returns {"is_pe": False} on failure."""
    try:
        pe = pefile.PE(str(file_path), fast_load=True)
    except Exception:
        return {"is_pe": False}

    report: dict = {"is_pe": True}

    # ── Header fields ─────────────────────────────────────────────────────────
    try:
        report["machine"]         = hex(pe.FILE_HEADER.Machine)
        report["timestamp"]       = int(pe.FILE_HEADER.TimeDateStamp)
        report["characteristics"] = hex(pe.FILE_HEADER.Characteristics)
        report["subsystem"]       = int(pe.OPTIONAL_HEADER.Subsystem)
        report["image_base"]      = hex(pe.OPTIONAL_HEADER.ImageBase)
        report["entry_point"]     = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        report["is_dll"]          = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    except Exception:
        pass

    # ── Sections ──────────────────────────────────────────────────────────────
    sections = []
    try:
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode(errors="ignore")
            sections.append({
                "name":            name,
                "virtual_address": hex(s.VirtualAddress),
                "virtual_size":    int(s.Misc_VirtualSize),
                "raw_size":        int(s.SizeOfRawData),
                "entropy":         float(s.get_entropy()),
                "characteristics": hex(s.Characteristics),
            })
    except Exception:
        pass
    report["sections"] = sections

    # ── Imports ───────────────────────────────────────────────────────────────
    imports = []
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll   = entry.dll.decode(errors="ignore") if entry.dll else ""
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        funcs.append(imp.name.decode(errors="ignore"))
                    else:
                        funcs.append(f"ord_{imp.ordinal}")
                imports.append({"dll": dll, "functions": funcs[:5000]})
    except Exception:
        pass
    report["imports"] = imports

    # Flat import set for fast capability inference lookups
    report["import_set"] = sorted(
        {f.lower() for d in imports for f in d.get("functions", [])}
        | {d["dll"].lower() for d in imports if "dll" in d}
    )

    return report


def _infer_capabilities(
    *,
    ascii_strings: list[str],
    utf16le_strings: list[str],
    pe_report: dict,
) -> dict:
    """Heuristic capability inference from strings and PE imports."""
    combined   = "\n".join((ascii_strings[:8000] + utf16le_strings[:8000])).lower()
    import_set = set((pe_report or {}).get("import_set", []))

    def _hit_any(needles: list[str]) -> bool:
        return any(n in combined for n in needles) or any(n in import_set for n in needles)

    networking  = _hit_any(_SUS_KEYWORDS["networking"])
    persistence = _hit_any(_SUS_KEYWORDS["persistence"])
    injection   = _hit_any(_SUS_KEYWORDS["injection"])

    # Additional notes from PE analysis
    notes = []
    if pe_report.get("is_pe"):
        high_ent_sections = [s for s in pe_report.get("sections", []) if s.get("entropy", 0) >= 7.2]
        if high_ent_sections:
            notes.append({
                "type":   "packing_hint",
                "detail": f"{len(high_ent_sections)} section(s) with entropy ≥ 7.2 (possible packing).",
            })

    def _confidence(flag: bool, needles: list[str]) -> int:
        if not flag:
            return 0
        hits = sum(1 for n in needles if n in combined or n in import_set)
        return min(100, 20 + hits * 10)

    return {
        "networking":  bool(networking),
        "persistence": bool(persistence),
        "injection":   bool(injection),
        "notes":       notes,
        "confidence": {
            "networking":  _confidence(networking,  _SUS_KEYWORDS["networking"]),
            "persistence": _confidence(persistence, _SUS_KEYWORDS["persistence"]),
            "injection":   _confidence(injection,   _SUS_KEYWORDS["injection"]),
        },
    }


# ─────────────────────────────────────────────
# Image Analyser
# ─────────────────────────────────────────────

def analyze_image(path: str) -> dict:
    """
    Static image inspection:
      - SHA-256 hash
      - Shannon entropy (flags high-entropy payloads)
      - Pillow format detection
      - EXIF metadata extraction via exifread
    """
    results = {
        "path":       path,
        "size_bytes": None,
        "hashes":     {},
        "format":     None,
        "exif":       {},
        "entropy":    None,
        "flags":      [],
        "errors":     [],
    }

    try:
        with open(path, "rb") as f:
            data = f.read()

        results["size_bytes"]       = len(data)
        results["hashes"]["sha256"] = hashlib.sha256(data).hexdigest()

        # ── Shannon entropy ───────────────────────────────────────────────────
        freq  = [0] * 256
        for b in data:
            freq[b] += 1
        ent = 0.0
        for c in freq:
            if c:
                p_i  = c / len(data)
                ent -= p_i * math.log2(p_i)
        results["entropy"] = round(ent, 3)

        if ent > 7.9:
            results["flags"].append("Very high entropy — compressed or encrypted payload possible")

        # ── Pillow format detection ───────────────────────────────────────────
        with Image.open(path) as img:
            results["format"] = img.format

        # ── EXIF metadata ─────────────────────────────────────────────────────
        with open(path, "rb") as f:
            tags = exifread.process_file(f, details=False)
            results["exif"] = {k: str(v) for k, v in tags.items()}

        if not results["exif"]:
            results["flags"].append("No EXIF metadata present")

    except Exception as e:
        results["errors"].append(str(e))

    return results