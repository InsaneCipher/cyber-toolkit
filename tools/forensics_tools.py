import ctypes
from datetime import datetime
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
            import pefile  # optional dependency
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
