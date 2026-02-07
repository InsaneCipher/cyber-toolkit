import os
import stat
import pathlib
import hashlib
import math
import ctypes
from datetime import datetime
import pytsk3
import exifread
from Evtx.Evtx import Evtx
from Registry import Registry
import os
import webview


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
