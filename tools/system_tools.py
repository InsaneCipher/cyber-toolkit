import platform
import psutil
import shutil
import socket
import getpass
import datetime
import subprocess
import cpuinfo
import wmi
import time
import json
from cpuinfo import get_cpu_info
from typing import Any, Dict, List, Optional


def _bytes_to_gb(n: int) -> float:
    return round(n / (1024 ** 3), 2)


def _bytes_to_mb(n: int) -> float:
    return round(n / (1024 ** 2), 2)


def get_system_info():
    info = {}

    try:
        # OS Info
        info["os_name"] = platform.system()
        info["os_version"] = platform.version()
        info["os_release"] = platform.release()
        info["os_arch"] = platform.machine()
        info["os_build"] = platform.release()
        info["build_number"] = platform.platform()

        # Host/User Info
        info["hostname"] = socket.gethostname()
        info["username"] = getpass.getuser()

        # Uptime
        boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.datetime.now() - boot_time
        info["system_uptime"] = str(uptime).split(".")[0]

        # Manufacturer/Model
        c = wmi.WMI()
        system_info = c.Win32_ComputerSystem()[0]
        info["manufacturer"] = system_info.Manufacturer
        info["model"] = system_info.Model

        # CPU Info
        cpu = cpuinfo.get_cpu_info()
        info["cpu_name"] = cpu.get("brand_raw", "Unknown CPU")
        info["cpu_cores"] = psutil.cpu_count(logical=False)
        info["cpu_threads"] = psutil.cpu_count(logical=True)
        info["cpu_freq"] = f"{psutil.cpu_freq().current:.2f} MHz" if psutil.cpu_freq() else "N/A"

        # Memory Info
        mem = psutil.virtual_memory()
        info["total_ram"] = f"{mem.total / (1024 ** 3):.2f} GB"
        info["used_ram"] = f"{mem.used / (1024 ** 3):.2f} GB"
        info["free_ram"] = f"{mem.available / (1024 ** 3):.2f} GB"

        # Disk Info
        disk = psutil.disk_usage("/")
        info["disk_total"] = f"{disk.total / (1024 ** 3):.2f} GB"
        info["disk_used"] = f"{disk.used / (1024 ** 3):.2f} GB"
        info["disk_free"] = f"{disk.free / (1024 ** 3):.2f} GB"

        # GPU Info
        try:
            gpus = [gpu.Name for gpu in wmi.WMI().Win32_VideoController()]
            info["gpu"] = gpus if gpus else ["No GPU detected"]
        except Exception:
            info["gpu"] = ["Unavailable"]

        # Battery Info
        try:
            battery = psutil.sensors_battery()
            if battery:
                info["battery_percent"] = f"{battery.percent}%"
                info["battery_plugged"] = "Plugged In" if battery.power_plugged else "On Battery"
            else:
                info["battery_percent"] = "N/A"
                info["battery_plugged"] = "N/A"
        except Exception:
            info["battery_percent"] = "N/A"
            info["battery_plugged"] = "N/A"
    except Exception as e:
        info["error"] = str(e)

    return info


def get_cpu_mem_info() -> dict:
    """
    Windows-focused CPU & Memory info.
    Requires: psutil, py-cpuinfo
    Optional (better cache/vendor/clock details): wmi (pip install wmi)
    """

    # --- CPU basic info (cpuinfo is cross-platform; decent on Windows) ---
    cpu_i = {}
    try:
        cpu_i = get_cpu_info() or {}
    except Exception:
        cpu_i = {}

    # Architecture (normalize)
    arch_raw = platform.machine() or ""
    arch = arch_raw
    if arch_raw.lower() in ("amd64", "x86_64"):
        arch = "x64"
    elif "arm" in arch_raw.lower():
        arch = "ARM"

    # Physical vs logical
    physical_cores = psutil.cpu_count(logical=False) or 0
    logical_cores = psutil.cpu_count(logical=True) or 0

    # Current frequency
    freq = None
    try:
        f = psutil.cpu_freq()
        if f:
            freq = {"current_mhz": f.current, "min_mhz": f.min, "max_mhz": f.max}
    except Exception:
        freq = None

    # Utilization (sample once; per-core requires a short interval)
    try:
        cpu_util_total = psutil.cpu_percent(interval=0.2)
    except Exception:
        cpu_util_total = None

    try:
        per_core = psutil.cpu_percent(interval=0.2, percpu=True)
    except Exception:
        per_core = []

    # --- Memory ---
    vm = psutil.virtual_memory()
    sm = psutil.swap_memory()

    # --- Optional: WMI for vendor + caches + nicer CPU name on Windows ---
    wmi_details = {}
    l2_kb = None
    l3_kb = None
    wmi_name = None
    wmi_vendor = None
    wmi_arch = None

    try:
        import wmi  # pip install wmi
        c = wmi.WMI()
        # Win32_Processor is usually one entry even on multi-socket consumer systems
        procs = c.Win32_Processor()
        if procs:
            p0 = procs[0]
            # Common fields: Name, Manufacturer, L2CacheSize, L3CacheSize, CurrentClockSpeed, MaxClockSpeed, Architecture
            wmi_name = getattr(p0, "Name", None)
            wmi_vendor = getattr(p0, "Manufacturer", None)
            l2_kb = getattr(p0, "L2CacheSize", None)
            l3_kb = getattr(p0, "L3CacheSize", None)

            # Architecture codes: 0=x86, 1=MIPS, 2=Alpha, 3=PowerPC, 5=ARM, 6=Itanium, 9=x64 (most common)
            arch_code = getattr(p0, "Architecture", None)
            arch_map = {0: "x86", 5: "ARM", 6: "IA64", 9: "x64"}
            wmi_arch = arch_map.get(arch_code, None)

            wmi_details = {
                "current_clock_mhz": getattr(p0, "CurrentClockSpeed", None),
                "max_clock_mhz": getattr(p0, "MaxClockSpeed", None),
                "processor_id": getattr(p0, "ProcessorId", None),
            }
    except Exception:
        pass

    # Pick best-available CPU name/vendor
    cpu_name = wmi_name or cpu_i.get("brand_raw") or cpu_i.get("brand") or platform.processor() or "Unknown"
    cpu_vendor = wmi_vendor or cpu_i.get("vendor_id_raw") or cpu_i.get("vendor_id") or "Unknown"

    # Cache sizes: WMI gives KB; cpuinfo may give bytes in some fields but is inconsistent across systems
    cache = {
        "l2_kb": int(l2_kb) if isinstance(l2_kb, (int, float, str)) and str(l2_kb).isdigit() else l2_kb,
        "l3_kb": int(l3_kb) if isinstance(l3_kb, (int, float, str)) and str(l3_kb).isdigit() else l3_kb,
    }

    result = {
        "cpu": {
            "name": cpu_name,
            "vendor": cpu_vendor,
            "architecture": wmi_arch or arch,
            "cores_physical": physical_cores,
            "threads_logical": logical_cores,
            "clock": freq,                  # from psutil.cpu_freq()
            "cache": cache,                 # l2/l3 in KB when available
            "utilization_percent": cpu_util_total,
            "per_core_percent": per_core,   # list aligned to logical cores
            "wmi_details": wmi_details,     # optional extra Windows fields
        },
        "memory": {
            "total_bytes": vm.total,
            "available_bytes": vm.available,
            "used_bytes": vm.used,
            "usage_percent": vm.percent,
        },
        "swap": {
            "total_bytes": sm.total,
            "used_bytes": sm.used,
            "free_bytes": sm.free,
            "usage_percent": sm.percent,
        },
    }

    return result


def get_storage_info(sample_interval_sec: float = 1.0) -> Dict[str, Any]:
    """
    Windows-focused storage inventory + usage + I/O + Windows HealthStatus (Get-PhysicalDisk).

    Returns a dict shaped like:
    {
      "platform": "...",
      "drives": [...],
      "disk_io": {...},
      "health": {...},
      "notes": [...]
    }
    """
    result: Dict[str, Any] = {
        "platform": platform.platform(),
        "drives": [],
        "disk_io": {},
        "health": {},
        "notes": []
    }

    try:
        # --- Partitions / mount points ---
        parts = psutil.disk_partitions(all=False)

        for p in parts:
            drive: Dict[str, Any] = {
                "device": p.device,
                "mountpoint": p.mountpoint,
                "fstype": p.fstype,
                "opts": p.opts,
                "usage": None,
            }

            try:
                u = psutil.disk_usage(p.mountpoint)
                drive["usage"] = {
                    "total_bytes": u.total,
                    "used_bytes": u.used,
                    "free_bytes": u.free,
                    "percent": u.percent,
                    "total_gb": _bytes_to_gb(u.total),
                    "used_gb": _bytes_to_gb(u.used),
                    "free_gb": _bytes_to_gb(u.free),
                }
            except Exception as e:
                drive["usage"] = {"error": str(e)}

            result["drives"].append(drive)

        # --- Disk I/O counters and rates ---
        io1 = psutil.disk_io_counters(perdisk=True)
        time.sleep(sample_interval_sec)
        io2 = psutil.disk_io_counters(perdisk=True)

        disk_io: Dict[str, Any] = {}
        for disk, a in io1.items():
            b = io2.get(disk)
            if not b:
                continue

            read_bytes_delta = b.read_bytes - a.read_bytes
            write_bytes_delta = b.write_bytes - a.write_bytes
            read_count_delta = b.read_count - a.read_count
            write_count_delta = b.write_count - a.write_count

            disk_io[disk] = {
                "read_bytes_total": b.read_bytes,
                "write_bytes_total": b.write_bytes,
                "read_count_total": b.read_count,
                "write_count_total": b.write_count,
                "read_time_ms_total": getattr(b, "read_time", None),
                "write_time_ms_total": getattr(b, "write_time", None),

                "read_bytes_per_sec": _bytes_to_mb(int(round(read_bytes_delta / sample_interval_sec, 2))),
                "write_bytes_per_sec": _bytes_to_mb(int(round(write_bytes_delta / sample_interval_sec, 2))),
                "read_ops_per_sec": round(read_count_delta / sample_interval_sec, 2),
                "write_ops_per_sec": round(write_count_delta / sample_interval_sec, 2),
            }

        result["disk_io"] = disk_io

    except Exception as e:
        return {"error": str(e)}

    return result
