from __future__ import annotations
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
import re
import ctypes
import pynvml
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


def get_network_adapters_info() -> Dict[str, Any]:
    """
    Windows-focused:
    - Adapters (name, MAC, IPv4/IPv6, status, speed, MTU)
    - Gateway + DNS servers (via ipconfig)
    - Active TCP/UDP connections (like netstat, via psutil)
    - Bandwidth usage per interface (total bytes/packets via psutil)

    Returns:
    {
      "platform": "...",
      "adapters": [...],
      "default_gateway": "...|None",
      "dns_servers": [...],
      "connections": {"tcp": [...], "udp": [...], "counts": {...}},
      "bandwidth": {"per_interface": {...}, "totals": {...}},
      "notes": [...]
    }
    """
    result: Dict[str, Any] = {
        "platform": platform.platform(),
        "adapters": [],
        "default_gateway": None,
        "dns_servers": [],
        "connections": {"tcp": [], "udp": [], "counts": {}},
        "bandwidth": {"per_interface": {}, "totals": {}},
        "notes": [],
    }

    try:
        # --- Adapter addresses (MAC/IP) ---
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        def _is_mac_family(fam) -> bool:
            # psutil uses AF_LINK on Unix; on Windows it may expose a numeric family.
            return (
                fam == getattr(psutil, "AF_LINK", object())
                or fam == getattr(socket, "AF_LINK", -1)
                or str(fam).upper().endswith("AF_LINK")
            )

        for if_name, addr_list in addrs.items():
            mac: Optional[str] = None
            ipv4: List[Dict[str, Any]] = []
            ipv6: List[Dict[str, Any]] = []

            for a in addr_list:
                if _is_mac_family(a.family) or a.family == getattr(socket, "AF_PACKET", -999):
                    if a.address and a.address != "00:00:00:00:00:00":
                        mac = a.address
                elif a.family == socket.AF_INET:
                    ipv4.append(
                        {
                            "ip": a.address,
                            "netmask": a.netmask,
                            "broadcast": getattr(a, "broadcast", None),
                        }
                    )
                elif a.family == socket.AF_INET6:
                    ipv6.append(
                        {
                            "ip": a.address,
                            "netmask": a.netmask,
                            "scope_id": getattr(a, "scope_id", None),
                        }
                    )

            st = stats.get(if_name)
            adapter = {
                "name": if_name,
                "mac": mac,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "is_up": st.isup if st else None,
                "speed_mbps": st.speed if st else None,  # may be 0 / None on some adapters
                "mtu": st.mtu if st else None,
                "duplex": str(st.duplex) if st else None,
            }
            result["adapters"].append(adapter)

        # --- Gateway + DNS servers (Windows ipconfig parsing) ---
        gw, dns = _parse_ipconfig_gateway_dns()
        result["default_gateway"] = gw
        result["dns_servers"] = dns

        # --- Active connections (psutil) ---
        tcp_list: List[Dict[str, Any]] = []
        udp_list: List[Dict[str, Any]] = []

        # This can require admin for full info on some systems; handle partial failures.
        try:
            conns = psutil.net_connections(kind="all")
        except Exception as e:
            result["notes"].append(f"Connections: psutil.net_connections failed: {e}")
            conns = []

        for c in conns:
            laddr = _fmt_addr(c.laddr)
            raddr = _fmt_addr(c.raddr) if c.raddr else None
            entry = {
                "type": c.type,  # numeric
                "family": c.family,  # numeric
                "status": getattr(c, "status", None),
                "local_address": laddr,
                "remote_address": raddr,
                "pid": c.pid,
            }

            if c.type == socket.SOCK_STREAM:
                tcp_list.append(entry)
            elif c.type == socket.SOCK_DGRAM:
                udp_list.append(entry)

        result["connections"]["tcp"] = tcp_list
        result["connections"]["udp"] = udp_list
        result["connections"]["counts"] = {
            "tcp": len(tcp_list),
            "udp": len(udp_list),
            "all": len(tcp_list) + len(udp_list),
        }

        # --- Bandwidth usage per interface (cumulative counters since boot) ---
        io = psutil.net_io_counters(pernic=True)
        per_if: Dict[str, Any] = {}
        totals = {
            "bytes_sent": 0,
            "bytes_recv": 0,
            "packets_sent": 0,
            "packets_recv": 0,
            "errin": 0,
            "errout": 0,
            "dropin": 0,
            "dropout": 0,
        }

        for if_name, ctr in io.items():
            per_if[if_name] = {
                "bytes_sent": ctr.bytes_sent,
                "bytes_recv": ctr.bytes_recv,
                "packets_sent": ctr.packets_sent,
                "packets_recv": ctr.packets_recv,
                "errin": ctr.errin,
                "errout": ctr.errout,
                "dropin": ctr.dropin,
                "dropout": ctr.dropout,
            }
            totals["bytes_sent"] += ctr.bytes_sent
            totals["bytes_recv"] += ctr.bytes_recv
            totals["packets_sent"] += ctr.packets_sent
            totals["packets_recv"] += ctr.packets_recv
            totals["errin"] += ctr.errin
            totals["errout"] += ctr.errout
            totals["dropin"] += ctr.dropin
            totals["dropout"] += ctr.dropout

        result["bandwidth"]["per_interface"] = per_if
        result["bandwidth"]["totals"] = totals

    except Exception as e:
        return {"error": str(e)}

    return result


def _fmt_addr(addr_obj) -> Optional[str]:
    if not addr_obj:
        return None
    try:
        ip = addr_obj.ip
        port = addr_obj.port
        return f"{ip}:{port}"
    except Exception:
        # sometimes it's already a tuple
        try:
            return f"{addr_obj[0]}:{addr_obj[1]}"
        except Exception:
            return str(addr_obj)


def _run_cmd(cmd: List[str], timeout: int = 8) -> Dict[str, Any]:
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return {"ok": p.returncode == 0, "stdout": p.stdout or "", "stderr": p.stderr or "", "code": p.returncode}
    except Exception as e:
        return {"ok": False, "stdout": "", "stderr": str(e), "code": None}


def _parse_ipconfig_gateway_dns(timeout: int = 8) -> (Optional[str], List[str]):
    """
    Parses Windows 'ipconfig /all' to extract:
    - Default gateway (first IPv4-ish gateway seen)
    - DNS servers (list, preserves order)
    """
    out = _run_cmd(["ipconfig", "/all"], timeout=timeout)
    if not out["ok"] and not out["stdout"]:
        return None, []

    text = out["stdout"]
    gateway: Optional[str] = None
    dns_servers: List[str] = []

    # Robust-ish parsing: handle multi-line gateway/DNS lists
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()

        # Default Gateway . . . . . . . . . :
        if "Default Gateway" in line:
            # value may be after colon or on subsequent indented lines
            val = line.split(":", 1)[-1].strip()
            if not val:
                j = i + 1
                while j < len(lines):
                    nxt = lines[j].strip()
                    if not nxt:
                        break
                    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", nxt):
                        val = nxt
                        break
                    j += 1
            if val and not gateway and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", val):
                gateway = val

        # DNS Servers . . . . . . . . . . . :
        if "DNS Servers" in line:
            val = line.split(":", 1)[-1].strip()
            if val and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", val):
                dns_servers.append(val)

            # consume subsequent indented lines that are IPs
            j = i + 1
            while j < len(lines):
                nxt = lines[j].strip()
                if not nxt:
                    break
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", nxt):
                    dns_servers.append(nxt)
                    j += 1
                    continue
                # stop when next key starts (not indented IP)
                break

        i += 1

    # de-dup while preserving order
    seen = set()
    dns_unique = []
    for d in dns_servers:
        if d not in seen:
            seen.add(d)
            dns_unique.append(d)

    return gateway, dns_unique


# --- Helpers ---------------------------------------------------------------
def _run_powershell_json(ps_script: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Runs a PowerShell script and forces JSON output. Returns dict with ok/stdout/stderr/error.
    """
    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command",
        ps_script
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if p.returncode != 0:
            return {"ok": False, "stdout": p.stdout, "stderr": p.stderr, "error": f"PowerShell exit {p.returncode}"}
        return {"ok": True, "stdout": p.stdout.strip(), "stderr": p.stderr.strip(), "error": None}
    except Exception as e:
        return {"ok": False, "stdout": "", "stderr": "", "error": str(e)}


def _parse_wmi_cim_datetime(dt: Optional[str]) -> str:
    """
    Converts WMI/CIM datetime like '20251029000000.000000-000' into '2025-10-29'.
    If missing/invalid returns 'Unknown'.
    """
    if not dt or not isinstance(dt, str):
        return dt
    # dt begins with YYYYMMDD...
    m = re.match(r"^(\d{4})(\d{2})(\d{2})", dt)
    if not m:
        return dt
    y, mo, d = m.group(1), m.group(2), m.group(3)
    return f"{y}-{mo}-{d}"


def _normalize_vendor(name: str, adapter_compat: str = "") -> str:
    s = f"{name} {adapter_compat}".lower()
    if "nvidia" in s:
        return "NVIDIA"
    if "amd" in s or "radeon" in s:
        return "AMD"
    if "intel" in s:
        return "Intel"
    if "microsoft" in s:
        return "Microsoft"
    return "Unknown"


def _is_junk_gpu(name: str, pnp_id: str = "", adapter_compat: str = "") -> bool:
    """
    Filters out typical Windows non-physical/undesirable entries.
    Adjust rules as you like.
    """
    s = f"{name} {pnp_id} {adapter_compat}".lower()

    junk_phrases = [
        "microsoft basic display",
        "microsoft basic render",
        "microsoft remote display",
        "remote display",
        "citrix",
        "vmware",
        "virtual",
        "hyper-v",
        "mirror",
        "miracast",
        "rdp",
    ]
    if any(j in s for j in junk_phrases):
        return True

    # If name is empty/unknown, treat as junk
    if not name or name.strip().lower() in {"unknown", "n/a"}:
        return True

    return False


def _safe_int(v: Any) -> Optional[int]:
    try:
        if v is None:
            return None
        return int(v)
    except:
        return None


def _bytes_to_mb(b: Optional[int]) -> Optional[float]:
    if b is None:
        return None
    try:
        return round(b / (1024 * 1024), 1)
    except:
        return None


def _display_info_primary() -> Dict[str, Any]:
    """
    Basic display info (primary display resolution, refresh rate).
    Resolution: reliable.
    Refresh rate: uses EnumDisplaySettings on Windows (no extra deps).
    """
    user32 = ctypes.windll.user32
    width = user32.GetSystemMetrics(0)
    height = user32.GetSystemMetrics(1)

    refresh_hz: Optional[int] = None
    try:
        class DEVMODE(ctypes.Structure):
            _fields_ = [
                ("dmDeviceName", ctypes.c_wchar * 32),
                ("dmSpecVersion", ctypes.c_ushort),
                ("dmDriverVersion", ctypes.c_ushort),
                ("dmSize", ctypes.c_ushort),
                ("dmDriverExtra", ctypes.c_ushort),
                ("dmFields", ctypes.c_ulong),
                ("dmOrientation", ctypes.c_short),
                ("dmPaperSize", ctypes.c_short),
                ("dmPaperLength", ctypes.c_short),
                ("dmPaperWidth", ctypes.c_short),
                ("dmScale", ctypes.c_short),
                ("dmCopies", ctypes.c_short),
                ("dmDefaultSource", ctypes.c_short),
                ("dmPrintQuality", ctypes.c_short),
                ("dmColor", ctypes.c_short),
                ("dmDuplex", ctypes.c_short),
                ("dmYResolution", ctypes.c_short),
                ("dmTTOption", ctypes.c_short),
                ("dmCollate", ctypes.c_short),
                ("dmFormName", ctypes.c_wchar * 32),
                ("dmLogPixels", ctypes.c_ushort),
                ("dmBitsPerPel", ctypes.c_ulong),
                ("dmPelsWidth", ctypes.c_ulong),
                ("dmPelsHeight", ctypes.c_ulong),
                ("dmDisplayFlags", ctypes.c_ulong),
                ("dmDisplayFrequency", ctypes.c_ulong),
                ("dmICMMethod", ctypes.c_ulong),
                ("dmICMIntent", ctypes.c_ulong),
                ("dmMediaType", ctypes.c_ulong),
                ("dmDitherType", ctypes.c_ulong),
                ("dmReserved1", ctypes.c_ulong),
                ("dmReserved2", ctypes.c_ulong),
                ("dmPanningWidth", ctypes.c_ulong),
                ("dmPanningHeight", ctypes.c_ulong),
            ]

        ENUM_CURRENT_SETTINGS = -1
        devmode = DEVMODE()
        devmode.dmSize = ctypes.sizeof(DEVMODE)

        # EnumDisplaySettingsW(None, ENUM_CURRENT_SETTINGS, &devmode)
        if ctypes.windll.user32.EnumDisplaySettingsW(None, ENUM_CURRENT_SETTINGS, ctypes.byref(devmode)):
            refresh_hz = int(devmode.dmDisplayFrequency) if devmode.dmDisplayFrequency else None
    except Exception:
        refresh_hz = None

    return {
        "primary_resolution": f"{width}x{height}",
        "width": int(width),
        "height": int(height),
        "refresh_rate_hz": refresh_hz,
    }


# --- Main ------------------------------------------------------------------
def get_gpu_display_info() -> Dict[str, Any]:
    """
    Windows-focused GPU + display info.

    What you get reliably without vendor APIs:
      - GPU name
      - Vendor (heuristic)
      - Driver version
      - Driver date (parsed)
      - VRAM total (sometimes, via AdapterRAM)

    What you do NOT get reliably without vendor APIs:
      - VRAM used
      - GPU utilization

    Returns:
    {
      "gpus": [
        {
          "name": "...",
          "vendor": "...",
          "driver_version": "...",
          "driver_date": "YYYY-MM-DD",
          "vram_total_mb": 0.0 or None,
          "vram_used_mb": None,
          "gpu_util_percent": None
        },
        ...
      ],
      "display": {...},
      "nvidia": {...},
      "notes": [...]
    }
    """
    result: Dict[str, Any] = {"gpus": [], "display": {}, "nvidia": {}, "notes": []}

    # ---- GPU inventory via CIM (better than wmic) --------------------------
    # Note: Some systems require admin for certain properties; this stays best-effort.
    ps = r"""
$ErrorActionPreference = 'Stop'
$gpus = Get-CimInstance Win32_VideoController |
    Select-Object Name, AdapterCompatibility, DriverVersion, DriverDate, AdapterRAM, PNPDeviceID, VideoProcessor
$gpus | ConvertTo-Json -Depth 4
"""
    r0 = _run_powershell_json(ps, timeout=12)
    if not r0.get("ok"):
        result["notes"].append(f"GPU inventory lookup failed: {r0.get('error') or r0.get('stderr')}")
        return result

    try:
        data = json.loads(r0["stdout"]) if r0["stdout"] else []
        if isinstance(data, dict):
            data = [data]
    except Exception as e:
        result["notes"].append(f"GPU inventory JSON parse failed: {e}")
        return result

    seen_names: set[str] = set()
    cleaned: List[Dict[str, Any]] = []

    for g in data:
        name = (g.get("Name") or "").strip()
        pnp = (g.get("PNPDeviceID") or "").strip()
        compat = (g.get("AdapterCompatibility") or "").strip()

        if _is_junk_gpu(name, pnp_id=pnp, adapter_compat=compat):
            continue

        # Deduplicate by name (common duplication issue)
        key = name.lower()
        if key in seen_names:
            continue
        seen_names.add(key)

        adapter_ram = _safe_int(g.get("AdapterRAM"))
        vram_mb = _bytes_to_mb(adapter_ram)

        cleaned.append({
            "name": name or "Unknown",
            "vendor": _normalize_vendor(name, compat),
            "driver_version": (g.get("DriverVersion") or "Unknown"),
            "driver_date": _parse_wmi_cim_datetime(g.get("DriverDate")),
            "vram_total_mb": vram_mb,          # may be None
            "vram_used_mb": None,              # filled only if vendor API available
            "gpu_util_percent": None,          # filled only if vendor API available
        })

    # If everything got filtered out, fall back to a non-filtered minimal list (but still dedupe empties)
    if not cleaned:
        result["notes"].append("All GPU entries were filtered as virtual/unknown; showing unfiltered entries.")
        seen_names.clear()
        for g in data:
            name = (g.get("Name") or "").strip() or "Unknown"
            key = name.lower()
            if key in seen_names:
                continue
            seen_names.add(key)

            adapter_ram = _safe_int(g.get("AdapterRAM"))
            vram_mb = _bytes_to_mb(adapter_ram)

            cleaned.append({
                "name": name,
                "vendor": _normalize_vendor(name, (g.get("AdapterCompatibility") or "")),
                "driver_version": (g.get("DriverVersion") or "Unknown"),
                "driver_date": _parse_wmi_cim_datetime(g.get("DriverDate")),
                "vram_total_mb": vram_mb,
                "vram_used_mb": None,
                "gpu_util_percent": None,
            })

    result["gpus"] = cleaned

    # ---- Display info (resolution / refresh rate) --------------------------
    # Display info
    result["display"] = _display_info_primary()

    # ---- NVIDIA live stats (optional) -------------------------------------
    # Only works if pynvml installed; this fills vram_used_mb + gpu_util_percent for NVIDIA GPUs.
    try:
        pynvml.nvmlInit()
        n = pynvml.nvmlDeviceGetCount()
        nvidia_cards = []
        for i in range(n):
            h = pynvml.nvmlDeviceGetHandleByIndex(i)
            name = pynvml.nvmlDeviceGetName(h)
            mem = pynvml.nvmlDeviceGetMemoryInfo(h)  # total/used/free in bytes
            util = pynvml.nvmlDeviceGetUtilizationRates(h)

            nvidia_cards.append({
                "index": i,
                "name": name.decode(errors="ignore") if isinstance(name, (bytes, bytearray)) else str(name),
                "vram_total_mb": round(mem.total / (1024 * 1024), 1),
                "vram_used_mb": round(mem.used / (1024 * 1024), 1),
                "vram_free_mb": round(mem.free / (1024 * 1024), 1),
                "gpu_util_percent": getattr(util, "gpu", None),
                "mem_util_percent": getattr(util, "memory", None),
            })

        result["nvidia"] = {"ok": True, "gpus": nvidia_cards}

        # Merge NVML stats into main list by best-effort name match
        for inv in result["gpus"]:
            if inv.get("vendor") != "NVIDIA":
                continue
            inv_name = (inv.get("name") or "").lower()
            for nv in nvidia_cards:
                nv_name = (nv.get("name") or "").lower()
                if inv_name and (inv_name in nv_name or nv_name in inv_name):
                    inv["vram_total_mb"] = inv.get("vram_total_mb") or nv.get("vram_total_mb")
                    inv["vram_used_mb"] = nv.get("vram_used_mb")
                    inv["gpu_util_percent"] = nv.get("gpu_util_percent")
                    break

    except Exception as e:
        result["nvidia"] = {"ok": False, "error": str(e)}
        result["notes"].append("NVIDIA stats unavailable: install pynvml (nvidia-ml-py) to enable utilization/VRAM used.")

    return result

