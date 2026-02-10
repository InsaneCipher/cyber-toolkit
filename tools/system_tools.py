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
import winreg


def _bytes_to_gb(n: int) -> float:
    return round(n / (1024 ** 3), 2)


def _bytes_to_mb(n: int) -> float:
    return round(n / (1024 ** 2), 2)


def get_system_info():
    print("Getting System Information...")
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
    print("Getting CPU Memory Information...")

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
    print("Getting Storage Information...")

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
    print("Getting Network Adapters Information...")

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


def get_gpu_display_info() -> Dict[str, Any]:
    print("Getting GPU And Display Information...")

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


def get_power_battery_info() -> Dict[str, Any]:
    print("Getting Power Information...")

    result = {
        "has_battery": False,
        "power_source": "Unknown",
        "battery_percent": None,
        "status": "Unknown",
        "time_remaining": "Unknown",
        "seconds_remaining": None,
        "notes": []
    }

    try:
        batt = psutil.sensors_battery()
        if batt is None:
            result["notes"].append("No battery detected (desktop system or unsupported hardware).")
            return result

        result["has_battery"] = True
        result["battery_percent"] = round(batt.percent, 1) if batt.percent is not None else None

        # Power source
        if batt.power_plugged:
            result["power_source"] = "AC"
        else:
            result["power_source"] = "Battery"

        # Status
        if batt.power_plugged and batt.percent == 100:
            result["status"] = "Full"
        elif batt.power_plugged:
            result["status"] = "Charging"
        else:
            result["status"] = "Discharging"

        # Time remaining
        if batt.secsleft == psutil.POWER_TIME_UNLIMITED:
            result["time_remaining"] = "Unlimited"
            result["seconds_remaining"] = None
        elif batt.secsleft == psutil.POWER_TIME_UNKNOWN:
            result["time_remaining"] = "Unknown"
            result["seconds_remaining"] = None
        else:
            result["seconds_remaining"] = batt.secsleft
            mins, secs = divmod(batt.secsleft, 60)
            hours, mins = divmod(mins, 60)
            result["time_remaining"] = f"{hours:d}:{mins:02d}"

    except Exception as e:
        result["notes"].append(f"Battery lookup failed: {e}")

    return result


# Currently Not In Use
def get_sensors_and_temps() -> Dict[str, Any]:
    print("Getting Sensors and Temperature Information...")

    # Helper
    def _run_powershell_json(ps_script: str, timeout: int = 8) -> Dict[str, Any]:
        """
        Runs a PowerShell script and returns parsed JSON.
        Returns {"ok": True, "data": ...} or {"ok": False, "error": "...", "stdout": "...", "stderr": "..."}.
        """
        cmd = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            ps_script,
        ]
        try:
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if cp.returncode != 0:
                return {"ok": False, "error": f"PowerShell failed (code {cp.returncode})", "stdout": cp.stdout,
                        "stderr": cp.stderr}
            out = (cp.stdout or "").strip()
            if not out:
                return {"ok": False, "error": "PowerShell returned empty output", "stdout": cp.stdout,
                        "stderr": cp.stderr}
            return {"ok": True, "data": json.loads(out)}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    result: Dict[str, Any] = {
        "available": False,
        "cpu_temps_c": [],
        "gpu_temps_c": [],
        "system_temps_c": [],
        "fan_speeds_rpm": [],
        "notes": [],
        "errors": [],
    }

    # OpenHardwareMonitor publishes sensors under WMI if it's running.
    # We query all sensors, then categorize by SensorType + Name/Parent.
    ps = r"""
        $ErrorActionPreference = 'Stop'
        
        # Detect whether the WMI namespace exists
        $nsOk = Get-CimInstance -Namespace root -ClassName __NAMESPACE -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'OpenHardwareMonitor' }
        if (-not $nsOk) {
          @{ available = $false; error = 'OpenHardwareMonitor WMI namespace not found (root\OpenHardwareMonitor). Start OpenHardwareMonitor with WMI enabled.' } | ConvertTo-Json -Depth 6
          exit
        }
        
        $sensors = Get-CimInstance -Namespace root\OpenHardwareMonitor -ClassName Sensor |
          Select-Object Name, SensorType, Value, Parent
        
        @{
          available = $true
          sensors = $sensors
        } | ConvertTo-Json -Depth 6
    """
    payload = _run_powershell_json(ps, timeout=10)
    if not payload.get("ok"):
        result["errors"].append(payload.get("error", "Unknown error running PowerShell"))
        return result

    data = payload.get("data", {})
    if not data.get("available"):
        result["errors"].append(data.get("error", "Sensors not available"))
        return result

    result["available"] = True
    sensors = data.get("sensors") or []
    if isinstance(sensors, dict):
        sensors = [sensors]  # in case WMI returns a single object

    # Helper: categorize by keywords
    def _parent_hint(s: Dict[str, Any]) -> str:
        p = (s.get("Parent") or "")
        n = (s.get("Name") or "")
        blob = f"{p} {n}".lower()
        return blob

    for s in sensors:
        try:
            stype = (s.get("SensorType") or "").lower()
            name = s.get("Name") or "Unknown"
            val = s.get("Value", None)

            # Skip null values
            if val is None:
                continue

            hint = _parent_hint(s)

            if stype == "temperature":
                entry = {"name": name, "value": float(val)}
                # Heuristics to classify CPU/GPU/System temps
                if "cpu" in hint:
                    result["cpu_temps_c"].append(entry)
                elif "gpu" in hint or "nvidia" in hint or "radeon" in hint or "intel" in hint and "graphics" in hint:
                    result["gpu_temps_c"].append(entry)
                else:
                    result["system_temps_c"].append(entry)

            elif stype == "fan":
                result["fan_speeds_rpm"].append({"name": name, "value": float(val)})

        except Exception as e:
            result["notes"].append(f"Skipped a sensor due to parse error: {e}")

    # Sort for stable display
    result["cpu_temps_c"].sort(key=lambda x: x["name"])
    result["gpu_temps_c"].sort(key=lambda x: x["name"])
    result["system_temps_c"].sort(key=lambda x: x["name"])
    result["fan_speeds_rpm"].sort(key=lambda x: x["name"])

    if not (result["cpu_temps_c"] or result["gpu_temps_c"] or result["system_temps_c"] or result["fan_speeds_rpm"]):
        result["notes"].append("No sensor values returned. Ensure OHM is running and sensors are supported on this device.")

    return result


def get_processes_services_info(top_n: int = 200, include_cmdline: bool = True, include_services: bool = True, ) -> Dict[str, Any]:
    print("Getting Processes And Services Information...")

    # Helpers
    def _fmt_bytes(num: float) -> str:
        step = 1024.0
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if num < step:
                return f"{num:.1f} {unit}"
            num /= step
        return f"{num:.1f} PB"

    def _fmt_dt(ts: Optional[float]) -> Optional[str]:
        if not ts:
            return None
        try:
            return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return None

    result: Dict[str, Any] = {
        "processes": [],
        "processes_count": 0,
        "services": [],
        "services_count": 0,
        "notes": [],
    }

    # --- Processes ---
    try:
        # 1st pass: prime cpu_percent (returns 0.0 on first call)
        procs = []
        for p in psutil.process_iter(attrs=["pid", "name"]):
            try:
                p.cpu_percent(interval=None)
                procs.append(p)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # 2nd pass: collect details with a fast non-blocking cpu_percent sample
        # (Still approximate; to be "real-time" you'd sample with interval>0 or run async.)
        for p in procs:
            try:
                info = p.as_dict(attrs=[
                    "pid",
                    "name",
                    "username",
                    "cpu_percent",
                    "memory_percent",
                    "memory_info",
                    "create_time",
                    "cmdline",
                ])
                mem_info = info.get("memory_info")
                rss = getattr(mem_info, "rss", None)

                proc_item = {
                    "pid": info.get("pid"),
                    "name": info.get("name") or "",
                    "user": info.get("username") or "N/A",
                    "cpu_percent": float(info.get("cpu_percent") or 0.0),
                    "ram_percent": float(info.get("memory_percent") or 0.0),
                    "ram_rss": _fmt_bytes(rss) if rss is not None else None,
                    "start_time": _fmt_dt(info.get("create_time")),
                    "cmdline": " ".join(info.get("cmdline") or []) if include_cmdline else None,
                }
                result["processes"].append(proc_item)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                # keep going; don't fail whole page
                result["notes"].append(f"Process read error: {e}")

        # Sort by CPU then RAM, and cap to top_n
        result["processes"].sort(
            key=lambda x: (x.get("cpu_percent", 0.0), x.get("ram_percent", 0.0)),
            reverse=True,
        )
        if top_n and len(result["processes"]) > top_n:
            result["processes"] = result["processes"][:top_n]

        result["processes_count"] = len(result["processes"])
    except Exception as e:
        result["notes"].append(f"Process scan failed: {e}")

    # --- Services (Windows) ---
    if include_services:
        if wmi is None:
            result["notes"].append("Services: WMI package not installed (pip install wmi). Services list will be empty.")
        else:
            try:
                c = wmi.WMI()
                services: List[Dict[str, Any]] = []

                for s in c.Win32_Service():
                    services.append({
                        "name": s.Name,
                        "display_name": s.DisplayName,
                        "state": s.State,          # Running / Stopped
                        "start_mode": s.StartMode, # Auto / Manual / Disabled
                        "pid": s.ProcessId if getattr(s, "ProcessId", None) else None,
                    })

                # optional: sort running services first
                services.sort(key=lambda x: (x["state"] != "Running", x["name"]))
                result["services"] = services
                result["services_count"] = len(services)
            except Exception as e:
                result["notes"].append(f"Services scan failed: {e}")

    return result


def get_bios_motherboard_info() -> Dict[str, Any]:
    print("Getting Bios And Motherboard Info...")

    # Map Win32_SystemEnclosure.ChassisTypes codes to friendly names (partial but useful)
    chassis_type_map = {
        1: "Other",
        2: "Unknown",
        3: "Desktop",
        4: "Low Profile Desktop",
        5: "Pizza Box",
        6: "Mini Tower",
        7: "Tower",
        8: "Portable",
        9: "Laptop",
        10: "Notebook",
        11: "Hand Held",
        12: "Docking Station",
        13: "All in One",
        14: "Sub Notebook",
        15: "Space-Saving",
        16: "Lunch Box",
        17: "Main System Chassis",
        18: "Expansion Chassis",
        19: "SubChassis",
        20: "Bus Expansion Chassis",
        21: "Peripheral Chassis",
        22: "Storage Chassis",
        23: "Rack Mount Chassis",
        24: "Sealed-Case PC",
        30: "Tablet",
        31: "Convertible",
        32: "Detachable",
    }

    def _wmi_date_to_iso(dtm: str | None) -> str | None:
        """
        WMI dates often look like: YYYYMMDDHHMMSS.mmmmmmsUUU
        Example: 20240115000000.000000+000
        """
        if not dtm or len(dtm) < 8:
            return None
        y, m, d = dtm[0:4], dtm[4:6], dtm[6:8]
        return f"{y}-{m}-{d}"

    try:
        c = wmi.WMI()

        # Motherboard
        mb = {}
        boards = c.Win32_BaseBoard()
        if boards:
            b = boards[0]
            mb = {
                "manufacturer": getattr(b, "Manufacturer", None),
                "model": getattr(b, "Model", None),
                "product": getattr(b, "Product", None),
                "serial": getattr(b, "SerialNumber", None),
                "version": getattr(b, "Version", None),
            }

        # BIOS
        bios = {}
        bios_list = c.Win32_BIOS()
        if bios_list:
            b = bios_list[0]
            bios = {
                "vendor": getattr(b, "Manufacturer", None),
                "version": getattr(b, "SMBIOSBIOSVersion", None) or getattr(b, "Version", None),
                "release_date": _wmi_date_to_iso(getattr(b, "ReleaseDate", None)),
                "serial": getattr(b, "SerialNumber", None),
            }

        # System UUID + model/manufacturer (ComputerSystemProduct has UUID)
        sysinfo = {}
        cs_products = c.Win32_ComputerSystemProduct()
        if cs_products:
            p = cs_products[0]
            sysinfo = {
                "uuid": getattr(p, "UUID", None),
                "vendor": getattr(p, "Vendor", None),
                "name": getattr(p, "Name", None),
                "version": getattr(p, "Version", None),
                "identifying_number": getattr(p, "IdentifyingNumber", None),
            }
        else:
            # Fallback: manufacturer/model from Win32_ComputerSystem (no UUID)
            cs = c.Win32_ComputerSystem()
            if cs:
                s = cs[0]
                sysinfo = {
                    "uuid": None,
                    "vendor": getattr(s, "Manufacturer", None),
                    "name": getattr(s, "Model", None),
                    "version": None,
                    "identifying_number": None,
                }

        # Chassis / enclosure
        chassis = {}
        enclosures = c.Win32_SystemEnclosure()
        if enclosures:
            e = enclosures[0]
            types = getattr(e, "ChassisTypes", None) or []
            type_code = types[0] if types else None
            chassis = {
                "type_code": type_code,
                "type_name": chassis_type_map.get(type_code, "Unknown") if type_code is not None else None,
                "serial": getattr(e, "SerialNumber", None),
                "asset_tag": getattr(e, "SMBIOSAssetTag", None),
                "manufacturer": getattr(e, "Manufacturer", None),
            }

        return {
            "motherboard": mb,
            "bios": bios,
            "system": sysinfo,
            "chassis": chassis,
        }

    except Exception as e:
        return {"error": str(e)}


def get_connected_devices_info() -> Dict[str, Any]:
    print("Getting Connected Devices Info...")
    result: Dict[str, Any] = {
        "usb_devices": [],
        "pnp_devices": [],
        "monitors": [],
        "hid_devices": [],
        "disk_drives": [],
        "logical_drives": [],
        "notes": [],
    }

    try:
        c = wmi.WMI()

        # --- USB Controllers / Hubs (not each USB device, but useful context)
        try:
            for u in c.Win32_USBController():
                result["usb_devices"].append({
                    "name": getattr(u, "Name", None),
                    "device_id": getattr(u, "DeviceID", None),
                    "manufacturer": getattr(u, "Manufacturer", None),
                    "pnp_device_id": getattr(u, "PNPDeviceID", None),
                    "status": getattr(u, "Status", None),
                })
        except Exception as e:
            result["notes"].append(f"USB controller query failed: {e}")

        # --- General Plug-and-Play devices (includes lots of devices)
        # Use this for "connected devices" overall. You can filter/limit in UI.
        try:
            for d in c.Win32_PnPEntity():
                result["pnp_devices"].append({
                    "name": getattr(d, "Name", None),
                    "device_id": getattr(d, "DeviceID", None),
                    "pnp_class": getattr(d, "PNPClass", None),
                    "manufacturer": getattr(d, "Manufacturer", None),
                    "status": getattr(d, "Status", None),
                })
        except Exception as e:
            result["notes"].append(f"PnP devices query failed: {e}")

        # --- Monitors
        try:
            for m in c.Win32_DesktopMonitor():
                result["monitors"].append({
                    "name": getattr(m, "Name", None),
                    "device_id": getattr(m, "DeviceID", None),
                    "monitor_type": getattr(m, "MonitorType", None),
                    "screen_height": getattr(m, "ScreenHeight", None),
                    "screen_width": getattr(m, "ScreenWidth", None),
                    "status": getattr(m, "Status", None),
                })
        except Exception as e:
            result["notes"].append(f"Monitor query failed: {e}")

        # --- HID devices (keyboards, mice, gamepads, etc.)
        # Win32_PnPEntity already contains them; this is a filtered view.
        try:
            for d in c.Win32_PnPEntity():
                pnp_class = (getattr(d, "PNPClass", "") or "").lower()
                name = getattr(d, "Name", "") or ""
                if pnp_class == "hidclass" or "hid" in name.lower():
                    result["hid_devices"].append({
                        "name": getattr(d, "Name", None),
                        "device_id": getattr(d, "DeviceID", None),
                        "manufacturer": getattr(d, "Manufacturer", None),
                        "status": getattr(d, "Status", None),
                    })
        except Exception as e:
            result["notes"].append(f"HID query failed: {e}")

        # --- Physical disk drives (captures USB external drives too)
        try:
            for dd in c.Win32_DiskDrive():
                # InterfaceType often: IDE/SCSI/USB, MediaType can help too.
                result["disk_drives"].append({
                    "model": getattr(dd, "Model", None),
                    "device_id": getattr(dd, "DeviceID", None),
                    "interface_type": getattr(dd, "InterfaceType", None),
                    "media_type": getattr(dd, "MediaType", None),
                    "serial": getattr(dd, "SerialNumber", None),
                    "size_bytes": int(getattr(dd, "Size", 0) or 0),
                    "status": getattr(dd, "Status", None),
                })
        except Exception as e:
            result["notes"].append(f"DiskDrive query failed: {e}")

        # --- Logical drives (C:, D:, removable media, mapped drives)
        try:
            for ld in c.Win32_LogicalDisk():
                mount = getattr(ld, "DeviceID", None)  # e.g. "C:"
                drive_type = getattr(ld, "DriveType", None)  # 2 removable, 3 local, 4 network, 5 CD-ROM
                entry: Dict[str, Any] = {
                    "device_id": mount,
                    "volume_name": getattr(ld, "VolumeName", None),
                    "file_system": getattr(ld, "FileSystem", None),
                    "drive_type": drive_type,
                    "size_bytes": int(getattr(ld, "Size", 0) or 0),
                    "free_bytes": int(getattr(ld, "FreeSpace", 0) or 0),
                }

                # add usage percentage via psutil if possible
                try:
                    if mount:
                        u = psutil.disk_usage(mount + "\\")
                        entry["used_bytes"] = u.used
                        entry["percent_used"] = u.percent
                except Exception:
                    pass

                result["logical_drives"].append(entry)
        except Exception as e:
            result["notes"].append(f"LogicalDisk query failed: {e}")

    except Exception as e:
        return {"error": str(e)}

    # Helpful note: "PCI devices" as a separate category isn’t directly exposed as lspci on Windows.
    # Win32_PnPEntity covers PCI/USB/etc. You can filter by PNPDeviceID starting with "PCI\\"
    # in the UI or in a separate view if you want.
    return result


def get_installed_software() -> Dict[str, Any]:
    print("Getting Installed Software Information...")

    # Helpers
    def _read_reg_value(_key, name: str) -> Optional[str]:
        try:
            val, _typ = winreg.QueryValueEx(_key, name)
            if val is None:
                return None
            if isinstance(val, (list, tuple)):
                return ", ".join(str(x) for x in val)
            return str(val)
        except OSError:
            return None

    def _norm_install_date(raw: Optional[str]) -> Optional[str]:
        """
        Typical registry format: 'YYYYMMDD'. Convert to 'YYYY-MM-DD' when possible.
        If it's already something else, return as-is.
        """
        if not raw:
            return None
        s = raw.strip()
        m = re.fullmatch(r"(\d{4})(\d{2})(\d{2})", s)
        if m:
            return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
        return s

    results: List[Dict[str, Any]] = []
    notes: List[str] = []

    # (root_key, path, source_label)
    uninstall_roots = [
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM_64",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM_32",
        ),
        (
            winreg.HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKCU",
        ),
    ]

    for root, path, source in uninstall_roots:
        try:
            with winreg.OpenKey(root, path) as uninstall_key:
                subkey_count, _val_count, _last_write = winreg.QueryInfoKey(uninstall_key)

                for i in range(subkey_count):
                    try:
                        sub_name = winreg.EnumKey(uninstall_key, i)
                        with winreg.OpenKey(uninstall_key, sub_name) as app_key:
                            display_name = _read_reg_value(app_key, "DisplayName")
                            if not display_name:
                                continue  # skip entries without an app name

                            # Filter out some noise (optional, but helps)
                            system_component = _read_reg_value(app_key, "SystemComponent")
                            parent_key = _read_reg_value(app_key, "ParentKeyName")
                            if system_component == "1" or parent_key:
                                # Many Windows components / patches
                                continue

                            app = {
                                "name": display_name,
                                "version": _read_reg_value(app_key, "DisplayVersion"),
                                "publisher": _read_reg_value(app_key, "Publisher"),
                                "install_date": _norm_install_date(_read_reg_value(app_key, "InstallDate")),
                                "install_location": _read_reg_value(app_key, "InstallLocation"),
                                "uninstall_string": _read_reg_value(app_key, "UninstallString"),
                                "source": source,
                                "registry_key": fr"{path}\{sub_name}",
                            }

                            results.append(app)

                    except OSError:
                        # Some subkeys can be unreadable; skip
                        continue

        except OSError as e:
            notes.append(f"Could not read {source} uninstall key: {e}")

    # Deduplicate by (name, version, publisher)
    deduped: Dict[tuple, Dict[str, Any]] = {}
    for a in results:
        key = (a.get("name"), a.get("version"), a.get("publisher"))
        # Prefer HKLM_64 over others, then HKLM_32, then HKCU
        if key not in deduped:
            deduped[key] = a
        else:
            existing = deduped[key]
            prio = {"HKLM_64": 3, "HKLM_32": 2, "HKCU": 1}
            if prio.get(a.get("source"), 0) > prio.get(existing.get("source"), 0):
                deduped[key] = a

    apps = list(deduped.values())

    # Sort A→Z by name
    apps.sort(key=lambda x: (x.get("name") or "").lower())

    return {
        "apps": apps,
        "count": len(apps),
        "notes": notes,
    }







