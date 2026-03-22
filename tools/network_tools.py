"""
network_tools.py
================
Windows-focused network tools.

Functions:
  Diagnostics:
    - ping_host()            → ping a host, return latency + output
    - get_arp_table()        → ARP table entries
    - get_interface_info()   → network interface details
    - get_dns_cache()        → local DNS cache

  Port Scanning:
    - scan_port()            → test a single port
    - scan_ports()           → scan a range of ports on localhost
    - get_service()          → resolve port number to service name

  Network Scanning:
    - net_scan()             → packet capture via scapy, returns traffic breakdown
    - reverse_dns()          → reverse DNS with caching
    - should_resolve()       → filter private/loopback IPs from DNS resolution

  Network Monitoring:
    - get_bandwidth_snapshot()     → per-interface bytes sent/recv since last call
    - get_active_connections()     → all current TCP/UDP connections with process info
    - get_top_processes_by_net()   → top N processes by network connection count
    - get_interface_stats()        → interface error/drop/packet counters

  Network Map:
    - build_network_map()          → ARP scan + ping sweep to discover LAN hosts
    - get_local_subnet()           → detect local subnet from default interface
    - traceroute_hops()            → lightweight traceroute returning hop list
"""

# ─────────────────────────────────────────────
# Imports
# ─────────────────────────────────────────────

import ipaddress
import platform
import socket
import subprocess
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import psutil
from scapy.all import conf, get_if_addr, sniff
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp


# ─────────────────────────────────────────────
# Diagnostics
# ─────────────────────────────────────────────

def ping_host(host: str, count: int = 4) -> dict:
    """Ping a host and return status and raw output."""
    try:
        result = subprocess.run(
            ["ping", "-n" if subprocess.os.name == "nt" else "-c", str(count), host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        output = result.stdout
        if "unreachable" in output.lower() or result.returncode != 0:
            return {"host": host, "status": "unreachable", "output": output}
        return {"host": host, "status": "reachable", "output": output}
    except Exception as e:
        return {"host": host, "error": str(e)}


def get_arp_table() -> list[dict]:
    """Return the ARP table as a list of dicts (IP, MAC, type)."""
    try:
        result = subprocess.run(
            ["arp", "-a"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        arp_entries = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and "." in parts[0]:
                arp_entries.append({
                    "ip": parts[0],
                    "mac": parts[1],
                    "type": parts[2] if len(parts) > 2 else "unknown",
                })
        return arp_entries
    except Exception as e:
        return [{"error": str(e)}]


def get_interface_info() -> list[dict]:
    """Return network interface details: IPs, MAC, status, speed."""
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for iface, addr_list in addrs.items():
        ipv4 = [a.address for a in addr_list if a.family == socket.AF_INET]
        ipv6 = [a.address for a in addr_list if a.family == socket.AF_INET6]
        mac  = [a.address for a in addr_list if a.family == psutil.AF_LINK]

        interfaces.append({
            "name": iface,
            "ipv4": ipv4 or ["None"],
            "ipv6": ipv6 or ["None"],
            "mac": mac[0] if mac else "None",
            "status": "Up" if stats[iface].isup else "Down",
            "speed_mbps": stats[iface].speed,
        })
    return interfaces


def get_dns_cache() -> dict:
    """Return local DNS cache entries (Windows/Linux/macOS)."""
    try:
        system = platform.system().lower()
        if "windows" in system:
            result = subprocess.run(
                ["ipconfig", "/displaydns"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            return {"output": result.stdout}
        elif "linux" in system:
            result = subprocess.run(
                ["systemd-resolve", "--statistics"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            return {"output": result.stdout}
        elif "darwin" in system:
            result = subprocess.run(
                ["dscacheutil", "-cachedump", "-entries", "host"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            return {"output": result.stdout}
        else:
            return {"error": "DNS cache view not supported on this OS"}
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────
# Port Scanning
# ─────────────────────────────────────────────

def get_service(port: int) -> str:
    """Resolve a port number to its service name."""
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Unknown"


def scan_port(host: str, port: int) -> int | None:
    """Test a single TCP port. Returns port number if open, else None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.3)
    try:
        if sock.connect_ex((host, port)) == 0:
            return port
    except Exception:
        pass
    finally:
        sock.close()
    return None


def scan_ports(ports: range = range(1, 1025), host: str = "127.0.0.1") -> list[dict]:
    """Scan a range of TCP ports on host. Returns list of open ports with service names."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(lambda p: scan_port(host, p), ports)
    for port in results:
        if port:
            open_ports.append({"port": port, "service": get_service(port)})
    return open_ports


# ─────────────────────────────────────────────
# Network Scanning (Scapy)
# ─────────────────────────────────────────────

# Module-level DNS cache to avoid repeated lookups across calls
_dns_cache: dict[str, str] = {}


def should_resolve(ip: str) -> bool:
    """Return True only for public IPs worth resolving."""
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_multicast)
    except ValueError:
        return False


def reverse_dns(ip: str) -> str:
    """Reverse DNS lookup with in-memory caching."""
    if ip in _dns_cache:
        return _dns_cache[ip]
    if not should_resolve(ip):
        _dns_cache[ip] = ip
        return ip
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        _dns_cache[ip] = hostname
        return hostname
    except (socket.herror, socket.gaierror):
        _dns_cache[ip] = ip
        return ip


def net_scan(timeout: int) -> list[list[dict]]:
    """
    Capture network packets for `timeout` seconds using Scapy.
    Returns [all_traffic, inbound, outbound, top_10_common].
    """
    counter: Counter = Counter()

    def packet_callback(packet):
        if packet.haslayer("IP"):
            ip_layer = packet["IP"]
            counter[(ip_layer.src, ip_layer.dst)] += 1

    print(f"Sniffing for {timeout} seconds...")
    sniff(prn=packet_callback, timeout=timeout)

    iface = conf.iface
    my_ip = get_if_addr(iface)
    print("Device IP:", my_ip)

    def build_entry(src, dst, count):
        src = "DEVICE_IP" if src == my_ip else src
        dst = "DEVICE_IP" if dst == my_ip else dst
        return {
            "src": src,
            "dst": dst,
            "count": count,
            "src_hostname": reverse_dns(src),
            "dst_hostname": reverse_dns(dst),
        }

    all_traffic  = [build_entry(s, d, c) for (s, d), c in counter.most_common(1000)]
    inbound      = [build_entry(s, d, c) for (s, d), c in counter.most_common(1000) if d == my_ip]
    outbound     = [build_entry(s, d, c) for (s, d), c in counter.most_common(1000) if s == my_ip]
    top_common   = [build_entry(s, d, c) for (s, d), c in counter.most_common(10)]

    return [all_traffic, inbound, outbound, top_common]


# ─────────────────────────────────────────────
# Network Monitoring
# ─────────────────────────────────────────────

# Store previous counters for bandwidth delta calculations
_last_net_io: dict = {}
_last_net_io_time: float = 0.0


def get_bandwidth_snapshot() -> list[dict]:
    """
    Returns per-interface bandwidth usage since the last call.
    On the first call, returns raw cumulative counters.
    Call this repeatedly (e.g. every second) to get live rates.
    """
    global _last_net_io, _last_net_io_time

    now = time.time()
    current = psutil.net_io_counters(pernic=True)
    results = []

    for iface, counters in current.items():
        prev = _last_net_io.get(iface)
        elapsed = now - _last_net_io_time if _last_net_io_time else 1.0

        if prev and elapsed > 0:
            bytes_sent_rate = (counters.bytes_sent - prev.bytes_sent) / elapsed
            bytes_recv_rate = (counters.bytes_recv - prev.bytes_recv) / elapsed
        else:
            bytes_sent_rate = 0.0
            bytes_recv_rate = 0.0

        results.append({
            "interface": iface,
            "bytes_sent_total": counters.bytes_sent,
            "bytes_recv_total": counters.bytes_recv,
            "bytes_sent_rate":  round(bytes_sent_rate, 2),   # bytes/sec
            "bytes_recv_rate":  round(bytes_recv_rate, 2),   # bytes/sec
            "kb_sent_rate":     round(bytes_sent_rate / 1024, 2),
            "kb_recv_rate":     round(bytes_recv_rate / 1024, 2),
            "packets_sent":     counters.packets_sent,
            "packets_recv":     counters.packets_recv,
            "errors_in":        counters.errin,
            "errors_out":       counters.errout,
            "drop_in":          counters.dropin,
            "drop_out":         counters.dropout,
        })

    _last_net_io = {iface: c for iface, c in current.items()}
    _last_net_io_time = now
    return results


def get_active_connections() -> list[dict]:
    """
    Returns all current TCP/UDP connections with associated process info.
    Similar to netstat -ano but richer.
    """
    connections = []
    for conn in psutil.net_connections(kind="inet"):
        proc_name = None
        proc_exe  = None
        try:
            if conn.pid:
                proc = psutil.Process(conn.pid)
                proc_name = proc.name()
                proc_exe  = proc.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        connections.append({
            "proto":       "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
            "local_addr":  f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—",
            "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "—",
            "status":      conn.status,
            "pid":         conn.pid,
            "process":     proc_name or "—",
            "exe":         proc_exe  or "—",
        })

    # Sort: ESTABLISHED first, then LISTEN, then others
    priority = {"ESTABLISHED": 0, "LISTEN": 1}
    connections.sort(key=lambda c: priority.get(c["status"], 2))
    return connections


def get_top_processes_by_net(top_n: int = 10) -> list[dict]:
    """
    Returns the top N processes ranked by number of active network connections.
    Useful for spotting chatty or suspicious processes.
    """
    pid_counts: Counter = Counter()
    pid_info: dict = {}

    for conn in psutil.net_connections(kind="inet"):
        if conn.pid:
            pid_counts[conn.pid] += 1
            if conn.pid not in pid_info:
                try:
                    proc = psutil.Process(conn.pid)
                    pid_info[conn.pid] = {
                        "name": proc.name(),
                        "exe":  proc.exe(),
                    }
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pid_info[conn.pid] = {"name": "—", "exe": "—"}

    results = []
    for pid, count in pid_counts.most_common(top_n):
        info = pid_info.get(pid, {"name": "—", "exe": "—"})
        results.append({
            "pid":         pid,
            "process":     info["name"],
            "exe":         info["exe"],
            "connections": count,
        })
    return results


def get_interface_stats() -> list[dict]:
    """
    Returns detailed per-interface error and packet counters.
    Useful for detecting flaky or saturated adapters.
    """
    stats = []
    io = psutil.net_io_counters(pernic=True)
    if_stats = psutil.net_if_stats()

    for iface, counters in io.items():
        up = if_stats[iface].isup if iface in if_stats else None
        speed = if_stats[iface].speed if iface in if_stats else None
        stats.append({
            "interface":    iface,
            "status":       "Up" if up else "Down",
            "speed_mbps":   speed,
            "packets_sent": counters.packets_sent,
            "packets_recv": counters.packets_recv,
            "bytes_sent":   counters.bytes_sent,
            "bytes_recv":   counters.bytes_recv,
            "errors_in":    counters.errin,
            "errors_out":   counters.errout,
            "drop_in":      counters.dropin,
            "drop_out":     counters.dropout,
        })
    return stats


# ─────────────────────────────────────────────
# Network Map
# ─────────────────────────────────────────────

def get_local_subnet() -> str | None:
    """
    Detect the local subnet (e.g. '192.168.1.0/24') from the default interface.
    Returns None if it cannot be determined.
    """
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        default_iface = conf.iface  # Scapy's best guess at default interface

        # Try default interface first, then fall back to any UP interface with IPv4
        candidates = [default_iface] + [
            iface for iface, st in stats.items()
            if st.isup and iface != default_iface
        ]

        for iface in candidates:
            for addr in addrs.get(iface, []):
                if addr.family == socket.AF_INET and addr.address != "127.0.0.1":
                    network = ipaddress.IPv4Network(
                        f"{addr.address}/{addr.netmask}", strict=False
                    )
                    return str(network)
    except Exception:
        pass
    return None


def build_network_map(subnet: str | None = None, timeout: float = 2.0) -> dict:
    """
    Discovers hosts on the local subnet using ARP (via Scapy).
    Falls back to a ping sweep for hosts that don't respond to ARP.

    Returns:
      {
        "subnet": "192.168.1.0/24",
        "hosts": [
          {
            "ip": "192.168.1.1",
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "router.local",
            "method": "arp" | "ping",
            "reachable": True
          }, ...
        ],
        "host_count": N,
        "errors": []
      }
    """
    result = {
        "subnet": subnet,
        "hosts": [],
        "host_count": 0,
        "errors": [],
    }

    if subnet is None:
        subnet = get_local_subnet()
        if subnet is None:
            result["errors"].append("Could not determine local subnet automatically.")
            return result
        result["subnet"] = subnet

    # ── ARP sweep (fast, layer 2) ─────────────────────────────────────────────
    arp_hosts: dict[str, str] = {}  # ip → mac
    try:
        arp_req = ARP(pdst=subnet)
        ether   = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet  = ether / arp_req
        answered, _ = srp(packet, timeout=timeout, verbose=False)
        for _, received in answered:
            arp_hosts[received.psrc] = received.hwsrc
    except Exception as e:
        result["errors"].append(f"ARP sweep failed: {e}")

    # ── Ping sweep for IPs that didn't respond to ARP ─────────────────────────
    try:
        network    = ipaddress.IPv4Network(subnet, strict=False)
        all_ips    = [str(ip) for ip in network.hosts()]
        arp_ips    = set(arp_hosts.keys())
        remaining  = [ip for ip in all_ips if ip not in arp_ips]

        # Only ping sweep if subnet is /24 or smaller to avoid huge sweeps
        if network.prefixlen >= 24:
            def _ping(ip: str) -> str | None:
                try:
                    cp = subprocess.run(
                        ["ping", "-n", "1", "-w", "300", ip],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=2,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                    return ip if cp.returncode == 0 else None
                except Exception:
                    return None

            with ThreadPoolExecutor(max_workers=50) as ex:
                ping_results = list(ex.map(_ping, remaining))

            for ip in ping_results:
                if ip and ip not in arp_hosts:
                    arp_hosts[ip] = "—"  # reachable but no MAC (ping only)

    except Exception as e:
        result["errors"].append(f"Ping sweep failed: {e}")

    # ── Assemble host list with reverse DNS ───────────────────────────────────
    for ip, mac in sorted(arp_hosts.items(), key=lambda x: socket.inet_aton(x[0])):
        hostname = "—"
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            pass

        result["hosts"].append({
            "ip":        ip,
            "mac":       mac,
            "hostname":  hostname,
            "method":    "arp" if mac != "—" else "ping",
            "reachable": True,
        })

    result["host_count"] = len(result["hosts"])
    return result


def traceroute_hops(target: str, max_hops: int = 20, timeout: int = 3) -> dict:
    """
    Lightweight traceroute using Windows tracert command.
    Returns a structured list of hops with IP, hostname, and RTT.

    Useful for the network map tab to show path to a target.
    """
    result = {
        "target": target,
        "hops": [],
        "errors": [],
    }

    try:
        cp = subprocess.run(
            ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout * 1000), target],
            capture_output=True,
            text=True,
            timeout=60,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        output = cp.stdout

        import re
        # Match lines like:  "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
        hop_pattern = re.compile(
            r"^\s*(\d+)\s+"           # hop number
            r"([\d<*]+\s*ms|[\*]+)\s+"  # rtt1
            r"([\d<*]+\s*ms|[\*]+)\s+"  # rtt2
            r"([\d<*]+\s*ms|[\*]+)\s+"  # rtt3
            r"([\d\.]+|Request timed out\.?|[\*]+)"  # IP or timeout
        )

        for line in output.splitlines():
            m = hop_pattern.match(line)
            if m:
                hop_num = int(m.group(1))
                ip      = m.group(5).strip()
                rtts    = [m.group(2).strip(), m.group(3).strip(), m.group(4).strip()]
                timed_out = "*" in ip or "timed out" in ip.lower()

                hostname = "—"
                if not timed_out:
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except (socket.herror, socket.gaierror):
                        hostname = ip

                result["hops"].append({
                    "hop":       hop_num,
                    "ip":        ip if not timed_out else "*",
                    "hostname":  hostname,
                    "rtts":      rtts,
                    "timed_out": timed_out,
                })

    except subprocess.TimeoutExpired:
        result["errors"].append("Traceroute timed out.")
    except Exception as e:
        result["errors"].append(f"Traceroute failed: {e}")

    return result