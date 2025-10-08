import subprocess
import psutil
import socket
import platform


def ping_host(host: str, count: int = 4):
    """Ping a host and return average latency in ms."""
    try:
        result = subprocess.run(
            ["ping", "-n" if subprocess.os.name == "nt" else "-c", str(count), host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )
        output = result.stdout
        if "unreachable" in output.lower() or result.returncode != 0:
            return {"host": host, "status": "unreachable", "output": output}
        return {"host": host, "status": "reachable", "output": output}
    except Exception as e:
        return {"host": host, "error": str(e)}


def get_arp_table():
    """Return the ARP table as a list of dicts (IP, MAC, Interface)."""
    try:
        result = subprocess.run(
            ["arp", "-a"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        lines = result.stdout.splitlines()
        arp_entries = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 3 and "." in parts[0]:
                arp_entries.append({
                    "ip": parts[0],
                    "mac": parts[1],
                    "type": parts[2] if len(parts) > 2 else "unknown"
                })
        return arp_entries
    except Exception as e:
        return [{"error": str(e)}]


def get_interface_info():
    """Return network interface details: IPs, gateways, and DNS."""
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for iface, addr_list in addrs.items():
        ipv4 = [a.address for a in addr_list if a.family == socket.AF_INET]
        ipv6 = [a.address for a in addr_list if a.family == socket.AF_INET6]
        mac = [a.address for a in addr_list if a.family == psutil.AF_LINK]

        interfaces.append({
            "name": iface,
            "ipv4": ipv4 or ["None"],
            "ipv6": ipv6 or ["None"],
            "mac": mac[0] if mac else "None",
            "status": "Up" if stats[iface].isup else "Down",
            "speed_mbps": stats[iface].speed
        })
    return interfaces


def get_dns_cache():
    """Return local DNS cache entries if supported."""
    try:
        system = platform.system().lower()
        if "windows" in system:
            result = subprocess.run(
                ["ipconfig", "/displaydns"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return {"output": result.stdout}
        elif "linux" in system:
            result = subprocess.run(
                ["systemd-resolve", "--statistics"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return {"output": result.stdout}
        elif "darwin" in system:  # macOS
            result = subprocess.run(
                ["dscacheutil", "-cachedump", "-entries", "host"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return {"output": result.stdout}
        else:
            return {"error": "DNS cache view not supported on this OS"}
    except Exception as e:
        return {"error": str(e)}