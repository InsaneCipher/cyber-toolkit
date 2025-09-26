import socket
import subprocess
import platform
import whois
import re
import ssl
from datetime import datetime


def dns_lookup(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except:
        hostname = "No hostname found"

    result = {'ip': ip, 'hostname': hostname}
    print(result)

    return result


def traceroute(host):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["tracert", host]
    else:
        cmd = ["traceroute", host]

    try:
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        hops = []
        lines = result.splitlines()

        # Matches hop number + up to 3 latency values + the final host/IP
        hop_pattern = re.compile(
            r"^\s*(\d+)\s+((?:\d+ ms|\*)\s+){1,3}(.+)$"
        )

        for line in lines:
            match = hop_pattern.match(line)
            if match:
                hop_number = int(match.group(1))

                # Extract all the latency values separately
                times = re.findall(r"(\d+ ms|\*)", line)

                # Host/IP is always the last thing after the times
                host_str = line.split(times[-1])[-1].strip() if times else "N/A"

                hops.append({
                    "hop": hop_number,
                    "latency1": times[0] if len(times) > 0 else "*",
                    "latency2": times[1] if len(times) > 1 else "*",
                    "latency3": times[2] if len(times) > 2 else "*",
                    "host": host_str
                })

        result = {"hops": hops}
    except Exception as e:
        result = {"error": str(e)}

    return result


def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        result = {
            "Domain Name": w.domain_name,
            "Registrar": w.registrar,
            "Registrar URL": getattr(w, "registrar_url", None),
            "Whois Server": getattr(w, "whois_server", None),
            "Updated Date": w.updated_date,
            "Creation Date": w.creation_date,
            "Expiration Date": w.expiration_date,
            "Name Servers": w.name_servers,
            "Status": w.status,
            "Emails": w.emails,
            "Dnssec": w.dnssec,
            "Org": w.org,
            "Country": w.country,
        }
    except Exception as e:
        result = {'result': str(e)}

    print(result)
    return result


def cert_lookup(hostname, port=443):
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # Extract useful fields
        result = {
            "Subject": dict(x[0] for x in cert.get("subject", [])),
            "Issuer": dict(x[0] for x in cert.get("issuer", [])),
            "Valid From": cert.get("notBefore"),
            "Valid Until": cert.get("notAfter"),
            "Serial Number": cert.get("serialNumber"),
            "SAN": [x[1] for x in cert.get("subjectAltName", [])],
        }

        return result

    except Exception as e:
        return {"error": str(e)}
