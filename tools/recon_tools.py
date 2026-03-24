"""
recon_tools.py
==============
Reconnaissance and OSINT tools for the Cyber Toolkit.

Functions:
  Network Intelligence:
    - dns_lookup()              → resolve domain to IP + hostname
    - reverse_dns_lookup()      → resolve IP to PTR hostname
    - traceroute()              → hop-by-hop path to a target
    - ip_geolocation()          → country/region/ISP from IP
    - asn_lookup()              → ASN and org info for an IP or domain

  Domain & Ownership:
    - whois_lookup()            → WHOIS registration data
    - cert_lookup()             → SSL/TLS certificate inspection
    - reverse_whois()           → reverse WHOIS (currently unavailable)

  Web Footprinting:
    - http_header_analyser()    → HTTP response headers analysis
    - http_response_viewer()    → full HTTP response inspection
    - technology_fingerprinting() → CMS/framework detection from headers + HTML
    - robots_sitemap_viewer()   → robots.txt and sitemap.xml retrieval

  Infrastructure Discovery:
    - infrastructure_discovery() → port scan, banner grab, reverse DNS,
                                   service fingerprint, and geo on a target
"""

# ─────────────────────────────────────────────
# Imports
# ─────────────────────────────────────────────

import re
import socket
import ssl
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import requests
import tldextract
import whois


# ─────────────────────────────────────────────
# Network Intelligence
# ─────────────────────────────────────────────

def dns_lookup(domain: str) -> dict:
    """Resolve a domain to its IP address and reverse hostname."""
    try:
        ip = socket.gethostbyname(domain)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = "No reverse hostname found"

        return {"domain": domain, "ip": ip, "hostname": hostname}

    except Exception:
        return {"domain": domain, "error": "Invalid domain or DNS lookup failed", "hostname": "N/A"}


def reverse_dns_lookup(ip: str) -> dict:
    """Resolve an IP address to its PTR hostname and registered domain."""
    try:
        full_hostname = socket.gethostbyaddr(ip)[0]
        extracted     = tldextract.extract(full_hostname)
        domain        = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else full_hostname

        return {"ip": ip, "hostname": full_hostname, "domain": domain}

    except Exception:
        return {"ip": ip, "error": "No PTR record found", "domain": "N/A"}


def traceroute(host: str) -> dict:
    """Run a traceroute/tracert and return structured hop data."""
    system = platform.system().lower()
    cmd    = ["tracert", host] if system == "windows" else ["traceroute", host]

    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        hops   = []

        hop_pattern = re.compile(r"^\s*(\d+)\s+((?:\d+ ms|\*)\s+){1,3}(.+)$")

        for line in output.splitlines():
            match = hop_pattern.match(line)
            if match:
                hop_number = int(match.group(1))
                times      = re.findall(r"(\d+ ms|\*)", line)
                host_str   = line.split(times[-1])[-1].strip() if times else "N/A"

                hops.append({
                    "hop":      hop_number,
                    "latency1": times[0] if len(times) > 0 else "*",
                    "latency2": times[1] if len(times) > 1 else "*",
                    "latency3": times[2] if len(times) > 2 else "*",
                    "host":     host_str,
                })

        return {"hops": hops}

    except Exception as e:
        return {"error": str(e)}


def ip_geolocation(ip: str) -> dict:
    """Return country, region, city, ISP, and coordinates for an IP address."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=8)
        data     = response.json()

        if data.get("status") == "success":
            return {
                "ip":      ip,
                "country": data["country"],
                "region":  data["region"],
                "city":    data["city"],
                "zip":     data["zip"],
                "lat":     data["lat"],
                "lon":     data["lon"],
                "isp":     data["isp"],
                "org":     data["org"],
            }
        else:
            return {"ip": ip, "error": "Lookup failed"}

    except Exception as e:
        return {"ip": ip, "error": str(e)}


def asn_lookup(query: str) -> dict:
    """Return ASN, org, and location info for an IP or domain."""
    try:
        try:
            ip = socket.gethostbyname(query)
        except socket.gaierror:
            ip = query

        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=8)
        data     = response.json()

        return {
            "Query":   query,
            "IP":      ip,
            "ASN":     data.get("org") or data.get("asn"),
            "Country": data.get("country"),
            "Region":  data.get("region"),
            "City":    data.get("city"),
        }

    except Exception as e:
        return {"query": query, "error": str(e)}


# ─────────────────────────────────────────────
# Domain & Ownership
# ─────────────────────────────────────────────

def whois_lookup(domain: str) -> dict:
    """Return WHOIS registration data for a domain."""
    try:
        w = whois.whois(domain)
        return {
            "Domain Name":    w.domain_name,
            "Registrar":      w.registrar,
            "Registrar URL":  getattr(w, "registrar_url", None),
            "Whois Server":   getattr(w, "whois_server", None),
            "Updated Date":   w.updated_date,
            "Creation Date":  w.creation_date,
            "Expiration Date": w.expiration_date,
            "Name Servers":   w.name_servers,
            "Status":         w.status,
            "Emails":         w.emails,
            "Dnssec":         w.dnssec,
            "Org":            w.org,
            "Country":        w.country,
        }
    except Exception as e:
        return {"error": str(e)}


def cert_lookup(hostname: str, port: int = 443) -> dict:
    """Fetch and inspect the SSL/TLS certificate for a hostname."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        return {
            "Subject":       dict(x[0] for x in cert.get("subject", [])),
            "Issuer":        dict(x[0] for x in cert.get("issuer", [])),
            "Valid From":    cert.get("notBefore"),
            "Valid Until":   cert.get("notAfter"),
            "Serial Number": cert.get("serialNumber"),
            "SAN":           [x[1] for x in cert.get("subjectAltName", [])],
        }

    except Exception as e:
        return {"error": str(e)}


def reverse_whois(query: str, tld_filter: str | None = None, exact: bool = False) -> dict:
    """Reverse WHOIS lookup — currently unavailable."""
    return {"query": query, "error": "Feature currently unavailable!"}


# ─────────────────────────────────────────────
# Web Footprinting
# ─────────────────────────────────────────────

def http_header_analyser(url: str) -> dict:
    """Fetch and analyse HTTP response headers for a URL."""
    try:
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        response = requests.head(url, timeout=5, allow_redirects=True)
        return {
            "url":         url,
            "status_code": response.status_code,
            "headers":     dict(response.headers),
        }
    except Exception as e:
        return {"error": str(e)}


def http_response_viewer(url: str) -> dict:
    """Fetch the full HTTP response including status, headers, and a content snippet."""
    try:
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        response = requests.get(url, timeout=8)
        return {
            "url":             response.url,
            "status_code":     response.status_code,
            "reason":          response.reason,
            "headers":         dict(response.headers),
            "content_snippet": response.text[:800] + "...",
        }
    except Exception as e:
        return {"error": str(e)}


def technology_fingerprinting(url: str) -> dict:
    """Detect CMS, frameworks, and CDNs from HTTP headers and HTML content."""
    try:
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        response = requests.get(url, timeout=10)
        headers  = response.headers
        html     = response.text.lower()
        detected = []

        # ── Header-based detection ────────────────────────────────────────────
        if "server" in headers:
            detected.append(f"Server: {headers['server']}")
        if "x-powered-by" in headers:
            detected.append(f"Powered by: {headers['x-powered-by']}")
        if "cf-ray" in headers:
            detected.append("Cloudflare CDN")
        if "x-amz-request-id" in headers:
            detected.append("Amazon AWS")
        if "x-azure-ref" in headers:
            detected.append("Microsoft Azure")

        # ── HTML-based detection ──────────────────────────────────────────────
        _HTML_SIGNATURES = [
            ("wp-content",  "WordPress CMS"),
            ("wordpress",   "WordPress CMS"),
            ("drupal",      "Drupal CMS"),
            ("joomla",      "Joomla CMS"),
            ("shopify",     "Shopify platform"),
            ("squarespace", "Squarespace platform"),
            ("wix.com",     "Wix platform"),
            ("react",       "React.js framework"),
            ("vue",         "Vue.js framework"),
            ("angular",     "Angular framework"),
            ("django",      "Django backend"),
            ("flask",       "Flask backend"),
            ("laravel",     "Laravel PHP framework"),
            ("jquery",      "jQuery"),
            ("bootstrap",   "Bootstrap CSS"),
            ("tailwind",    "Tailwind CSS"),
            ("gtag(",       "Google Analytics"),
            ("fbq(",        "Facebook Pixel"),
        ]
        seen = set()
        for signature, label in _HTML_SIGNATURES:
            if signature in html and label not in seen:
                detected.append(label)
                seen.add(label)

        if not detected:
            detected.append("No clear technology fingerprints found.")

        return {
            "url":         response.url,
            "status_code": response.status_code,
            "detected":    detected,
        }
    except Exception as e:
        return {"error": str(e)}


def robots_sitemap_viewer(url: str) -> dict:
    """Fetch and return the robots.txt and sitemap.xml for a domain."""
    try:
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        base         = url.rstrip("/")
        robots_resp  = requests.get(f"{base}/robots.txt",  timeout=5)
        sitemap_resp = requests.get(f"{base}/sitemap.xml", timeout=5)

        return {
            "robots_url":      f"{base}/robots.txt",
            "robots_status":   robots_resp.status_code,
            "robots_content":  robots_resp.text if robots_resp.ok else "robots.txt not found.",
            "sitemap_url":     f"{base}/sitemap.xml",
            "sitemap_status":  sitemap_resp.status_code,
            "sitemap_content": sitemap_resp.text[:1000] if sitemap_resp.ok else "sitemap.xml not found.",
        }
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────
# Infrastructure Discovery
# ─────────────────────────────────────────────

# Common ports to scan for infrastructure discovery
_INFRA_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443,
]

# Known service banners / protocol labels
_PORT_LABELS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    111:  "RPC",
    135:  "MSRPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    993:  "IMAPS",
    995:  "POP3S",
    1723: "PPTP VPN",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


def _grab_banner(ip: str, port: int, timeout: float = 1.5) -> str | None:
    """Attempt to grab a service banner from an open port."""
    try:
        if port == 443 or port == 8443:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as s:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    return s.recv(512).decode(errors="ignore").strip()[:200]

        if port in (80, 8080):
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                return s.recv(512).decode(errors="ignore").strip()[:200]

        # Generic banner grab (FTP, SSH, SMTP, etc.)
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                return s.recv(512).decode(errors="ignore").strip()[:200]
            except Exception:
                return None

    except Exception:
        return None


def _scan_port(ip: str, port: int, timeout: float = 0.8) -> dict | None:
    """
    Test a single TCP port. Returns a result dict if open, None if closed/filtered.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            pass
        return {"port": port, "state": "open", "service": _PORT_LABELS.get(port, "unknown")}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def infrastructure_discovery(
    target: str,
    ports: list[int] | None = None,
    banner_grab: bool = True,
    geo: bool = True,
    rdns: bool = True,
    workers: int = 50,
    banner_timeout: float = 1.5,
) -> dict:
    """
    Comprehensive infrastructure discovery for a target host or IP.

    Steps:
      1. Resolve target to IP (if domain given)
      2. Reverse DNS lookup
      3. IP geolocation
      4. Multithreaded port scan across common infrastructure ports
      5. Banner grabbing on open ports (optional)
      6. WHOIS lookup
      7. SSL/TLS certificate inspection (if port 443 open)

    Args:
      target:         Hostname or IP address to scan
      ports:          List of ports to scan (defaults to _INFRA_PORTS)
      banner_grab:    Whether to grab service banners from open ports
      geo:            Whether to run IP geolocation
      rdns:           Whether to run reverse DNS
      workers:        Thread pool size for port scanning
      banner_timeout: Timeout in seconds for banner connections

    Returns a structured dict with all findings.
    """
    print(f"Running infrastructure discovery on {target}...")

    results = {
        "target":       target,
        "timestamp":    datetime.now().isoformat(timespec="seconds"),
        "ip":           None,
        "rdns":         None,
        "geo":          None,
        "open_ports":   [],
        "whois":        None,
        "certificate":  None,
        "errors":       [],
    }

    scan_ports = ports or _INFRA_PORTS

    # ── Step 1: Resolve target to IP ─────────────────────────────────────────
    try:
        ip = socket.gethostbyname(target)
        results["ip"] = ip
    except socket.gaierror as e:
        results["errors"].append(f"DNS resolution failed: {e}")
        return results

    # ── Step 2: Reverse DNS ───────────────────────────────────────────────────
    if rdns:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            results["rdns"] = hostname
        except Exception:
            results["rdns"] = "No PTR record"

    # ── Step 3: Geolocation ───────────────────────────────────────────────────
    if geo:
        try:
            geo_data = ip_geolocation(ip)
            results["geo"] = geo_data
        except Exception as e:
            results["errors"].append(f"Geolocation failed: {e}")

    # ── Step 4: Port scan ─────────────────────────────────────────────────────
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_scan_port, ip, p): p for p in scan_ports}
        for future, port in futures.items():
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
            except Exception:
                pass

    # Sort by port number
    open_ports.sort(key=lambda x: x["port"])

    # ── Step 5: Banner grabbing ───────────────────────────────────────────────
    if banner_grab:
        for port_entry in open_ports:
            banner = _grab_banner(ip, port_entry["port"], timeout=banner_timeout)
            port_entry["banner"] = banner

    results["open_ports"] = open_ports

    # ── Step 6: WHOIS ─────────────────────────────────────────────────────────
    try:
        # Use original target (domain) for WHOIS if not a raw IP
        whois_target = target if not _is_ip(target) else ip
        results["whois"] = whois_lookup(whois_target)
    except Exception as e:
        results["errors"].append(f"WHOIS failed: {e}")

    # ── Step 7: Certificate (if 443 open) ────────────────────────────────────
    has_443 = any(p["port"] == 443 for p in open_ports)
    if has_443:
        try:
            results["certificate"] = cert_lookup(target)
        except Exception as e:
            results["errors"].append(f"Certificate lookup failed: {e}")

    # ── Summary ───────────────────────────────────────────────────────────────
    results["summary"] = {
        "open_port_count":  len(open_ports),
        "has_http":         any(p["port"] in (80, 8080)        for p in open_ports),
        "has_https":        any(p["port"] in (443, 8443)       for p in open_ports),
        "has_ssh":          any(p["port"] == 22                for p in open_ports),
        "has_rdp":          any(p["port"] == 3389              for p in open_ports),
        "has_smb":          any(p["port"] in (139, 445)        for p in open_ports),
        "has_database":     any(p["port"] in (3306, 5432, 1433) for p in open_ports),
        "has_ftp":          any(p["port"] == 21                for p in open_ports),
    }

    return results


def _is_ip(value: str) -> bool:
    """Return True if value looks like an IPv4 address."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False