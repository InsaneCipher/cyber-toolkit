import socket
import subprocess
import platform
import whois
import re
import ssl
import tldextract
import requests
from datetime import datetime

from django.utils.dateformat import re_escaped


def dns_lookup(domain):
    try:
        # Get IP address for the given domain
        ip = socket.gethostbyname(domain)

        # Try to get full hostname (sometimes same as domain)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = "No reverse hostname found"

        result = {
            "domain": domain,
            "ip": ip,
            "hostname": hostname
        }

    except Exception as e:
        result = {
            "domain": domain,
            "error": "Invalid domain or DNS lookup failed",
            "hostname": "N/A"
        }

    return result


def reverse_dns_lookup(ip):
    try:
        # Get the full PTR hostname
        full_hostname = socket.gethostbyaddr(ip)[0]

        # Extract just the registered domain (e.g., google.com)
        extracted = tldextract.extract(full_hostname)
        domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else full_hostname

        result = {
            "ip": ip,
            "hostname": full_hostname,
            "domain": domain
        }

    except Exception as e:
        result = {
            "ip": ip,
            "error": "No PTR record found",
            "domain": "N/A"
        }

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


def ip_geolocation(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        
        if data["status"] == "success":
            result = {
                "ip": ip, 
                "country": data["country"],
                "region": data["region"],
                "city": data["city"],
                "zip": data["zip"], 
                "lat": data["lat"],
                "lon": data["lon"],
                "isp": data["isp"], 
                "org": data["org"]
            }
            print(result)
        else:
            result = {"ip": ip, "error": "Lookup Failed!"}
    except Exception as e:
        result = {"ip": ip, "error": str(e)}
        
    return result


# Currently Unavailable
def reverse_whois(query, tld_filter=None, exact=False):
    try:
        # Build base params dynamically
        params = {"query": query}

        if tld_filter:
            # Normalize commas/spaces
            tlds = [t.strip().lstrip('.') for t in tld_filter.split(',') if t.strip()]
            params["tlds"] = ",".join(tlds)

        if exact:
            params["exact_match"] = "true"

        # Example API (you’d replace with the actual service)
        response = requests.get("https://api.viewdns.info/reversewhois/", params=params)
        data = response.json()

        # Example response parsing — adapt to your API
        result = {
            "query": query,
            "tld": params.get("tlds"),
            "exact": exact,
            "domains": data.get("domains", []),
        }

    except Exception as e:
        result = {"query": query, "error": str(e)}

    return result


def asn_lookup(query):
    try:
        # If a domain is given, resolve it to an IP first
        try:
            ip = socket.gethostbyname(query)
        except socket.gaierror:
            ip = query  # already an IP

        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()

        result = {
            "Query": query,
            "IP": ip,
            "ASN": data.get("org") or data.get("asn"),
            "Country": data.get("country"),
            "Region": data.get("region"),
            "City": data.get("city")
        }

    except Exception as e:
        result = {"query": query, "error": str(e)}

    return result


def http_header_analyser(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        response = requests.head(url, timeout=5, allow_redirects=True)
        headers = dict(response.headers)

        result = {
            "url": url,
            "status_code": response.status_code,
            "headers": headers
        }
    except Exception as e:
        result = {"error": str(e)}

    return result


def http_response_viewer(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        response = requests.get(url, timeout=8)
        result = {
            "url": response.url,
            "status_code": response.status_code,
            "reason": response.reason,
            "headers": dict(response.headers),
            "content_snippet": str(response.text[:800] + "...")  # limit for safety
        }
    except Exception as e:
        result = {"error": str(e)}

    return result


def technology_fingerprinting(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        response = requests.get(url, timeout=10)
        headers = response.headers
        html = response.text.lower()

        detected = []

        # Header based clues
        if "server" in headers:
            detected.append(f"Server: {headers["server"]}")
        if "x-powered-by" in headers:
            detected.append(f"Powered by: {headers['x-powered-by']}")
        if "cf-ray" in headers:
            detected.append(f"Cloudflare detected")

        # HTML based clues
        if "wp-content" in html or "wordpress" in html:
            detected.append(f"WordPress CMS")
        if "drupal" in html:
            detected.append(f"Drupal CMS")
        if "joomla" in html:
            detected.append(f"Joomla CMS")
        if "shopify" in html:
            detected.append(f"Shopify platform")
        if "react" in html:
            detected.append(f"React.js framework")
        if "vue" in html:
            detected.append(f"Vue.js framework")
        if "django" in html:
            detected.append(f"Django Backend")
        if "flask" in html:
            detected.append(f"Flask Backend")

        if not detected:
            detected.append(f"No clear technology fingerprints found.")

        result = {
            "url": response.url,
            "status_code": response.status_code,
            "detected": detected
        }
    except Exception as e:
        result = {"error": str(e)}

    return result


def robots_sitemap_viewer(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        robots_url = url.rstrip("/") + "/robots.txt"
        sitemap_url = url.rstrip("/") + "/sitemap.xml"

        robots_resp = requests.get(robots_url, timeout=5)
        sitemap_resp = requests.get(sitemap_url, timeout=5)

        result = {
            "robots_url": robots_url,
            "robots_status": robots_resp.status_code,
            "robots_content": robots_resp.text if robots_resp.ok else "robots.txt not found.",
            "sitemap_url": sitemap_url,
            "sitemap_status": sitemap_resp.status_code,
            "sitemap_content": sitemap_resp.text[:1000] if sitemap_resp.ok else "sitemap.xml not found.",
        }
    except Exception as e:
        result = {"error": str(e)}

    return result


