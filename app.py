"""
app.py
======
Cyber Toolkit — main application entry point.

Starts a local Flask server on 127.0.0.1:5000 and launches a native
desktop window via pywebview. All tool logic lives in tools/*.py.
Results are stored in a central STATE dictionary and passed to Jinja2
templates on every render.
"""

# ─────────────────────────────────────────────
# Imports
# ─────────────────────────────────────────────

import argparse
import multiprocessing
import os
import sys
import threading
import webview

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request

from tools.caching_tools import *
from tools.developer_tools import *
from tools.forensics_tools import *
from tools.network_tools import *
from tools.recon_tools import *
from tools.security_tools import *
from tools.system_tools import *
from tools.utility_tools import *


# ─────────────────────────────────────────────
# Central State
# ─────────────────────────────────────────────

STATE = {
    # ── Network ───────────────────────────────────────────────────────────────
    "result":               None,
    "port_results":         None,
    "dns_cache":            None,
    "ping_result":          None,
    "arp_table":            None,
    "interface_info":       None,
    "monitoring_results":   None,
    "network_map_results":  None,

    # ── Recon ─────────────────────────────────────────────────────────────────
    "dns_result":           None,
    "traceroute_result":    None,
    "whois_result":         None,
    "rev_whois_result":     None,
    "cert_result":          None,
    "trace_target":         None,
    "cert_target":          None,
    "rev_dns_result":       None,
    "geo_result":           None,
    "asn_result":           None,
    "header_result":        None,
    "response_result":      None,
    "tech_result":          None,
    "robots_result":        None,

    # ── Utilities ─────────────────────────────────────────────────────────────
    "hashed_strings":       None,
    "encoded_string":       None,
    "decoded_string":       None,
    "subnet":               None,

    # ── System (loaded lazily — cache only at startup) ────────────────────────
    "system_info":              None,
    "cpu_info":                 None,
    "storage_info":             None,
    "network_info":             None,
    "display_info":             None,
    "power_info":               None,
    "sensors_info":             None,
    "process_services_info":    None,
    "bios_info":                None,
    "devices_info":             None,
    "software_info":            None,

    # ── Forensics (loaded from cache only at startup) ─────────────────────────
    "forensics_results":        None,
    "file_analysis_results":    None,
    "malware_report":           None,
    "image_analysis_results":   None,

    # ── Security (loaded from cache only at startup) ──────────────────────────
    "vuln_results":             None,
    "persistence_results":      None,
    "firewall_results":         None,
    "shares_results":           None,
    "privesc_results":          None,

    # ── Developer ─────────────────────────────────────────────────────────────
    "snippet_result":           None,
    "tasks_result":             None,
    "task_action_result":       None,
    "scripts_result":           None,
    "script_run_result":        None,
    "event_log_result":         None,
    "app_log_result":           None,
    "app_log_files":            None,
}


# ─────────────────────────────────────────────
# Startup Cache Loading
# ─────────────────────────────────────────────

def init_cached_state():
    """
    Load previously cached results into STATE on first request.
    Uses load_only=True so nothing is computed — only existing cache
    files are read. Heavy scans remain lazy until the user runs them.
    """

    # System info — never computed at startup, only restored from cache
    for key in [
        "system_info", "cpu_info", "storage_info", "network_info",
        "display_info", "power_info", "sensors_info",
        "process_services_info", "bios_info", "devices_info", "software_info",
    ]:
        if STATE[key] is None:
            STATE[key] = get_or_refresh(key, lambda: {"error": "not loaded"}, load_only=True)

    # Forensics + security scan outputs — restore from cache
    for key in [
        "forensics_results", "vuln_results", "file_analysis_results",
        "malware_report", "image_analysis_results",
        "persistence_results", "firewall_results",
        "shares_results", "privesc_results",
    ]:
        if STATE[key] is None:
            STATE[key] = get_or_refresh(key, lambda: {"error": "not loaded"}, load_only=True)


# ─────────────────────────────────────────────
# App Factory
# ─────────────────────────────────────────────

def resource_path(relative_path: str) -> str:
    """Resolve file paths correctly whether running from source or PyInstaller bundle."""
    base = getattr(sys, "_MEIPASS", os.path.abspath("."))
    return os.path.join(base, relative_path)


def create_app() -> Flask:
    """Create and configure the Flask application instance."""
    return Flask(
        __name__,
        template_folder=resource_path("templates"),
        static_folder=resource_path("static"),
    )


app = create_app()


def get_template(name: str, active: str):
    """Render a template with the full STATE dictionary unpacked as context."""
    return render_template(name, active=active, **STATE)


# ─────────────────────────────────────────────
# Before Request Hook
# ─────────────────────────────────────────────

_state_inited = False


@app.before_request
def _before():
    """Initialise cached state once on the first incoming request."""
    global _state_inited
    if not _state_inited:
        init_cached_state()
        _state_inited = True


# ─────────────────────────────────────────────
# pywebview JS API
# ─────────────────────────────────────────────

def pick_file():
    """Open a native file picker dialog and return the selected path."""
    try:
        wnd = webview.windows[0]
        paths = wnd.create_file_dialog(webview.OPEN_DIALOG, allow_multiple=False)
        return paths[0] if paths else ""
    except Exception:
        return ""


class Api:
    pass


# ─────────────────────────────────────────────
# Routes — Network
# ─────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
@app.route("/network", methods=["GET", "POST"])
def network():
    if request.method == "POST":
        action = request.form.get("action")

        # ── Packet capture ────────────────────────────────────────────────────
        if action == "scan":
            timeout = int(request.form.get("timeout", 5))
            print(f"Running network scan for {timeout} seconds...")
            results = net_scan(timeout)
            STATE["result"] = {
                "all":      results[0],
                "inbound":  results[1],
                "outbound": results[2],
                "common":   results[3],
            }

        # ── Port scanner ──────────────────────────────────────────────────────
        elif action == "port_scan":
            ports = int(request.form.get("ports"))
            print(f"Scanning ports 1–{ports}...")
            STATE["port_results"] = scan_ports(range(1, ports))

        # ── Diagnostics ───────────────────────────────────────────────────────
        elif action == "ping_host":
            host = request.form.get("ping_target")
            print(f"Pinging {host}...")
            STATE["ping_result"] = ping_host(host)

        elif action == "arp_table":
            print("Fetching ARP table...")
            STATE["arp_table"] = get_arp_table()

        elif action == "interface_info":
            print("Fetching interface info...")
            STATE["interface_info"] = get_interface_info()

        elif action == "dns_cache":
            print("Fetching DNS cache...")
            STATE["dns_cache"] = get_dns_cache()

        # ── Monitoring ────────────────────────────────────────────────────────
        elif action == "bandwidth_snapshot":
            print("Taking bandwidth snapshot...")
            STATE["monitoring_results"] = {
                "type": "bandwidth",
                "data": get_bandwidth_snapshot(),
            }

        elif action == "active_connections":
            print("Fetching active connections...")
            STATE["monitoring_results"] = {
                "type": "connections",
                "data": get_active_connections(),
            }

        elif action == "top_processes":
            top_n = int(request.form.get("top_n", 10))
            print(f"Fetching top {top_n} processes by network usage...")
            STATE["monitoring_results"] = {
                "type": "processes",
                "data": get_top_processes_by_net(top_n),
            }

        elif action == "interface_stats":
            print("Fetching interface stats...")
            STATE["monitoring_results"] = {
                "type": "interface_stats",
                "data": get_interface_stats(),
            }

        # ── Network map ───────────────────────────────────────────────────────
        elif action == "network_map":
            subnet = request.form.get("map_subnet", "").strip() or None
            print(f"Building network map for subnet: {subnet or 'auto-detect'}...")
            STATE["network_map_results"] = build_network_map(subnet=subnet)

        elif action == "traceroute_map":
            target   = request.form.get("trace_target", "").strip()
            max_hops = int(request.form.get("max_hops", 20))
            print(f"Running traceroute to {target}...")
            STATE["network_map_results"] = {
                "type": "traceroute",
                "data": traceroute_hops(target, max_hops=max_hops),
            }

    return get_template("index.html", "network")


# ─────────────────────────────────────────────
# Routes — Recon
# ─────────────────────────────────────────────

@app.route("/recon", methods=["GET", "POST"])
def recon():
    if request.method == "POST":
        action = request.form.get("action")

        # ── Network intelligence ──────────────────────────────────────────────
        if action == "dns_lookup":
            domain = request.form.get("dns_domain")
            print(f"Running DNS lookup on {domain}...")
            STATE["dns_result"] = dns_lookup(domain)

        elif action == "rev_dns_lookup":
            ip = request.form.get("dns_ip")
            print(f"Running reverse DNS lookup on {ip}...")
            STATE["rev_dns_result"] = reverse_dns_lookup(ip)

        elif action == "traceroute":
            STATE["trace_target"] = request.form.get("trace_target")
            print(f"Running traceroute on {STATE['trace_target']}...")
            STATE["traceroute_result"] = traceroute(STATE["trace_target"])

        elif action == "ip_geo":
            ip = request.form.get("geo_ip")
            print(f"Running geolocation lookup on {ip}...")
            STATE["geo_result"] = ip_geolocation(ip)

        # ── Domain & ownership ────────────────────────────────────────────────
        elif action == "whois":
            target = request.form.get("whois_target")
            print(f"Running WHOIS lookup on {target}...")
            STATE["whois_result"] = whois_lookup(target)

        elif action == "rev_whois":
            query       = request.form.get("rev_whois_target")
            tld_filter  = request.form.get("tld_filter", "").strip()
            exact_match = bool(request.form.get("exact_match"))
            print(f"Running reverse WHOIS on {query} (exact={exact_match}, filter={tld_filter})...")
            STATE["rev_whois_result"] = {"query": query, "error": "Feature currently unavailable!"}

        elif action == "cert_lookup":
            STATE["cert_target"] = request.form.get("cert_target")
            print(f"Inspecting certificate for {STATE['cert_target']}...")
            STATE["cert_result"] = cert_lookup(STATE["cert_target"])

        elif action == "asn_lookup":
            asn_ip = request.form.get("asn_ip")
            print(f"Running ASN lookup on {asn_ip}...")
            STATE["asn_result"] = asn_lookup(asn_ip)

        # ── Web footprinting ──────────────────────────────────────────────────
        elif action == "http_headers":
            url = request.form.get("header_url")
            print(f"Analysing HTTP headers for {url}...")
            STATE["header_result"] = http_header_analyser(url)

        elif action == "http_response":
            url = request.form.get("resp_url")
            print(f"Fetching HTTP response for {url}...")
            STATE["response_result"] = http_response_viewer(url)

        elif action == "tech_fingerprint":
            url = request.form.get("tech_url")
            print(f"Running technology fingerprinting on {url}...")
            STATE["tech_result"] = technology_fingerprinting(url)

        elif action == "robots_sitemap":
            url = request.form.get("robots_url")
            print(f"Fetching robots.txt / sitemap for {url}...")
            STATE["robots_result"] = robots_sitemap_viewer(url)

    return get_template("recon.html", "recon")


# ─────────────────────────────────────────────
# Routes — Utilities
# ─────────────────────────────────────────────

@app.route("/utils", methods=["GET", "POST"])
def utils():
    if request.method == "POST":
        action = request.form.get("action")

        # ── Hashing ───────────────────────────────────────────────────────────
        if action == "hash_encrypt":
            plain_string  = request.form.get("plain_string")
            uploaded_file = request.files.get("file_input")

            if plain_string and uploaded_file and uploaded_file.filename != "":
                # Both provided — ambiguous input, clear result
                STATE["hashed_strings"] = None
            elif uploaded_file and uploaded_file.filename != "":
                file_bytes = uploaded_file.read()
                print(f"Hashing file: {uploaded_file.filename}")
                STATE["hashed_strings"] = hash_bytes(file_bytes)
            elif plain_string:
                print(f"Hashing string: {plain_string}")
                STATE["hashed_strings"] = hash_string(plain_string)
            else:
                STATE["hashed_strings"] = None

        # ── Encoding ──────────────────────────────────────────────────────────
        elif action == "encode_string":
            data = request.form.get("encode_string")
            print(f"Encoding: {data}")
            STATE["encoded_string"] = encode_string(data)

        elif action == "decode_string":
            data = request.form.get("decode_string")
            print(f"Decoding: {data}")
            STATE["decoded_string"] = decode_string(data)

        # ── Subnet calculator ─────────────────────────────────────────────────
        elif action == "subnet_calc":
            base_network = request.form.get("base_network")
            requirements = request.form.get("requirements")
            print(f"Calculating subnets for {base_network}...")
            STATE["subnet"] = allocate_subnets(base_network, requirements)

    return get_template("utils.html", "utils")


# ─────────────────────────────────────────────
# Routes — System
# ─────────────────────────────────────────────

@app.route("/system", methods=["GET", "POST"])
def system():
    if request.method == "GET":
        return get_template("system.html", "system")

    action = request.form.get("action")

    # Map action names to (STATE key, tool function) pairs
    REFRESH_MAP = {
        "refresh_system":           ("system_info",             get_system_info),
        "refresh_cpu":              ("cpu_info",                get_cpu_mem_info),
        "refresh_storage":          ("storage_info",            get_storage_info),
        "refresh_network":          ("network_info",            get_network_adapters_info),
        "refresh_display":          ("display_info",            get_gpu_display_info),
        "refresh_power":            ("power_info",              get_power_battery_info),
        "refresh_sensors":          ("sensors_info",            get_sensors_and_temps),
        "refresh_process_services": ("process_services_info",   get_processes_services_info),
        "refresh_bios":             ("bios_info",               get_bios_motherboard_info),
        "refresh_devices":          ("devices_info",            get_connected_devices_info),
        "refresh_software":         ("software_info",           get_installed_software),
    }

    if action in REFRESH_MAP:
        key, func = REFRESH_MAP[action]
        STATE[key] = get_or_refresh(key, func, force=True)

    return get_template("system.html", "system")


# ─────────────────────────────────────────────
# Routes — Forensics
# ─────────────────────────────────────────────

@app.route("/forensics", methods=["GET", "POST"])
def forensics():
    if request.method == "POST":
        action = request.form.get("action")

        # ── File system forensics ─────────────────────────────────────────────
        if action == "forensics":
            import tempfile
            uploaded_file = request.files.get("target_file")
            target_path = (request.form.get("target_path") or "").strip()

            if uploaded_file and uploaded_file.filename != "":
                suffix = os.path.splitext(uploaded_file.filename)[1] or ".bin"
                try:
                    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                        uploaded_file.save(tmp)
                        tmp_path = tmp.name
                    STATE["forensics_results"] = collect_forensics_results(target_path=tmp_path)
                except Exception as e:
                    STATE["forensics_results"] = {"error": str(e)}
                finally:
                    try:
                        os.unlink(tmp_path)
                    except Exception:
                        pass
            elif target_path:
                try:
                    STATE["forensics_results"] = collect_forensics_results(target_path=target_path)
                except Exception as e:
                    STATE["forensics_results"] = {"error": str(e)}
            else:
                STATE["forensics_results"] = {"error": "Please upload a file or enter a valid file path."}
            save_cache("forensics_results", STATE["forensics_results"])

        # ── File analysis ─────────────────────────────────────────────────────
        elif action == "file_analysis":
            import tempfile
            uploaded_file = request.files.get("target_file")
            fa_target_path = (request.form.get("target_path") or "").strip()

            if uploaded_file and uploaded_file.filename != "":
                # Save to a temp file so analyze_file() can read it by path
                suffix = os.path.splitext(uploaded_file.filename)[1] or ".bin"
                try:
                    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                        uploaded_file.save(tmp)
                        tmp_path = tmp.name
                    STATE["file_analysis_results"] = analyze_file(tmp_path)
                except Exception as e:
                    STATE["file_analysis_results"] = {"error": str(e)}
                finally:
                    try:
                        os.unlink(tmp_path)
                    except Exception:
                        pass
            elif fa_target_path:
                try:
                    STATE["file_analysis_results"] = analyze_file(fa_target_path)
                except Exception as e:
                    STATE["file_analysis_results"] = {"error": str(e)}
            else:
                STATE["file_analysis_results"] = {"error": "Please upload a file or enter a valid file path."}
            save_cache("file_analysis_results", STATE["file_analysis_results"])

        # ── Malware sandbox ───────────────────────────────────────────────────
        elif action == "malware_sandbox":
            STATE["malware_report"] = None
            try:
                file = request.files.get("malware_file")
                if not file or file.filename == "":
                    raise ValueError("No file uploaded")
                uploaded_bytes = file.read()
                if not uploaded_bytes:
                    raise ValueError("Uploaded file is empty")
                STATE["malware_report"] = run_malware_sandbox(
                    uploaded_bytes=uploaded_bytes,
                    original_filename=file.filename,
                    quarantine_dir="quarantine",
                    export_json_path=None,
                )
            except Exception as e:
                STATE["malware_report"] = {"error": str(e)}
            save_cache("malware_report", STATE["malware_report"])

        # ── Image analysis ────────────────────────────────────────────────────
        elif action == "image_analysis":
            import tempfile
            uploaded_file = request.files.get("target_file")
            target_path = (request.form.get("target_path") or "").strip()

            if uploaded_file and uploaded_file.filename != "":
                suffix = os.path.splitext(uploaded_file.filename)[1] or ".bin"
                tmp_path = None
                try:
                    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                        uploaded_file.save(tmp)
                        tmp_path = tmp.name
                    STATE["image_analysis_results"] = analyze_image(tmp_path)
                except Exception as e:
                    STATE["image_analysis_results"] = {"error": str(e)}
                finally:
                    if tmp_path:
                        try:
                            os.unlink(tmp_path)
                        except Exception as e:
                            pass
            elif target_path:
                try:
                    STATE["image_analysis_results"] = analyze_image(target_path)
                except Exception as e:
                    STATE["image_analysis_results"] = {"error": str(e)}
            else:
                STATE["image_analysis_results"] = {"error": "Please upload an image or enter a valid file path."}

            save_cache("image_analysis_results", STATE["image_analysis_results"])

    return get_template("forensics.html", "forensics")


# ─────────────────────────────────────────────
# Routes — Security
# ─────────────────────────────────────────────

@app.route("/security", methods=["GET", "POST"])
def security():
    if request.method == "POST":
        action = request.form.get("action")

        # ── Vulnerability scanner ─────────────────────────────────────────────
        if action == "vuln_scan":
            try:
                vs_limit = int(request.form.get("vs_limit", 50))
            except ValueError:
                vs_limit = 50
            vs_limit = max(1, min(vs_limit, 500))
            vs_nmap  = (request.form.get("vs_nmap", "1") == "1")

            apps = []
            try:
                apps = (STATE["software_info"] or {}).get("apps", [])
                if not isinstance(apps, list):
                    apps = []
            except Exception:
                apps = []

            try:
                STATE["vuln_results"] = run_vulnerability_scanner(
                    installed_software=apps[:vs_limit],
                    use_nmap_if_available=vs_nmap,
                )
            except Exception as e:
                STATE["vuln_results"] = {"error": str(e)}
            save_cache("vuln_results", STATE["vuln_results"])

        # ── Persistence detection ─────────────────────────────────────────────
        elif action == "persistence_scan":
            try:
                STATE["persistence_results"] = persistence_detection()
            except Exception as e:
                STATE["persistence_results"] = {"error": str(e)}
            save_cache("persistence_results", STATE["persistence_results"])

        # ── Firewall analyser ─────────────────────────────────────────────────
        elif action == "firewall_scan":
            try:
                STATE["firewall_results"] = firewall_rules_analyser()
            except Exception as e:
                STATE["firewall_results"] = {"error": str(e)}
            save_cache("firewall_results", STATE["firewall_results"])

        # ── Open shares checker ───────────────────────────────────────────────
        elif action == "shares_scan":
            try:
                STATE["shares_results"] = open_shares_checker()
            except Exception as e:
                STATE["shares_results"] = {"error": str(e)}
            save_cache("shares_results", STATE["shares_results"])

        # ── Privilege escalation checks ───────────────────────────────────────
        elif action == "privesc_scan":
            try:
                STATE["privesc_results"] = privesc_checks()
            except Exception as e:
                STATE["privesc_results"] = {"error": str(e)}
            save_cache("privesc_results", STATE["privesc_results"])

    return get_template("security.html", "security")


# ─────────────────────────────────────────────
# Routes — Developer
# ─────────────────────────────────────────────

@app.route("/developer", methods=["GET", "POST"])
def developer():
    if request.method == "POST":
        action = request.form.get("action")

        # ── Python snippet runner ─────────────────────────────────────────────
        if action == "run_python":
            code    = request.form.get("code", "")
            timeout = int(request.form.get("timeout", 10))
            try:
                STATE["snippet_result"] = run_python_snippet(code, timeout=timeout)
            except Exception as e:
                STATE["snippet_result"] = {
                    "error": str(e), "stdout": "", "stderr": "",
                    "returncode": -1, "elapsed_ms": 0,
                    "language": "python", "code": code,
                }

        # ── PowerShell snippet runner ─────────────────────────────────────────
        elif action == "run_powershell":
            code    = request.form.get("code", "")
            timeout = int(request.form.get("timeout", 15))
            try:
                STATE["snippet_result"] = run_powershell_snippet(code, timeout=timeout)
            except Exception as e:
                STATE["snippet_result"] = {
                    "error": str(e), "stdout": "", "stderr": "",
                    "returncode": -1, "elapsed_ms": 0,
                    "language": "powershell", "code": code,
                }

        # ── Scheduled tasks ───────────────────────────────────────────────────
        elif action == "get_tasks":
            try:
                STATE["tasks_result"] = get_scheduled_tasks()
            except Exception as e:
                STATE["tasks_result"] = {"tasks": [], "count": 0, "errors": [str(e)]}

        elif action == "task_action":
            task_name   = request.form.get("task_name", "").strip()
            task_action = request.form.get("task_action", "")
            try:
                STATE["task_action_result"] = set_scheduled_task(task_name, task_action)
            except Exception as e:
                STATE["task_action_result"] = {"success": False, "output": "", "error": str(e)}

        # ── Script manager ────────────────────────────────────────────────────
        elif action == "load_scripts":
            try:
                STATE["scripts_result"] = get_script_manager_scripts()
            except Exception as e:
                STATE["scripts_result"] = {"scripts": {}, "error": str(e)}

        elif action == "save_script":
            name     = request.form.get("script_name", "").strip()
            language = request.form.get("script_language", "python")
            code     = request.form.get("script_code", "")
            try:
                save_script(name, language, code)
            except Exception as e:
                STATE["scripts_result"] = {"scripts": {}, "error": str(e)}
            # Reload so the UI reflects the saved script immediately
            STATE["scripts_result"] = get_script_manager_scripts()

        elif action == "delete_script":
            name = request.form.get("script_name", "").strip()
            try:
                delete_script(name)
            except Exception as e:
                STATE["scripts_result"] = {"scripts": {}, "error": str(e)}
            # Reload after deletion
            STATE["scripts_result"] = get_script_manager_scripts()

        elif action == "run_saved_script":
            name = request.form.get("script_name", "").strip()
            try:
                STATE["script_run_result"] = run_saved_script(name)
                STATE["scripts_result"]    = get_script_manager_scripts()
            except Exception as e:
                STATE["script_run_result"] = {
                    "error": str(e), "stdout": "", "stderr": "",
                    "returncode": -1, "elapsed_ms": 0,
                }

        # ── Event log viewer ──────────────────────────────────────────────────
        elif action == "get_event_log":
            log_name     = request.form.get("log_name", "System")
            max_events   = int(request.form.get("max_events", 200))
            level_filter = request.form.get("level_filter", "") or None
            search       = request.form.get("log_search", "").strip() or None
            try:
                STATE["event_log_result"] = get_event_log(
                    log_name=log_name,
                    max_events=max_events,
                    level_filter=level_filter,
                    search=search,
                )
            except Exception as e:
                STATE["event_log_result"] = {
                    "log_name": log_name, "events": [],
                    "count": 0, "errors": [str(e)],
                }

        # ── App log viewer ────────────────────────────────────────────────────
        elif action == "list_app_logs":
            try:
                STATE["app_log_files"] = list_app_logs()
            except Exception as e:
                STATE["app_log_files"] = {"files": [], "error": str(e)}

        elif action == "get_app_log":
            log_path  = request.form.get("log_file", "").strip()
            max_lines = int(request.form.get("max_lines", 500))
            search    = request.form.get("app_log_search", "").strip() or None
            try:
                STATE["app_log_result"] = get_app_log(
                    log_path=log_path,
                    max_lines=max_lines,
                    search=search,
                )
            except Exception as e:
                STATE["app_log_result"] = {
                    "log_path": log_path, "lines": [],
                    "count": 0, "truncated": False, "error": str(e),
                }

    return get_template("developer.html", "developer")


# ─────────────────────────────────────────────
# Routes — About
# ─────────────────────────────────────────────

@app.route("/about")
def about():
    return render_template("about.html", title="About", active="about")


# ─────────────────────────────────────────────
# Server Entry Point
# ─────────────────────────────────────────────

def run_flask():
    """Start the Flask development server (no reloader — required for PyInstaller)."""
    app.run(debug=False, host="127.0.0.1", port=5000, use_reloader=False)


if __name__ == "__main__":
    multiprocessing.freeze_support()

    parser = argparse.ArgumentParser(description="Cyber Toolkit")
    parser.add_argument("--nogui", action="store_true", default=False,
                        help="Run in CLI mode without the desktop window")
    args = parser.parse_args()

    if args.nogui:
        # ── CLI mode — Flask only ─────────────────────────────────────────────
        print("Running in CLI mode (no GUI)...")
        run_flask()
    else:
        # ── Desktop mode — Flask + pywebview ──────────────────────────────────
        print("Starting desktop window...")
        threading.Thread(target=run_flask, daemon=True).start()
        webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True
        webview.create_window(
            "Cyber Toolkit",
            "http://127.0.0.1:5000/",
            js_api=Api(),
            maximized=True,
            text_select=True,
        )
        webview.start()
