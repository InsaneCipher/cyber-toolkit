from flask import Flask, render_template, request
import webview
import argparse
import threading
import sys
import os
import multiprocessing

from tools.diagnostics import get_dns_cache, ping_host, get_arp_table, get_interface_info
from tools.net_scan import *
from tools.port_scan import *
from tools.recon_tools import *
from tools.hashing_and_encoding import *
from tools.subnet import *
from tools.system_tools import *
from tools.forensics_tools import *
from tools.caching_tools import *

STATE = {
    # network
    "result": None,
    "port_results": None,
    "dns_cache": None,
    "ping_result": None,
    "arp_table": None,
    "interface_info": None,

    # recon
    "dns_result": None,
    "traceroute_result": None,
    "whois_result": None,
    "rev_whois_result": None,
    "cert_result": None,
    "trace_target": None,
    "cert_target": None,
    "rev_dns_result": None,
    "geo_result": None,
    "asn_result": None,
    "header_result": None,
    "response_result": None,
    "tech_result": None,
    "robots_result": None,

    # utils
    "hashed_strings": None,
    "encoded_string": None,
    "decoded_string": None,
    "subnet": None,

    # system (loaded lazily)
    "system_info": None,
    "cpu_info": None,
    "storage_info": None,
    "network_info": None,
    "display_info": None,
    "power_info": None,
    "sensors_info": None,
    "process_services_info": None,
    "bios_info": None,
    "devices_info": None,
    "software_info": None,

    # forensics tools (load cache only initially)
    "forensics_results": None,
    "vuln_results": None,
    "file_analysis_results": None,
    "malware_report": None,
    "image_analysis_results": None,
}


def init_cached_state():
    # system info: don’t compute at import. load cache only if present.
    for key in [
        "system_info", "cpu_info", "storage_info", "network_info", "display_info",
        "power_info", "sensors_info", "process_services_info", "bios_info",
        "devices_info", "software_info",
    ]:
        if STATE[key] is None:
            STATE[key] = get_or_refresh(key, lambda: {"error": "not loaded"}, load_only=True)

    # forensics outputs: load cache only
    for key in ["forensics_results", "vuln_results", "file_analysis_results", "malware_report", "image_analysis_results"]:
        if STATE[key] is None:
            STATE[key] = get_or_refresh(key, lambda: {"error": "not loaded"}, load_only=True)


def resource_path(relative_path: str) -> str:
    # When packaged, PyInstaller extracts to sys._MEIPASS
    base = getattr(sys, "_MEIPASS", os.path.abspath("."))
    return os.path.join(base, relative_path)


def create_app():
    app = Flask(
        __name__,
        template_folder=resource_path("templates"),
        static_folder=resource_path("static"),
    )
    # register routes here
    return app


app = create_app()


def get_template(name, active):
    return render_template(
        name,
        active=active,
        **STATE
    )


_state_inited = False


@app.before_request
def _before():
    global _state_inited
    if not _state_inited:
        init_cached_state()
        _state_inited = True


# -------------------------------------
# Network Page
# -------------------------------------

@app.route("/", methods=["GET", "POST"])
@app.route("/network", methods=["GET", "POST"])
def network():
    if request.method == "POST":
        action = request.form.get("action")

        if action == "scan":
            timeout = int(request.form.get("timeout", 5))
            print(f"Running network scan for {timeout} seconds...")
            results = net_scan(timeout)
            STATE["result"]= {
                "all": results[0],
                "inbound": results[1],
                "outbound": results[2],
                "common": results[3],
            }

        elif action == "port_scan":
            ports = int(request.form.get("ports"))
            print(f"Scanning ports 1–{ports}...")
            STATE["port_results"] = scan_ports(range(1, ports))

        elif action == "ping_host":
            host = request.form.get("ping_target")
            print(f"Pinging {host}...")
            STATE["ping_result"] = ping_host(host)

        elif action == "arp_table":
            print("Scanning dns cache...")
            STATE["arp_table"] = get_arp_table()

        elif action == "interface_info":
            print("Scanning dns cache...")
            STATE["interface_info"] = get_interface_info()

        elif action == "dns_cache":
            print("Scanning dns cache...")
            STATE["dns_cache"] = get_dns_cache()

    return get_template("index.html", "network")


# -------------------------------------
# Recon Page
# -------------------------------------
@app.route("/recon", methods=["GET", "POST"])
def recon():
    if request.method == "POST":
        action = request.form.get("action")

        if action == "dns_lookup":
            domain = request.form.get("dns_domain")
            print(f"Running DNS lookup on {domain}...")
            STATE["dns_result"] = dns_lookup(domain)

        elif action == "rev_dns_lookup":
            ip = request.form.get("dns_ip")
            print(f"Running Reverse DNS lookup on {ip}...")
            STATE["rev_dns_result"] = reverse_dns_lookup(ip)

        elif action == "traceroute":
            STATE["trace_target"] = request.form.get("trace_target")
            print(f"Running traceroute on {STATE["trace_target"]}...")
            STATE["traceroute_result"] = traceroute(STATE["trace_target"])

        elif action == "ip_geo":
            ip = request.form.get("geo_ip")
            print(f"Running geolocation finding on {ip}...")
            STATE["geo_result"] = ip_geolocation(ip)

        elif action == "whois":
            target = request.form.get("whois_target")
            print(f"Running WHOIS lookup on {target}...")
            STATE["whois_result"] = whois_lookup(target)

        elif action == "rev_whois":
            query = request.form.get("rev_whois_target")
            tld_filter = request.form.get("tld_filter", "").strip()
            exact_match = bool(request.form.get("exact_match"))
            print(f"Running reverse WHOIS lookup on {query}, exact match: {exact_match} and filter: {tld_filter}...")
            STATE["rev_whois_result"] = {"query": query, "error": "Feature currently unavailable!"}

        elif action == "cert_lookup":
            STATE["cert_target"] = request.form.get("cert_target")
            print(f"Inspecting certificate for {STATE["cert_target"]}...")
            STATE["cert_result"] = cert_lookup(STATE["cert_target"])

        elif action == "asn_lookup":
            asn_ip = request.form.get("asn_ip")
            print(f"Inspecting certificate for {asn_ip}...")
            STATE["asn_result"] = asn_lookup(asn_ip)

        elif action == "http_headers":
            url = request.form.get("header_url")
            print(f"Analysing headers for {url}...")
            STATE["header_result"] = http_header_analyser(url)

        elif action == "http_response":
            url = request.form.get("resp_url")
            print(f"Analysing headers for {url}...")
            STATE["response_result"] = http_response_viewer(url)

        elif action == "tech_fingerprint":
            url = request.form.get("tech_url")
            print(f"Analysing headers for {url}...")
            STATE["tech_result"] = technology_fingerprinting(url)

        elif action == "robots_sitemap":
            url = request.form.get("robots_url")
            print(f"Analysing headers for {url}...")
            STATE["robots_result"] = robots_sitemap_viewer(url)

    return get_template("recon.html", "recon")


# -------------------------------------
# Utilities Page
# -------------------------------------
@app.route("/utils", methods=["GET", "POST"])
def utils():
    if request.method == "POST":
        action = request.form.get("action")

        if action == "hash_encrypt":
            plain_string = request.form.get("plain_string")
            uploaded_file = request.files.get("file_input")

            if plain_string and uploaded_file and uploaded_file.filename != "":
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

        elif action == "encode_string":
            data = request.form.get("encode_string")
            print(f"Encoding: {data}")
            STATE["encoded_string"] = encode_string(data)

        elif action == "decode_string":
            data = request.form.get("decode_string")
            print(f"Decoding: {data}")
            STATE["decoded_string"] = decode_string(data)

        elif action == "subnet_calc":
            base_network = request.form.get("base_network")
            requirements = request.form.get("requirements")
            print(f"Calculating subnet's for {base_network}")
            STATE["subnet"] = allocate_subnets(base_network, requirements)

    return get_template("utils.html", "utils")


@app.route("/system", methods=["GET", "POST"])
def system():

    # Page load
    if request.method == "GET":
        return get_template("system.html", "system")

    # AJAX actions
    action = request.form.get("action")

    REFRESH_MAP = {
        "refresh_system": ("system_info", get_system_info),
        "refresh_cpu": ("cpu_info", get_cpu_mem_info),
        "refresh_storage": ("storage_info", get_storage_info),
        "refresh_network": ("network_info", get_network_adapters_info),
        "refresh_display": ("display_info", get_gpu_display_info),
        "refresh_power": ("power_info", get_power_battery_info),
        "refresh_sensors": ("sensors_info", get_sensors_and_temps),
        "refresh_process_services": ("process_services_info", get_processes_services_info),
        "refresh_bios": ("bios_info", get_bios_motherboard_info),
        "refresh_devices": ("devices_info", get_connected_devices_info),
        "refresh_software": ("software_info", get_installed_software),
    }

    if action in REFRESH_MAP:
        key, func = REFRESH_MAP[action]
        STATE[key] = get_or_refresh(key, func, force=True)

    return get_template("system.html", "system")


@app.route("/forensics", methods=["GET", "POST"])
def forensics():
    if request.method == "POST":
        action = request.form.get("action")

        if action == "forensics":
            target_path = None
            STATE["forensics_results"] = None

            # Matches the HTML input name="target_path"
            target_path = (request.form.get("target_path") or "").strip()

            if target_path:
                try:
                    # Your collector (from tools.forensics_tools import *)
                    STATE["forensics_results"] = collect_forensics_results(target_path=target_path)
                except Exception as e:
                    STATE["forensics_results"] = {"error": str(e)}
            else:
                STATE["forensics_results"] = {"error": "Please enter a valid file path."}

            # Optional: store last run globally if you want it accessible elsewhere
            save_cache("forensics_results", STATE["forensics_results"])

        elif action == "file_analysis":
            # HTML uses name="target_path" for the input in the File Analysis form
            fa_target_path = (request.form.get("target_path") or "").strip()

            if fa_target_path:
                try:
                    # Use your file analysis function (e.g., analyze_file from tools.forensics_tools)
                    STATE["file_analysis_results"] = analyze_file(fa_target_path)
                except Exception as e:
                    STATE["file_analysis_results"] = {"error": str(e)}
            else:
                STATE["file_analysis_results"] = {"error": "Please enter a valid file path."}

            save_cache("file_analysis_results", STATE["file_analysis_results"])

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
                    export_json_path=None,  # or f"reports/{uuid}.json"
                )

            except Exception as e:
                STATE["malware_report"] = {"error": str(e)}

            save_cache("malware_report", STATE["malware_report"])

        elif action == "image_analysis":
            # HTML uses name="target_path" for the input in the Image Analysis form
            target_path = (request.form.get("target_path") or "").strip()

            if target_path:
                try:
                    # Use your image analysis function
                    STATE["image_analysis_results"] = analyze_image(target_path)
                except Exception as e:
                    STATE["image_analysis_results"] = {"error": str(e)}
            else:
                STATE["image_analysis_results"] = {"error": "Please enter a valid image file path."}

            save_cache("image_analysis_results", STATE["image_analysis_results"])

    # Render with your existing shared context + add forensics vars
    return get_template("forensics.html", "forensics")


@app.route("/security", methods=["GET", "POST"])
def security():
    if request.method == "POST":
        action = request.form.get("action")

        if action == "vuln_scan":
            # Read form inputs
            try:
                vs_limit = int(request.form.get("vs_limit", 50))
            except ValueError:
                vs_limit = 50

            vs_limit = max(1, min(vs_limit, 500))
            vs_nmap = (request.form.get("vs_nmap", "1") == "1")

            # Your installed software is in STATE["software_info"]["apps"]
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
                    use_nmap_if_available=vs_nmap
                )
            except Exception as e:
                STATE["vuln_results"] = {"error": str(e)}

            save_cache("vuln_results", STATE["vuln_results"])

    return get_template("security.html", "security")


@app.route("/developer")
def developer():
    return get_template("developer.html", "developer")


@app.route("/about")
def about():
    return render_template("about.html", title="About", active="about")


def run_flask():
    """Start Flask server (used for CLI mode or background threading)."""
    app.run(debug=False, host="127.0.0.1", port=5000, use_reloader=False)


if __name__ == "__main__":
    multiprocessing.freeze_support()

    # Parse CLI arguments
    parser = argparse.ArgumentParser(description="CyberToolkit App")
    parser.add_argument('--nogui', action='store_true', default=False, help='Run without GUI (CLI mode)')
    args = parser.parse_args()

    # Run Flask server either as CLI only or with GUI using webview
    if args.nogui:
        print("Running without GUI...")
        run_flask()
    else:
        print("Running with GUI...")
        # Run Flask server in background thread
        threading.Thread(target=run_flask, daemon=True).start()
        webview.settings['OPEN_EXTERNAL_LINKS_IN_BROWSER'] = True
        webview.create_window(
            "Cyber Toolkit App",
            "http://127.0.0.1:5000/",
            js_api=Api(),
            maximized=True,
            text_select=True
        )
        webview.start()  # Start the GUI event loop
