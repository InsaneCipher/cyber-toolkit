from flask import Flask, render_template, request
from torch.utils.model_dump import get_storage_info

from tools.diagnostics import get_dns_cache, ping_host, get_arp_table, get_interface_info
from tools.net_scan import *
from tools.port_scan import *
from tools.recon_tools import *
from tools.process_scan import *
from tools.service_scan import *
from tools.hashing_and_encoding import *
from tools.subnet import *
from tools.system_tools import *

app = Flask(__name__)


result = None
port_results = None
running_processes = None
running_services = None
dns_cache = None
dns_result = None
traceroute_result = None
whois_result = None
rev_whois_result = None
cert_result = None
trace_target = None
cert_target = None
hashed_strings = None
encoded_string = None
decoded_string = None
subnet = None
ping_result = None
arp_table = None
interface_info = None
rev_dns_result = None
geo_result = None
asn_result = None
header_result = None
response_result = None
tech_result = None
robots_result = None
system_info = get_system_info()
cpu_info = get_cpu_mem_info()
storage_info = get_storage_info()
network_info = get_network_adapters_info()
display_info = get_gpu_display_info()
power_info = get_system_info()
sensor_info = get_system_info()
motherboard_info = get_system_info()
devices_info = get_system_info()
software_info = get_system_info()


def get_template(name, active):
    return render_template(
        name,
        active=active,
        result=result,
        port_results=port_results,
        running_processes=running_processes,
        running_services=running_services,
        dns_cache=dns_cache,
        dns_result=dns_result,
        traceroute_result=traceroute_result,
        whois_result=whois_result,
        cert_result=cert_result,
        trace_target=trace_target,
        cert_target=cert_target,
        hashed_strings=hashed_strings,
        encoded_string=encoded_string,
        decoded_string=decoded_string,
        subnet=subnet,
        ping_result=ping_result,
        arp_table=arp_table,
        interface_info=interface_info,
        rev_dns_result=rev_dns_result,
        geo_result=geo_result,
        rev_whois_result=rev_whois_result,
        asn_result=asn_result,
        header_result=header_result,
        response_result=response_result,
        tech_result=tech_result,
        robots_result=robots_result,
        system_info=system_info,
        cpu_info=cpu_info,
        storage_info=storage_info,
        network_info=network_info,
        display_info=display_info,
        power_info=power_info,
        sensor_info=sensor_info,
        motherboard_info=motherboard_info,
        devices_info=devices_info,
        software_info=software_info,
    )


# -------------------------------------
# Network Page
# -------------------------------------

@app.route("/", methods=["GET", "POST"])
@app.route("/network", methods=["GET", "POST"])
def network():
    global result, port_results, dns_cache, ping_result, arp_table, interface_info

    if request.method == "POST":
        action = request.form.get("action")

        if action == "scan":
            timeout = int(request.form.get("timeout", 5))
            print(f"Running network scan for {timeout} seconds...")
            results = net_scan(timeout)
            result = {
                "all": results[0],
                "inbound": results[1],
                "outbound": results[2],
                "common": results[3],
            }

        elif action == "port_scan":
            ports = int(request.form.get("ports"))
            print(f"Scanning ports 1–{ports}...")
            port_results = scan_ports(range(1, ports))

        elif action == "ping_host":
            host = request.form.get("ping_target")
            print(f"Pinging {host}...")
            ping_result = ping_host(host)

        elif action == "arp_table":
            print("Scanning dns cache...")
            arp_table = get_arp_table()

        elif action == "interface_info":
            print("Scanning dns cache...")
            interface_info = get_interface_info()

        elif action == "dns_cache":
            print("Scanning dns cache...")
            dns_cache = get_dns_cache()

    return get_template("index.html", "network")


# -------------------------------------
# Recon Page
# -------------------------------------
@app.route("/recon", methods=["GET", "POST"])
def recon():
    global dns_result, traceroute_result, whois_result, cert_result, trace_target, cert_target, \
        rev_dns_result, geo_result, rev_whois_result, asn_result, header_result, response_result, \
        tech_result, robots_result

    if request.method == "POST":
        action = request.form.get("action")

        if action == "dns_lookup":
            domain = request.form.get("dns_domain")
            print(f"Running DNS lookup on {domain}...")
            dns_result = dns_lookup(domain)

        elif action == "rev_dns_lookup":
            ip = request.form.get("dns_ip")
            print(f"Running Reverse DNS lookup on {ip}...")
            rev_dns_result = reverse_dns_lookup(ip)
            print(rev_dns_result)

        elif action == "traceroute":
            trace_target = request.form.get("trace_target")
            print(f"Running traceroute on {trace_target}...")
            traceroute_result = traceroute(trace_target)

        elif action == "ip_geo":
            ip = request.form.get("geo_ip")
            print(f"Running geolocation finding on {ip}...")
            geo_result = ip_geolocation(ip)

        elif action == "whois":
            target = request.form.get("whois_target")
            print(f"Running WHOIS lookup on {target}...")
            whois_result = whois_lookup(target)

        elif action == "rev_whois":
            query = request.form.get("rev_whois_target")
            tld_filter = request.form.get("tld_filter", "").strip()
            exact_match = bool(request.form.get("exact_match"))
            print(f"Running reverse WHOIS lookup on {query}, exact match: {exact_match} and filter: {tld_filter}...")
            # rev_whois_result = reverse_whois(query, tld_filter, exact_match)
            rev_whois_result = {"query": query, "error": "Feature currently unavailable!"}

        elif action == "cert_lookup":
            cert_target = request.form.get("cert_target")
            print(f"Inspecting certificate for {cert_target}...")
            cert_result = cert_lookup(cert_target)

        elif action == "asn_lookup":
            asn_ip = request.form.get("asn_ip")
            print(f"Inspecting certificate for {asn_ip}...")
            asn_result = asn_lookup(asn_ip)

        elif action == "http_headers":
            url = request.form.get("header_url")
            print(f"Analysing headers for {url}...")
            header_result = http_header_analyser(url)

        elif action == "http_response":
            url = request.form.get("resp_url")
            print(f"Analysing headers for {url}...")
            response_result = http_response_viewer(url)

        elif action == "tech_fingerprint":
            url = request.form.get("tech_url")
            print(f"Analysing headers for {url}...")
            tech_result = technology_fingerprinting(url)

        elif action == "robots_sitemap":
            url = request.form.get("robots_url")
            print(f"Analysing headers for {url}...")
            robots_result = robots_sitemap_viewer(url)

    return get_template("recon.html", "recon")


# -------------------------------------
# Utilities Page
# -------------------------------------
@app.route("/utils", methods=["GET", "POST"])
def utils():
    global result, port_results, running_processes, running_services, dns_cache, dns_result, \
        traceroute_result, whois_result, cert_result, trace_target, cert_target, \
        hashed_strings, encoded_string, decoded_string, subnet

    if request.method == "POST":
        action = request.form.get("action")

        if action == "hash_encrypt":
            plain_string = request.form.get("plain_string")
            uploaded_file = request.files.get("file_input")

            if plain_string and uploaded_file and uploaded_file.filename != "":
                hashed_strings = None
            elif uploaded_file and uploaded_file.filename != "":
                file_bytes = uploaded_file.read()
                print(f"Hashing file: {uploaded_file.filename}")
                hashed_strings = hash_bytes(file_bytes)
            elif plain_string:
                print(f"Hashing string: {plain_string}")
                hashed_strings = hash_string(plain_string)
            else:
                hashed_strings = None

        elif action == "encode_string":
            data = request.form.get("encode_string")
            print(f"Encoding: {data}")
            encoded_string = encode_string(data)

        elif action == "decode_string":
            data = request.form.get("decode_string")
            print(f"Decoding: {data}")
            decoded_string = decode_string(data)

        elif action == "subnet_calc":
            base_network = request.form.get("base_network")
            requirements = request.form.get("requirements")
            print(f"Calculating subnets for {base_network}")
            subnet = allocate_subnets(base_network, requirements)

    return get_template("utils.html", "utils")


@app.route("/system")
def system():
    global system_info, running_services, running_processes

    if request.method == "POST":
        action = request.form.get("action")

        if action == "process_scan":
            print("Scanning processes...")
            running_processes = scan_processes()

        elif action == "service_scan":
            print("Scanning services...")
            running_services = scan_services()

    return get_template("system.html", "system")


@app.route("/forensics")
def forensics():
    return get_template("forensics.html", "forensics")


@app.route("/security")
def security():
    return get_template("security.html", "security")


@app.route("/developer")
def developer():
    return get_template("developer.html", "developer")


@app.route("/about")
def about():
    return render_template("about.html", title="About", active="about")


if __name__ == "__main__":
    app.run()