from flask import Flask, render_template, request
from tools.net_scan import *
from tools.port_scan import *
from tools.recon_tools import *
from tools.process_scan import *
from tools.service_scan import *
from tools.hashing_and_encoding import *
from tools.subnet import *

app = Flask(__name__)


# -------------------------------------
# Network Page
# -------------------------------------
@app.route("/", methods=["GET", "POST"])
@app.route("/network", methods=["GET", "POST"])
def network():
    result = None
    port_results = None
    running_processes = None
    running_services = None

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

        elif action == "process_scan":
            print("Scanning processes...")
            running_processes = scan_processes()

        elif action == "service_scan":
            print("Scanning services...")
            running_services = scan_services()

    return render_template(
        "index.html",
        active="network",
        result=result,
        port_results=port_results,
        running_processes=running_processes,
        running_services=running_services,
    )


# -------------------------------------
# Recon Page
# -------------------------------------
@app.route("/recon", methods=["GET", "POST"])
def recon():
    dns_result = None
    traceroute_result = None
    whois_result = None
    cert_result = None
    trace_target = None
    whois_target = None
    cert_target = None

    if request.method == "POST":
        action = request.form.get("action")

        if action == "dns_lookup":
            ip = request.form.get("ip")
            print(f"Running DNS lookup on {ip}")
            dns_result = dns_lookup(ip)

        elif action == "traceroute":
            trace_target = request.form.get("trace_target")
            print(f"Running traceroute on {trace_target}")
            traceroute_result = traceroute(trace_target)

        elif action == "whois":
            whois_target = request.form.get("whois_target")
            print(f"Running WHOIS lookup on {whois_target}")
            whois_result = whois_lookup(whois_target)

        elif action == "cert_lookup":
            cert_target = request.form.get("cert_target")
            print(f"Inspecting certificate for {cert_target}")
            cert_result = cert_lookup(cert_target)

    return render_template(
        "recon.html",
        active="recon",
        dns_result=dns_result,
        traceroute_result=traceroute_result,
        whois_result=whois_result,
        cert_result=cert_result,
        trace_target=trace_target,
        whois_target=whois_target,
        cert_target=cert_target,
    )


# -------------------------------------
# Utilities Page
# -------------------------------------
@app.route("/utils", methods=["GET", "POST"])
def utils():
    hashed_strings = None
    encoded_string = None
    decoded_string = None
    subnet = None

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

    return render_template(
        "utils.html",
        active="utils",
        hashed_strings=hashed_strings,
        encoded_string=encoded_string,
        decoded_string=decoded_string,
        subnet=subnet,
    )

if __name__ == "__main__":
    app.run(debug=True)
