from flask import Flask, render_template, request
from tools.net_scan import *
from tools.port_scan import *
from tools.recon_tools import *
from tools.process_scan import *
from tools.service_scan import *
from tools.hashing_and_encoding import *
from tools.subnet import *

app = Flask(__name__)


# Replace this with your existing scan function
def run_scan(timeout):
    results = net_scan(timeout)
    all_output = results[0]
    inbound_output = results[1]
    outbound_output = results[2]
    most_common_output = results[3]

    scan_result = {
        "all": all_output,
        "inbound": inbound_output,
        "outbound": outbound_output,
        "common": most_common_output
    }

    return scan_result


result = None
dns_result = None
trace_target = None
traceroute_result = None
whois_target = None
whois_result = None
port_results = None
cert_target = None
cert_result = None
running_processes = None
running_services = None
hashed_strings = None
subnet = None


@app.route("/", methods=["GET", "POST"])
def index():
    global result, dns_result, port_results, \
        traceroute_result, whois_result, \
        trace_target, whois_target, cert_target, \
        cert_result, running_processes, running_services, \
        hashed_strings, subnet

    if request.method == "POST":
        action = request.form.get("action")

        if action == "scan":
            timeout = int(request.form.get("timeout", 5))
            result = run_scan(timeout)

        elif action == "port_scan":
            ports = int(request.form.get("ports"))
            print(f"Scanning ports 1-{ports}...")
            port_results = scan_ports(range(1, ports))

        elif action == "process_scan":
            print(f"Scanning processes...")
            running_processes = scan_processes()

        elif action == "service_scan":
            print(f"Scanning services...")
            running_services = scan_services()

        elif action == "dns_lookup":
            print("Looking up DNS records...")
            ip = request.form.get("ip")
            dns_result = dns_lookup(ip)

        elif action == "traceroute":
            trace_target = request.form.get("trace_target")
            print(f"Running traceroute onm {trace_target}...")
            traceroute_result = traceroute(trace_target)

        elif action == "whois":
            whois_target = request.form.get("whois_target")
            print(f"Looking up whois records on {whois_target}...")
            whois_result = whois_lookup(whois_target)

        elif action == "cert_lookup":
            cert_target = request.form.get("cert_target")
            print(f"Looking up cert records on {cert_target}...")
            cert_result = cert_lookup(cert_target)

        elif action == "hash_encrypt":
            plain_string = request.form.get("plain_string")
            print(f"Hashing {plain_string}...")
            hashed_strings = hash_string(plain_string)

        elif action == "subnet_calc":
            base_network = request.form.get("base_network")
            requirements = request.form.get("requirements")
            print(f"Creating subnet for {base_network}...")
            subnet = allocate_subnets(base_network, requirements)

    return render_template("index.html",
                           result=result,
                           dns_result=dns_result,
                           port_results=port_results,
                           traceroute_result=traceroute_result,
                           trace_target=trace_target,
                           whois_result=whois_result,
                           whois_target=whois_target,
                           cert_result=cert_result,
                           cert_target=cert_target,
                           running_processes=running_processes,
                           running_services=running_services,
                           hashed_strings=hashed_strings,
                           subnet=subnet,
                           )


if __name__ == "__main__":
    app.run(debug=False)
