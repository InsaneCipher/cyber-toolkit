from flask import Flask, render_template, request
import time
from net_scan import *
from port_scan import *

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
port_results = None


@app.route("/", methods=["GET", "POST"])
def index():
    global result, dns_result, port_results

    if request.method == "POST":
        action = request.form.get("action")

        if action == "scan":
            timeout = int(request.form.get("timeout", 5))
            result = run_scan(timeout)
        elif action == "dns_lookup":
            print("Looking up DNS records...")
            ip = request.form.get("ip")
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "No hostname found"
            dns_result = {"ip": ip, "hostname": hostname}
        elif action == "port_scan":
            ports = int(request.form.get("ports"))
            print(f"Scanning ports 1-{ports}...")
            port_results = scan_ports(range(1, ports))

    return render_template("index.html", result=result, dns_result=dns_result, port_results=port_results)


if __name__ == "__main__":
    app.run(debug=False)
