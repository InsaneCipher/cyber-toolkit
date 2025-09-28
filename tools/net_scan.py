from scapy.all import sniff, conf, get_if_addr
from collections import Counter
import socket
import ipaddress


def should_resolve(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_multicast)
    except ValueError:
        return False


dns_cache = {}


def reverse_dns(ip):

    if ip in dns_cache:
        return dns_cache[ip]
    if not should_resolve(ip):
        dns_cache[ip] = ip
        return ip
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        dns_cache[ip] = hostname
        return hostname
    except (socket.herror, socket.gaierror):
        dns_cache[ip] = ip
        return ip


def net_scan(timeout):
    counter = Counter()

    def packet_callback(packet):
        if packet.haslayer("IP"):
            ip_layer = packet["IP"]
            key = (ip_layer.src, ip_layer.dst)
            counter[key] += 1

    # Capture for 30s
    print(f"Sniffing for {timeout} seconds...")
    sniff(prn=packet_callback, timeout=timeout)

    iface = conf.iface  # default interface name (e.g. "eth0" or "Wi-Fi")
    my_ip = get_if_addr(iface)
    print("Device IP:", my_ip)

    results_all = []
    for (src, dst), count in counter.most_common(1000):
        if src == my_ip:
            src = "DEVICE_IP"
        if dst == my_ip:
            dst = "DEVICE_IP"

        src_hostname = reverse_dns(src)
        dst_hostname = reverse_dns(dst)

        results_all.append({
            'src': src,
            'dst': dst,
            'count': count,
            'src_hostname': src_hostname,
            'dst_hostname': dst_hostname,
        })

    print(results_all)

    results_most_common = []
    for (src, dst), count in counter.most_common(10):
        if src == my_ip:
            src = "DEVICE_IP"
        if dst == my_ip:
            dst = "DEVICE_IP"
        src_hostname = reverse_dns(src)
        dst_hostname = reverse_dns(dst)
        results_most_common.append({
            'src': src,
            'dst': dst,
            'count': count,
            'src_hostname': src_hostname,
            'dst_hostname': dst_hostname,
        })

    results_inbound = []
    for (src, dst), count in counter.most_common(1000):
        if dst == my_ip:
            dst = "DEVICE_IP"
            src_hostname = reverse_dns(src)
            dst_hostname = reverse_dns(dst)
            results_inbound.append({
                'src': src,
                'dst': dst,
                'count': count,
                'src_hostname': src_hostname,
                'dst_hostname': dst_hostname,
            })

    results_outbound = []
    for (src, dst), count in counter.most_common(1000):
        if src == my_ip:
            src = "DEVICE_IP"
            src_hostname = reverse_dns(src)
            dst_hostname = reverse_dns(dst)
            results_outbound.append({
                'src': src,
                'dst': dst,
                'count': count,
                'src_hostname': src_hostname,
                'dst_hostname': dst_hostname,
            })

    return [results_all, results_inbound, results_outbound, results_most_common]

