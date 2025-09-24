import socket
from concurrent.futures import ThreadPoolExecutor


def scan_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.3)
    try:
        if sock.connect_ex((host, port)) == 0:
            return port
    except:
        pass
    finally:
        sock.close()
    return None


def scan_ports(ports=range(1, 1025)):
    host = "127.0.0.1"
    workers = 50
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = executor.map(lambda p: scan_port(host, p), ports)

    for port in results:
        if port:
            open_ports.append({'port': port})
    return open_ports


if __name__ == "__main__":
    target_host = "127.0.0.1"
    open_ports = scan_ports()
    print(f"Open ports: {open_ports}")
