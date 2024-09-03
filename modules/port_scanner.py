import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            logging.info(f"Port {port} is open on {host}")
            return port
        sock.close()
    except Exception as e:
        logging.error(f"Error scanning port {port} on {host}: {e}")
    return None

def scan_ports(host, ports):
    open_ports = []
    with ThreadPoolExecutor(max_workers=10) as executor:  # You can adjust max_workers as needed
        futures = {executor.submit(scan_port, host, port): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            result = future.result()
            if result is not None:
                open_ports.append(result)
    return open_ports