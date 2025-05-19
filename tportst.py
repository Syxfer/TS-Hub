import socket
import threading
import time
from queue import Queue


def scan_port(ip_address, port, results):
    """Scans a single port on the given IP address."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set a timeout for the connection attempt
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            try:
                service_name = socket.getservbyport(port, 'tcp')
            except socket.error:
                service_name = "Unknown"
            results.append(f"Port {port} is open - {service_name}")
        sock.close()
    except socket.error as e:
        print(f"Error scanning port {port}: {e}")

def port_scanner(ip_address, port_list):
    """Scans a list of ports on the given IP address using threads."""
    print(f"Scanning ports on {ip_address}...")
    results = []
    threads = []
    for port in port_list:
        thread = threading.Thread(target=scan_port, args=(ip_address, port, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()  # Wait for all threads to complete

    if results:
        print(f"\nOpen ports on {ip_address}:")
        for result in sorted(results):
            print(result)
    else:
        print(f"\nNo open ports found on {ip_address} within the scanned range.")

def get_port_range():
    """Gets the port range to scan from the user."""
    while True:
        port_range_str = input("Enter the port range to scan (e.g., 1-1024, or a single port like 80): ")
        if '-' in port_range_str:
            try:
                start_port, end_port = map(int, port_range_str.split('-'))
                if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                    return list(range(start_port, end_port + 1))
                else:
                    print("Invalid port range. Ports must be between 1 and 65535.")
            except ValueError:
                print("Invalid port range format. Please use 'start-end' or a single port number.")
        else:
            try:
                single_port = int(port_range_str)
                if 1 <= single_port <= 65535:
                    return [single_port]
                else:
                    print("Invalid port number. Port must be between 1 and 65535.")
            except ValueError:
                print("Invalid input. Please enter a valid port range or a single port number.")

if __name__ == "__main__":
    target_ip = input("Enter the target IP address to scan > ")
    ports_to_scan = get_port_range()

    start_time = time.time()
    port_scanner(target_ip, ports_to_scan)
    end_time = time.time()

    print(f"\nPort scan completed in {end_time - start_time:.2f} seconds.")