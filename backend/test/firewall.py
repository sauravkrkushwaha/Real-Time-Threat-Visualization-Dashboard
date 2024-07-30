import os
import sys
import ctypes
import socket
import struct

# Define the IP address and port to listen on (e.g., for a specific network interface)
HOST = '0.0.0.0'
PORT = 0  # Listen to all ports

# Define basic rules (e.g., block a specific IP address)
BLOCKED_IPS = ['192.168.1.100']
BLOCKED_PORTS = [80, 443]

def ip_to_str(ip):
    """Convert a packed IP address to a string."""
    return socket.inet_ntoa(ip)

def parse_packet(packet):
    """Parse the IP packet header and return source/destination addresses and ports."""
    ip_header = packet[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

    # Extract source and destination IP addresses
    source_ip = ip_to_str(iph[8])
    dest_ip = ip_to_str(iph[9])

    # Extract protocol (TCP = 6, UDP = 17)
    protocol = iph[6]

    source_port, dest_port = None, None
    if protocol == 6:  # TCP
        tcp_header = packet[20:40]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
        source_port = tcph[0]
        dest_port = tcph[1]
    elif protocol == 17:  # UDP
        udp_header = packet[20:28]
        udph = struct.unpack('!HHHH', udp_header)
        source_port = udph[0]
        dest_port = udph[1]

    return source_ip, dest_ip, source_port, dest_port

def firewall(packet):
    """Basic firewall logic to filter packets."""
    source_ip, dest_ip, source_port, dest_port = parse_packet(packet)

    # Block traffic from/to specific IP addresses or ports
    if source_ip in BLOCKED_IPS or dest_ip in BLOCKED_IPS:
        print(f"Blocked packet from/to {source_ip} <-> {dest_ip}")
        return

    if source_port in BLOCKED_PORTS or dest_port in BLOCKED_PORTS:
        print(f"Blocked packet on port {source_port} or {dest_port}")
        return

    # Allow other packets
    print(f"Allowed packet from {source_ip}:{source_port} to {dest_ip}:{dest_port}")

def request_admin_privileges():
    if os.name == 'nt':
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("Requesting administrative privileges...")
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, ' '.join(sys.argv), None, 1)
                print("Elevated privileges requested.")
                sys.exit(0)
        except Exception as e:
            print(f"Failed to elevate privileges: {e}")
            sys.exit(1)


def main():
    request_admin_privileges()

    try:
        print("Initializing socket...")
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((HOST, PORT))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        print("Firewall is running...")

        while True:
            try:
                packet, addr = s.recvfrom(65565)
                firewall(packet)
            except KeyboardInterrupt:
                print("Terminating firewall...")
                break
            except Exception as e:
                print(f"Error during packet capture: {e}")

    except Exception as e:
        print(f"Error initializing socket: {e}")

if __name__ == "__main__":
    main()
