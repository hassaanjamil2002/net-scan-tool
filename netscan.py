## HASSAAN JAMIL i212774

import subprocess
import ipaddress
import re
from scapy.all import IP, ICMP, sr1

def icmp_echo_ping(target_ip):
    ping_cmd = ["ping", "-c", "1", "-W", "1", target_ip]  # Set a timeout of 1 second
    try:
        # Execute the ping command
        output = subprocess.check_output(ping_cmd, stderr=subprocess.STDOUT, universal_newlines=True)
        # Check if the output contains a successful response
        if "ttl=" in output.lower():
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        return False

def icmp_echo_sweep(network):
    reachable_hosts = []
    network = ipaddress.ip_network(network)
    for ip in network.hosts():
        ip = str(ip)
        if icmp_echo_ping(ip):
            reachable_hosts.append(ip)
    return reachable_hosts

def icmp_timestamp_request(target_ip):
    ping_cmd = ["ping", "-c", "1", "-Q", "13", "-p", "7375", target_ip]
    try:
        # Execute the ping command
        output = subprocess.check_output(ping_cmd, stderr=subprocess.STDOUT, universal_newlines=True)
        # Check if the output contains a successful response
        if "ttl=" in output.lower():
            timestamp_info = extract_timestamp_info(output)
            if timestamp_info:
                return True, timestamp_info
            else:
                return True, None
        else:
            return False, None
    except subprocess.CalledProcessError:
        return False, None

def icmp_address_mask_ping(target_ip):
    icmp = IP(dst=target_ip)/ICMP(type=17, code=0)  # Type 17 for Address Mask Request
    try:
        # Send ICMP Address Mask Ping request and wait for response
        response = sr1(icmp, timeout=1, verbose=False)
        # Check if there's a response packet
        if response:
            # If the response is an ICMP Address Mask Reply, the host is reachable
            if response[ICMP].type == 18:  # ICMP Address Mask Reply type is 18
                return True
    except Exception as e:
        pass  # Ignore any exceptions (e.g., timeout, errors)

    return False

def extract_timestamp_info(output):
    # Regular expression to match timestamp information
    timestamp_regex = r"icmp_seq=\d+ ttl=\d+ time=\d+\.\d+ ms icmp_tx_timestamp=(\d+) icmp_rx_timestamp=(\d+)"
    match = re.search(timestamp_regex, output)
    if match:
        icmp_tx_timestamp = int(match.group(1))
        icmp_rx_timestamp = int(match.group(2))
        return icmp_tx_timestamp, icmp_rx_timestamp
    else:
        return None

def tcp_syn_scan(target_ip, port):
    # Construct the netcat command to send a TCP SYN packet to the target IP and port
    nc_cmd = ["nc", "-z", "-n", "-v", "-w", "1", "-G", "1", target_ip, str(port)]
    try:
        # Execute the netcat command
        output = subprocess.check_output(nc_cmd, stderr=subprocess.STDOUT, universal_newlines=True)
        # Check if the output contains a successful connection message
        if "succeeded" in output.lower():
            return True  # Port is open
        else:
            return False  # Port is closed
    except subprocess.CalledProcessError:
        return False  # Port is closed

def tcp_ack_scan(target_ip, port):
    # Construct the netcat command to send a TCP ACK packet to the target IP and port
    nc_cmd = ["nc", "-z", "-n", "-v", "-w", "1", "-G", "1", "-A", "1", target_ip, str(port)]
    try:
        # Execute the netcat command
        output = subprocess.check_output(nc_cmd, stderr=subprocess.STDOUT, universal_newlines=True)
        # Check if the output contains a successful connection message
        if "succeeded" in output.lower():
            return True  # Port is unfiltered
        elif "filtered" in output.lower():
            return False  # Port is filtered
        else:
            return False  # Unable to determine port status
    except subprocess.CalledProcessError:
        return False  # Port is filtered

def tcp_null_scan(target_ip, port):
    # Construct the netcat command to send a TCP Null packet to the target IP and port
    nc_cmd = ["nc", "-z", "-n", "-v", "-w", "1", "-G", "1", "-n", target_ip, str(port)]
    try:
        # Execute the netcat command
        output = subprocess.check_output(nc_cmd, stderr=subprocess.STDOUT, universal_newlines=True)
        # Check if the output contains a successful connection message
        if "succeeded" in output.lower():
            return True  # Port is open or unfiltered
        elif "filtered" in output.lower():
            return False  # Port is filtered
        else:
            return False  # Unable to determine port status
    except subprocess.CalledProcessError:
        return False  # Port is open or unfiltered

def tcp_xmas_scan(target_ip, port):
    # Construct the netcat command to send a TCP XMAS packet to the target IP and port
    nc_cmd = ["nc", "-z", "-n", "-v", "-w", "1", "-G", "1", "-z", target_ip, str(port)]
    try:
        # Execute the netcat command
        output = subprocess.check_output(nc_cmd, stderr=subprocess.STDOUT, universal_newlines=True)
        # Check if the output contains a successful connection message
        if "succeeded" in output.lower():
            return True  # Port is open or unfiltered
        elif "filtered" in output.lower():
            return False  # Port is filtered
        else:
            return False  # Unable to determine port status
    except subprocess.CalledProcessError:
        return False  # Port is open or unfiltered

def tcp_fin_scan(target_ip, port):
    # Construct the netcat command to send a TCP FIN packet to the target IP and port
    nc_cmd = ["nc", "-z", "-n", "-v", "-w", "1", "-G", "1", "-z", target_ip, str(port)]
    try:
        # Execute the netcat command
        output = subprocess.check_output(nc_cmd, stderr=subprocess.STDOUT, universal_newlines=True)
        # Check if the output contains a successful connection message
        if "succeeded" in output.lower():
            return True  # Port is closed
        elif "filtered" in output.lower():
            return False  # Port is filtered
        else:
            return False  # Unable to determine port status
    except subprocess.CalledProcessError:
        return False  # Port is open or unfiltered

def udp_port_scan(target_ip, port):
    # Construct the netcat command to send a UDP packet to the target IP and port
    nc_cmd = ["nc", "-zu", target_ip, str(port)]
    try:
        # Execute the netcat command
        subprocess.check_output(nc_cmd, stderr=subprocess.STDOUT)
        return True  # Port is open
    except subprocess.CalledProcessError:
        return False  # Port is closed

def protocol_ping_scan(target_ip):
    supported_protocols = []

    # Define a list of IP protocols to ping
    protocols = [0,1, 2, 6, 17,41]  # ICMP, IGMP, TCP, UDP

    # Send packets for each protocol and check for responses
    for protocol in protocols:
        packet = IP(dst=target_ip, proto=protocol)
        response = sr1(packet, timeout=1, verbose=False)
        if response:
            supported_protocols.append(protocol)

    return supported_protocols
    
def arp_ping_scan(network):
    arp_cmd = ["arp", "-n", network]
    try:
        output = subprocess.check_output(arp_cmd, stderr=subprocess.STDOUT, universal_newlines=True)
        # Parse the ARP table to find live hosts
        live_hosts = []
        lines = output.split("\n")
        for line in lines:
            if line.strip() and line.split()[0] != "Address":
                ip_address = line.split()[0]
                live_hosts.append(ip_address)
        return live_hosts
    except subprocess.CalledProcessError:
        return []
 

def main():
    print("Welcome to my network scanning tool!")
    print("Select a scan type:")
    print("1. ICMP Echo Ping")
    print("2. ICMP Echo Sweep")
    print("3. ICMP Timestamp Request")
    print("4. ICMP Address Mask Ping")
    print("5. TCP SYN Scan")
    print("6. TCP ACK Scan")
    print("7. TCP NULL Scan")
    print("8. TCP XMAS Scan")
    print("9. TCP FIN Scan")
    print("10. UDP Port Scan")
    print("11. Protocol Ping Scan")
    print("12. ARP Ping Scan")
    choice = input("Enter your choice (1/2/3/4/5/6/7/8/9/10/11): ")

    if choice == "1":
        target_ip = input("Enter the target IP address: ")
        if icmp_echo_ping(target_ip):
            print(f"ICMP Echo Ping to {target_ip} successful: Host is reachable")
        else:
            print(f"ICMP Echo Ping to {target_ip} failed: Host is unreachable")
    elif choice == "2":
        target_network = input("Enter the target network (e.g., 192.168.1.0/24): ")
        reachable_hosts = icmp_echo_sweep(target_network)
        if reachable_hosts:
            print("Reachable hosts:")
            for host in reachable_hosts:
                print(host)
        else:
            print("No reachable hosts found.")
    elif choice == "3":
        target_ip = input("Enter the target IP address: ")
        success, timestamp_info = icmp_timestamp_request(target_ip)
        if success:
            print(f"ICMP Timestamp Request to {target_ip} successful")
            if timestamp_info:
                tx_timestamp, rx_timestamp = timestamp_info
                print(f"Tx Timestamp: {tx_timestamp}, Rx Timestamp: {rx_timestamp}")
            else:
                print("No timestamp information found in response.")
        else:
            print(f"ICMP Timestamp Request to {target_ip} failed: Host is unreachable")
    elif choice == "4":
        target_ip = input("Enter the target IP address: ")
        if icmp_address_mask_ping(target_ip):
            print(f"{target_ip} is reachable.")
        else:
            print(f"{target_ip} is not reachable.")
    elif choice == "5":
        target_ip = input("Enter the target IP address: ")
        ports = input("Enter comma-separated list of ports to scan (e.g., 80,443,8080): ")
        ports_to_scan = [int(port) for port in ports.split(",")]
        for port in ports_to_scan:
            if tcp_syn_scan(target_ip, port):
                print(f"TCP Port {port} is open on {target_ip}")
            else:
                print(f"TCP Port {port} is closed on {target_ip}")
    elif choice == "6":
        target_ip = input("Enter the target IP address: ")
        ports = input("Enter comma-separated list of ports to scan (e.g., 80,443,8080): ")
        ports_to_scan = [int(port) for port in ports.split(",")]
        for port in ports_to_scan:
            if tcp_ack_scan(target_ip, port):
                print(f"TCP Port {port} is unfiltered on {target_ip}")
            else:
                print(f"TCP Port {port} is filtered on {target_ip}")
    elif choice == "7":
        target_ip = input("Enter the target IP address: ")
        ports = input("Enter comma-separated list of ports to scan (e.g., 80,443,8080): ")
        ports_to_scan = [int(port) for port in ports.split(",")]
        for port in ports_to_scan:
            if tcp_null_scan(target_ip, port):
                print(f"TCP Port {port} is open or unfiltered on {target_ip}")
            else:
                print(f"TCP Port {port} is filtered on {target_ip}")
    elif choice == "8":
        target_ip = input("Enter the target IP address: ")
        ports = input("Enter comma-separated list of ports to scan (e.g., 80,443,8080): ")
        ports_to_scan = [int(port) for port in ports.split(",")]
        for port in ports_to_scan:
            if tcp_xmas_scan(target_ip, port):
                print(f"TCP Port {port} is open or unfiltered on {target_ip}")
            else:
                print(f"TCP Port {port} is filtered on {target_ip}")
    elif choice == "9":
        target_ip = input("Enter the target IP address: ")
        ports = input("Enter comma-separated list of ports to scan (e.g., 80,443,8080): ")
        ports_to_scan = [int(port) for port in ports.split(",")]
        for port in ports_to_scan:
            if tcp_fin_scan(target_ip, port):
                print(f"TCP Port {port} is closed on {target_ip}")
            else:
                print(f"TCP Port {port} is open or unfiltered on {target_ip}")
    elif choice == "10":
        target_ip = input("Enter the target IP address: ")
        ports = input("Enter comma-separated list of ports to scan (e.g., 80,443,8080): ")
        ports_to_scan = [int(port) for port in ports.split(",")]
        for port in ports_to_scan:
            if udp_port_scan(target_ip, port):
                print(f"UDP Port {port} is open on {target_ip}")
            else:
                print(f"UDP Port {port} is closed on {target_ip}")
    elif choice == "11":
        target_ip = input("Enter the target IP address: ")
        supported_protocols = protocol_ping_scan(target_ip)
        if supported_protocols:
            print(f"Supported IP Protocols on {target_ip}:")
            for protocol in supported_protocols:
                print(f"Protocol {protocol}")
        else:
            print(f"No supported IP Protocols found on {target_ip}.")
    elif choice == "12":
        target_network = input("Enter the target network (e.g., 192.168.1.0/24): ")
        live_hosts = arp_ping_scan(target_network)
        if live_hosts:
            print("Live hosts:")
            for host in live_hosts:
                print(host)
        else:
            print("No live hosts found.")        
    else:
        print("Invalid choice. Please choose 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, or 11.")
    
if __name__ == "__main__":
    main()
