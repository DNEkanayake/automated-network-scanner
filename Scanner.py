import scapy.all as scapy
import argparse
import socket
import json
import csv

def scan_hosts(ip_range):
    print(f"[*] Scanning subnet: {ip_range} for active hosts...")
    
    # 1. Create an ARP request packet for the target IP/subnet
    arp_request = scapy.ARP(pdst=ip_range)
    
    # 2. Create an Ethernet broadcast packet (to send to everyone on the network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # 3. Combine them into a single packet
    arp_request_broadcast = broadcast / arp_request
    
    # 4. Send the packet and capture the responses
    # srp() sends and receives packets at layer 2 (Ethernet)
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
        
    return clients_list

def display_hosts(clients_list):
    print("\nTarget IP\t\tMAC Address")
    print("--------------------------------------------------")
    for client in clients_list:
        print(f"{client['ip']}\t\t{client['mac']}")


        import socket

COMMON_PORTS = {
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP"
}

def scan_ports(ip):
    print(f"\n[*] Scanning ports for {ip}...")
    open_ports = []
    
    for port, service in COMMON_PORTS.items():
        # Create a socket object (AF_INET = IPv4, SOCK_STREAM = TCP)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0) # Don't wait forever
        
        result = s.connect_ex((ip, port)) # returns 0 if connection was successful
        if result == 0:
            # Attempt basic device/banner detection
            try:
                banner = s.recv(1024).decode().strip()
                detection = f"{service} ({banner})" if banner else service
            except:
                detection = service
                
            open_ports.append((port, detection))
        s.close()
        
    return open_ports


def get_arguments():
    parser = argparse.ArgumentParser(description="Automated Network Scanner")
    parser.add_argument("-t", "--target", dest="target", required=True, help="Target IP address or Subnet IP range (e.g., 192.168.1.1/24)")
    options = parser.parse_args()
    return options


def export_to_json(results_data, filename="scan_results.json"):
    """Saves the scan data into a structured JSON file."""
    try:
        with open(filename, "w") as f:
            json.dump(results_data, f, indent=4)
        print(f"\n[+] Success! Results exported to JSON format: {filename}")
    except Exception as e:
        print(f"[-] Error exporting to JSON: {e}")

def export_to_csv(results_data, filename="scan_results.csv"):
    """Saves the scan data into a spreadsheet-compatible CSV file."""
    try:
        with open(filename, "w", newline="") as f:
            # Define the column headers based on our data structure
            fieldnames = ["ip", "mac", "ports"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            
            writer.writeheader()
            for row in results_data:
                writer.writerow(row)
        print(f"[+] Success! Results exported to CSV format: {filename}")
    except Exception as e:
        print(f"[-] Error exporting to CSV: {e}")

if __name__ == "__main__":
    args = get_arguments()
    
    # Run Host Discovery
    hosts = scan_hosts(args.target)
    display_hosts(hosts)
    
    # This list will hold all our final data structured for export
    final_scan_results = []
    
    if hosts:
        print("\n" + "="*50)
        print("Starting Deep Port Scan on Active Hosts")
        print("="*50)
        
        for host in hosts:
            open_ports = scan_ports(host['ip'])
            
            # Format ports for clean storage (e.g., "80 (HTTP), 443 (HTTPS)")
            port_strings = []
            if open_ports:
                for port, service in open_ports:
                    print(f"   -> Port {port}: Open [{service}]")
                    port_strings.append(f"{port} ({service})")
                ports_display = ", ".join(port_strings)
            else:
                print("   -> No common open ports found.")
                ports_display = "None"
            
            # Build a structured dictionary for this specific host
            host_entry = {
                "ip": host['ip'],
                "mac": host['mac'],
                "ports": ports_display
            }
            # Append it to our tracking list
            final_scan_results.append(host_entry)
            
        # --- EXPORT PHASE ---
        # Call our functions to write out the data files automatically
        export_to_json(final_scan_results)
        export_to_csv(final_scan_results)
        
    else:
        print("\n[-] No hosts found on the specified subnet.")


