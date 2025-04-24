import scapy.all as scapy
import socket
import sys
from datetime import datetime
import speedtest
from collections import defaultdict
import time
from scapy.utils import wrpcap
from scapy.all import sniff, IP, TCP, UDP, ICMP
import subprocess
import platform

#cant use argparse for this so this selects modes for each argument
# Should also return here after a process Counter: 18/20 status: :)
def get_arguments_idle():
    print("Select Mode:")
    print("1: arp")
    print("2: port")
    print("3: speed")
    print("4: sniff")
    print("5: exit")  
    mode_choice = input("Enter mode: ")
    return mode_choice

# ARP scan part, not fully tested cuz I'm using my own ip lol
def arp_scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for element in answered_list:
        devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return devices

def print_arp_results(devices):
    print("IP\t\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}") #need to test with someone else than my own ip

# Port Scan
def scan_port(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            print(f"Port {port}: Open")
        sock.close()
    except socket.error as e:
        print(f"Error on port {port}: {e}")

def scan_host(target):
    try:
        target_ip = socket.gethostbyname(target)
        print("-" * 50)
        print(f"Scanning target: {target_ip}")
        print(f"Scan started at: {datetime.now()}")
        print("-" * 50)

        for port in range(1, 1024):
            scan_port(target_ip, port)

    except socket.gaierror:
        print("Hostname could not be resolved.")
    except socket.error as e:
        print(f"Socket error: {e}")

# Speedtest
def check_bandwidth():
    try:
        st = speedtest.Speedtest()
        download_speed = st.download() / 1_000_000
        upload_speed = st.upload() / 1_000_000
        ping = st.results.ping

        print(f"Download Speed: {download_speed:.2f} Mbps")
        print(f"Upload Speed: {upload_speed:.2f} Mbps")
        print(f"Ping Latency: {ping:.2f} ms")
    except Exception as e:
        print(f"Error during speed test: {e}")

# Ip blocking (haven't tested and might remove if it doesnt work maybe even if it doesn't work)
def block_ip(ip_address):
    system_os = platform.system()

    try:
        if system_os == "Windows":
            print(f"[!] Blocking IP (Windows): {ip_address}")
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                                 f"name=Block_{ip_address}", "dir=in", "action=block",
                                 f"remoteip={ip_address}"], check=True)
        elif system_os == "Linux":
            print(f"[!] Blocking IP (Linux): {ip_address}")
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        else:
            print(f"[!] Blocking not supported on {system_os}")
    except subprocess.CalledProcessError:
        print(f"[-] Failed to block {ip_address}")

# Logs (if the code wants to -_-) and Packet sniffing
captured_packets = []
connection_counter = defaultdict(int)
ip_blacklist = set()
start_time = time.time()

def analyze_packet(packet):
    global captured_packets
    captured_packets.append(packet)

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        connection_counter[src] += 1

        if time.time() - start_time < 10 and connection_counter[src] > 100:
            if src not in ip_blacklist:
                print(f"[!] High traffic volume from {src}")
                ip_blacklist.add(src)
                if hasattr(args, 'block') and args.block: # Check if args has "block" attribute to prevent the "restart" message :'(
                    block_ip(src)

        if TCP in packet:
            dport = packet[TCP].dport
            if dport in [23, 21]:
                print(f"[!] Suspicious TCP port from {src} -> {dport}")
                if hasattr(args, 'block') and args.block and src not in ip_blacklist: # Check if args has "block" attribute, same as earlier
                    ip_blacklist.add(src)
                    block_ip(src)
        elif UDP in packet:
            print(f"[i] UDP packet: {src} -> {dst}")
        elif ICMP in packet:
            print(f"[i] ICMP packet: {src} -> {dst}")
        else:
            print(f"[!] Unknown protocol from {src}")

#look  more into this packet snififng as it's not saving the pcap file when pressing ctrl+ c
def start_sniffing(interface=None, pcap_file="captured_traffic.pcap"):
    print("[*] Sniffing started. Press Ctrl+C in the IDLE shell to stop...")
    try:
        sniff(filter="ip", prn=analyze_packet, iface=interface, store=False)
    except KeyboardInterrupt:
        print(f"\n[*] Sniffing stopped. Saving packets to {pcap_file}") #This does not seem to work so I'm not sure how to make it work
        wrpcap(pcap_file, captured_packets)
        print("[*] PCAP saved successfully.")
    except PermissionError:
        print("[!] Permission denied >:). Run IDLE as administrator for sniffing.")

#Will hopefully workarond the arg block that's been causing sadness, misery, and pain in IDLE env
if __name__ == "__main__":
    while True:
        mode_choice = get_arguments_idle()

        if mode_choice == "1":
            args = type('Args', (), {})() 
            args.target = input("Enter target IP or range for ARP scan: ")
            if args.target:
                result = arp_scan(args.target)
                print_arp_results(result)
            else:
                print("[-] Target IP or range can't be empty.")
        elif mode_choice == "2":
            args = type('Args', (), {})() 
            args.target = input("Enter target IP or hostname for port scan: ")
            if args.target:
                scan_host(args.target)
            else:
                print("[-] Target IP or hostname can't be empty.")
        elif mode_choice == "3":
            check_bandwidth()
        elif mode_choice == "4":
            args = type('Args', (), {})() # Create a simple object for Sniffing *sniff sniff*
            args.interface = input("Enter network interface for sniffing (leave blank for all): ") or None
            args.pcap = input(f"Enter filename to save captured packets (default: captured_traffic.pcap): ") or "captured_traffic.pcap"
            block_choice = input("Enable automatic IP blocking for suspicious traffic? (y/n): ").lower()
            args.block = True if block_choice == "y" else False
            start_sniffing(interface=args.interface, pcap_file=args.pcap)
        elif mode_choice == "5":
            print("[*] Exiting the Network Utility Tool.")
            break
        else:
            print("[-] Invalid mode selected. Please try again.")
