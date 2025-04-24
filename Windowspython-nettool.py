import argparse
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

# Argument parser, might make it prettier, doesn't work in idle, works in terminal
def get_arguments():
    parser = argparse.ArgumentParser(description="Python Network Utility Tool")
    parser.add_argument("-m", "--mode", choices=["arp", "port", "speed", "sniff"], required=True, help="Select mode: arp, port, speed, sniff")
    parser.add_argument("-t", "--target", help="Target IP or hostname (required for arp/port)")
    parser.add_argument("-i", "--interface", help="Network interface for sniffing (e.g., Ethernet, Wi-Fi)")
    parser.add_argument("-p", "--pcap", help="Filename to save captured packets (default: captured_traffic.pcap)")
    parser.add_argument("--block", action="store_true", help="Enable automatic IP blocking for suspicious traffic")
    return parser.parse_args()

# arp scans
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
    print("+-----------------------------------------+")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

# port scans
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

# speedtest/badnwidth
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

# ip blocks/blacklist
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

# pack sniff and log
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
                if args.block:
                    block_ip(src)

        if TCP in packet:
            dport = packet[TCP].dport
            if dport in [23, 21]:
                print(f"[!] Suspicious TCP port from {src} -> {dport}")
                if args.block and src not in ip_blacklist:
                    ip_blacklist.add(src)
                    block_ip(src)
        elif UDP in packet:
            print(f"[i] UDP packet: {src} -> {dst}")
        elif ICMP in packet:
            print(f"[i] ICMP packet: {src} -> {dst}")
        else:
            print(f"[!] Unknown protocol from {src}")

def start_sniffing(interface=None, pcap_file="captured_traffic.pcap"):
    print("[*] Sniffing started. Press Ctrl+C to stop...")
    try:
        sniff(filter="ip", prn=analyze_packet, iface=interface, store=False)
    except KeyboardInterrupt:
        print(f"\n[*] Sniffing stopped. Saving packets to {pcap_file}")
        wrpcap(pcap_file, captured_packets)
        print("[*] PCAP saved successfully.")
    except PermissionError:
        print("[!] Permission denied. Run as administrator.")

# main name function
#come back to this l8r?????
if __name__ == "__main__":
    args = get_arguments()

    if args.mode == "arp":
        if not args.target:
            print("[-] Please provide a target IP or range for ARP scan.")
            sys.exit(1)
        result = arp_scan(args.target)
        print_arp_results(result)

    elif args.mode == "port":
        if not args.target:
            print("[-] Please provide a target IP or hostname for port scan.")
            sys.exit(1)
        scan_host(args.target)

    elif args.mode == "speed":
        check_bandwidth()

    elif args.mode == "sniff":
        pcap_file = args.pcap or "captured_traffic.pcap"
        start_sniffing(interface=args.interface, pcap_file=pcap_file)
