from scapy.all import *
import subprocess
import time
from collections import defaultdict

# Konfigurasi
THRESHOLD = 100  # Jumlah paket yang dikirim dalam satu detik
REQUESTS_LIMIT = 1000  # Batas paket dalam periode
REQUESTS_WINDOW = 60  # Durasi jendela waktu dalam detik
BLOCK_DURATION = 300  # Durasi pemblokiran dalam detik (5 menit)
INTERFACE = 'eth0'  # Sesuaikan dengan antarmuka jaringan Anda

# Penyimpanan untuk hitungan paket per IP
ip_count = {}
ip_timestamps = defaultdict(list)
blocked_ips = {}

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        current_time = time.time()
        
        # Menyaring timestamp yang tidak relevan
        ip_timestamps[ip_src] = [timestamp for timestamp in ip_timestamps[ip_src] if current_time - timestamp < REQUESTS_WINDOW]
        ip_timestamps[ip_src].append(current_time)
        
        if len(ip_timestamps[ip_src]) > REQUESTS_LIMIT:
            print(f"Potensi serangan DDoS dari IP: {ip_src}")
            block_ip(ip_src)
            ip_timestamps[ip_src] = []  # Reset setelah pemblokiran

        ip_count[ip_src] = ip_count.get(ip_src, 0) + 1

        # Memeriksa apakah ambang batas terlampaui
        if ip_count[ip_src] > THRESHOLD:
            print(f"Potensi serangan DDoS dari IP: {ip_src}")
            block_ip(ip_src)
            ip_count[ip_src] = 0  # Reset hitungan setelah pemblokiran

    manage_blocked_ips()

def block_ip(ip):
    print(f"Memblokir IP: {ip}")
    subprocess.call(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
    blocked_ips[ip] = time.time()  # Simpan waktu pemblokiran

def unblock_ip(ip):
    print(f"Melepaskan blokir IP: {ip}")
    subprocess.call(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
    blocked_ips.pop(ip, None)

def manage_blocked_ips():
    current_time = time.time()
    for ip, block_time in list(blocked_ips.items()):
        if current_time - block_time > BLOCK_DURATION:
            unblock_ip(ip)

def main():
    print(f"Mulai memantau lalu lintas pada {INTERFACE}...")
    sniff(iface=INTERFACE, prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
