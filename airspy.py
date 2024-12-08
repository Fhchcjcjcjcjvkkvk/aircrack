import pywifi
from pywifi import const
import time
import os
from collections import defaultdict
from scapy.all import sniff, Dot11, Dot11Beacon

# Dictionary to track beacon count for each SSID
beacon_counts = defaultdict(int)

# Function to get authentication modes from Beacon frames
def get_auth_modes(packet):
    """Extract authentication mode from Beacon frames."""
    if packet.haslayer(Dot11Beacon):
        ssid = packet[Dot11].info.decode(errors="ignore")  # Extract SSID
        capabilities = packet[Dot11Beacon].capability
        auth_mode = "Open"  # Default to open authentication

        # Check for WPA/WPA2 (RSN information) from capabilities
        if capabilities & 0x0040:  # WPA2 (RSN)
            auth_mode = "WPA2"
        elif capabilities & 0x0020:  # WPA
            auth_mode = "WPA"
        
        return ssid, auth_mode
    return None, None

# Function to sniff packets and capture SSID, Authentication modes, and Beacon counts
def packet_callback(packet):
    """Process sniffed packets and track authentication modes and beacon counts for each network."""
    if packet.haslayer(Dot11Beacon):
        ssid, auth_mode = get_auth_modes(packet)
        if ssid:
            # Increment beacon count for the SSID
            beacon_counts[ssid] += 1
            print(f"SSID: {ssid} - Authentication Mode: {auth_mode} - Beacon Count: {beacon_counts[ssid]}")

# Function to sniff packets
def sniff_packets():
    """Start sniffing Wi-Fi packets to track authentication modes and beacon counts."""
    print("[INFO] Starting packet sniffing...")
    sniff(prn=packet_callback, store=0, timeout=0)  # Infinite sniffing unless stopped manually

# Function to scan Wi-Fi networks using pywifi
def scan_wifi():
    """Continuously scan available WiFi networks and show their details live."""
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]  # Assuming you're using the first interface

    while True:
        iface.scan()  # Start scanning for networks
        time.sleep(2)  # Allow time for scan results to populate
        networks = iface.scan_results()

        # Display networks from the scan results
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{'BSSID':<20} {'SSID':<30} {'Signal (dBm)':<15} {'Auth':<20} {'Beacons':<10}")
        print("=" * 110)

        for network in networks:
            bssid = network.bssid
            ssid = network.ssid
            signal = network.signal  # Signal strength

            # Display network information with the current Beacon count
            beacon_count = beacon_counts.get(ssid, 0)  # Default to 0 if no beacons counted
            print(f"{bssid:<20} {ssid:<30} {signal:<15} {'-':<20} {beacon_count:<10}")

        time.sleep(3)  # Refresh every 3 seconds

if __name__ == "__main__":
    from threading import Thread

    # Start sniffing packets in a separate thread (to capture authentication mode and beacon count)
    sniff_thread = Thread(target=sniff_packets, daemon=True)
    sniff_thread.start()

    # Start scanning Wi-Fi networks
    scan_wifi()
