import pywifi
from pywifi import const
import subprocess
import time
import os
from collections import defaultdict
from scapy.all import sniff, Dot11, Dot11Beacon, EAPOL

# Function to retrieve authentication modes using netsh
def get_auth_modes():
    result = subprocess.run(
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        capture_output=True, text=True
    )
    networks = {}

    for block in result.stdout.split("\n\n"):
        lines = block.splitlines()
        ssid = None
        auth = None

        for line in lines:
            if line.strip().startswith("SSID "):
                ssid = line.split(":", 1)[1].strip()
            elif line.strip().startswith("Authentication"):  
                auth = line.split(":", 1)[1].strip()

        if ssid and auth:
            networks[ssid] = auth

    return networks

def clear_console():
    """Clear the console for live display."""
    os.system('cls' if os.name == 'nt' else 'clear')

# Track sequence numbers, lost packets, and beacon frames
packet_tracking = defaultdict(lambda: {'last_seq': None, 'lost_count': 0, 'timestamps': [], 'beacon_count': 0})

LOSS_THRESHOLD = 10  # Time window for tracking lost packets (in seconds)

def track_lost_packets(ssid, seq_num):
    """Track lost packets based on sequence numbers over the last 10 seconds."""
    current_time = time.time()

    # Initialize tracking for a new SSID
    if ssid not in packet_tracking:
        packet_tracking[ssid]['last_seq'] = seq_num
        packet_tracking[ssid]['timestamps'].append(current_time)
        return 0

    # Retrieve previous sequence number and timestamps
    last_seq = packet_tracking[ssid]['last_seq']
    timestamps = packet_tracking[ssid]['timestamps']

    # Calculate lost packets if sequence is not contiguous
    if last_seq is not None and seq_num != last_seq + 1:
        lost_count = seq_num - last_seq - 1
        packet_tracking[ssid]['lost_count'] += lost_count

    # Update tracking
    packet_tracking[ssid]['last_seq'] = seq_num
    packet_tracking[ssid]['timestamps'].append(current_time)

    # Remove timestamps outside the time window
    packet_tracking[ssid]['timestamps'] = [
        ts for ts in timestamps if current_time - ts <= LOSS_THRESHOLD
    ]

    # Return the number of lost packets
    return packet_tracking[ssid]['lost_count']

def track_beacon_frames(ssid):
    """Increment the beacon frame count for a network."""
    packet_tracking[ssid]['beacon_count'] += 1

# Function to sniff packets and capture sequence numbers and beacon frames
def packet_callback(packet):
    """Process sniffed packets and track lost packets and beacons for each SSID."""
    if packet.haslayer(EAPOL):
        ssid = packet.addr2  # BSSID as identifier
        seq_num = packet[Dot11].SC  # Sequence number (SC is Sequence Control)

        lost_count = track_lost_packets(ssid, seq_num)
        print(f"{ssid} - Lost packets (last {LOSS_THRESHOLD} sec): {lost_count}")

    elif packet.haslayer(Dot11Beacon):
        ssid = packet[Dot11].SSID  # SSID from the Beacon frame
        track_beacon_frames(ssid)
        print(f"{ssid} - Beacon count: {packet_tracking[ssid]['beacon_count']}")

def sniff_packets():
    """Start sniffing Wi-Fi packets to track sequence number loss and beacon frames."""
    print("[INFO] Starting packet sniffing...")
    sniff(prn=packet_callback, store=0, timeout=0)  # Infinite sniffing unless stopped manually

# Function to scan Wi-Fi networks
def scan_wifi():
    """Continuously scan available WiFi networks and show their details live."""
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]

    while True:
        iface.scan()
        time.sleep(2)  # Allow time for scan results to populate
        networks = iface.scan_results()

        auth_modes = get_auth_modes()

        clear_console()
        print(f"{'BSSID':<20} {'SSID':<30} {'Signal (dBm)':<15} {'Auth':<20} {'Lost Packets':<25} {'Beacon Count':<20}")
        print("=" * 120)

        # Display networks from the scan results
        for network in networks:
            bssid = network.bssid
            ssid = network.ssid
            signal = network.signal  # Signal strength

            auth = auth_modes.get(ssid, "Unknown")
            
            # Track lost packets and beacon counts
            lost_count = packet_tracking[ssid]['lost_count']
            beacon_count = packet_tracking[ssid]['beacon_count']

            print(f"{bssid:<20} {ssid:<30} {signal:<15} {auth:<20} {lost_count:<25} {beacon_count:<20}")

        time.sleep(3)  # Refresh every 3 seconds

if __name__ == "__main__":
    from threading import Thread

    # Start sniffing packets in a separate thread
    sniff_thread = Thread(target=sniff_packets, daemon=True)
    sniff_thread.start()

    # Start scanning Wi-Fi networks
    scan_wifi()
