from scapy.all import *
from pywifi import PyWiFi, const
import time
from collections import defaultdict

# Store detected networks
networks = defaultdict(lambda: {'ESSID': '', 'Power': '', 'Auth': '', 'Beacons': 0})

# Define a function to handle captured packets
def handle_packet(packet):
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2  # BSSID
        essid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')  # ESSID
        power = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 'N/A'  # Signal power
        auth = "Open"  # Default to open

        # Check for authentication type
        if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 48:
            auth = "WPA2"
        elif packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 221:
            auth = "WPA"

        # Update network details
        networks[bssid]['ESSID'] = essid
        networks[bssid]['Power'] = power
        networks[bssid]['Auth'] = auth
        networks[bssid]['Beacons'] += 1

# Scanning function
def scan():
    try:
        sniff(prn=handle_packet, iface="Wi-Fi", timeout=10)  # Adjust "Wi-Fi" to your adapter name
    except Exception as e:
        print(f"Error while scanning: {e}")

# Display function
def display_results():
    print(f"{'BSSID':<20} {'ESSID':<30} {'Power':<10} {'Auth':<10} {'Beacons':<10}")
    print("=" * 80)
    for bssid, details in networks.items():
        print(f"{bssid:<20} {details['ESSID']:<30} {details['Power']:<10} {details['Auth']:<10} {details['Beacons']:<10}")

# Main function
def main():
    # Ensure PyWiFi is ready
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]  # Get the first wireless interface
    iface.disconnect()
    time.sleep(1)  # Let the interface settle

    print("Starting WiFi scanner... Press Ctrl+C to stop.")
    scan()
    display_results()

if __name__ == "__main__":
    main()
