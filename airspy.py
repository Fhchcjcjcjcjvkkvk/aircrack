import os
import sys
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Data
from pywifi import PyWiFi, const, Profile
from collections import defaultdict

# Dictionary to track beacon count and data frames count for each SSID
beacon_counts = defaultdict(int)
data_counts = defaultdict(int)

# Function to list available Wi-Fi interfaces using PyWiFi
def list_wifi_interfaces():
    """List all Wi-Fi interfaces on the system."""
    wifi = PyWiFi()
    interfaces = wifi.interfaces()
    print("\nAvailable Wi-Fi Interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"[{i}] {iface.name()}")
    return interfaces

# Function to enable monitor mode (if supported)
def enable_monitor_mode(interface):
    """
    Enable monitor mode on a Wi-Fi interface.
    Note: This functionality is not directly supported by PyWiFi on Windows.
    """
    print(f"[INFO] PyWiFi does not support enabling monitor mode on Windows. Ensure the interface is set manually.")
    return interface  # Return the interface as is

# Function to get authentication modes, BSSID, RSSI from Beacon frames
def get_auth_modes(packet):
    """Extract authentication mode, BSSID, and RSSI from Beacon frames."""
    if packet.haslayer(Dot11Beacon):
        ssid = packet[Dot11].info.decode(errors="ignore")  # Extract SSID
        bssid = packet[Dot11].addr3  # Extract BSSID (MAC address of the access point)
        rssi = getattr(packet, 'dBm_AntSignal', 'N/A')  # Extract RSSI (signal strength) if available
        capabilities = packet[Dot11Beacon].capability
        auth_mode = "Open"  # Default to open authentication

        # Check for WPA/WPA2 (RSN information) from capabilities
        if capabilities & 0x0040:  # WPA2 (RSN)
            auth_mode = "WPA2"
        elif capabilities & 0x0020:  # WPA
            auth_mode = "WPA"
        
        return ssid, bssid, auth_mode, rssi
    return None, None, None, None

# Function to handle sniffed packets and capture SSID, Authentication modes, BSSID, RSSI, Data count, and Beacon counts
def packet_callback(packet):
    """Process sniffed packets and track beacon count, data frames count, authentication modes, BSSID, and RSSI."""
    if packet.haslayer(Dot11Beacon):  # If it's a Beacon frame
        ssid, bssid, auth_mode, rssi = get_auth_modes(packet)
        if ssid:
            # Increment beacon count for the SSID
            beacon_counts[ssid] += 1
            # Print in tabular format (columns aligned)
            print(f"{bssid:<20} {ssid:<30} {auth_mode:<10} {rssi:<6} {beacon_counts[ssid]:<10} {data_counts[ssid]:<10}")

    elif packet.haslayer(Dot11Data):  # If it's a Data frame
        ssid = packet[Dot11].info.decode(errors="ignore")  # Extract SSID from Data frame
        if ssid:
            # Increment data frame count for the SSID
            data_counts[ssid] += 1

# Function to sniff packets on the specified interface
def sniff_packets(interface_name):
    """Start sniffing Wi-Fi packets on a given interface."""
    print(f"\n[INFO] Starting packet sniffing on interface: {interface_name}")
    print(f"{'BSSID':<20} {'SSID':<30} {'Auth Mode':<10} {'PWR':<10} {'Beacon':<10} {'#Data':<10}")
    print("=" * 120)  # Separator line
    sniff(prn=packet_callback, store=0, iface=interface_name, timeout=0)  # Infinite sniffing unless stopped manually

def main():
    # List available Wi-Fi interfaces and let the user select one
    interfaces = list_wifi_interfaces()
    if not interfaces:
        print("[ERROR] No Wi-Fi interfaces found. Ensure your adapter is installed and enabled.")
        sys.exit(1)

    try:
        interface_index = int(input("Select the interface index to use for sniffing: "))
        if interface_index < 0 or interface_index >= len(interfaces):
            print("[ERROR] Invalid interface index.")
            sys.exit(1)
    except ValueError:
        print("[ERROR] Please enter a valid numeric index.")
        sys.exit(1)

    interface = interfaces[interface_index]
    interface_name = enable_monitor_mode(interface.name())

    # Start sniffing Wi-Fi packets
    sniff_packets(interface_name)

if __name__ == "__main__":
    main()
