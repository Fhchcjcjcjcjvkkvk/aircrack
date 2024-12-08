import time
import os
import scapy.all as scapy
from pywifi import PyWiFi, const
from subprocess import check_output

# Function to scan WiFi networks using scapy
def scan_wifi(interface):
    print("Scanning WiFi networks...")
    networks = []
    
    def packet_handler(pkt):
        if pkt.haslayer(scapy.Dot11Beacon):  # Beacon frame
            ssid = pkt.info.decode('utf-8', errors='ignore')  # ESSID
            bssid = pkt.addr2  # BSSID
            channel = int(ord(pkt[scapy.Dot11Elt:3].info))  # Channel
            power = pkt.dBm_AntSignal  # Signal power
            
            network = {
                'BSSID': bssid,
                'SSID': ssid,
                'Power': power,
                'Channel': channel
            }
            if network not in networks:
                networks.append(network)

    # Start sniffing packets on the given interface
    scapy.sniff(iface=interface, prn=packet_handler, timeout=5)
    
    return networks

# Function to get WiFi authentication using PyWiFi
def get_authentication():
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]  # Use the first interface
    iface.scan()  # Scan for networks
    results = iface.scan_results()
    
    for result in results:
        # Check if 'Authentication' is available using netsh (for Windows)
        ssid = result.ssid
        command = f'netsh wlan show network mode=bssid'
        networks_info = check_output(command, shell=True).decode()
        
        # Extract the authentication method
        auth_line = [line for line in networks_info.split('\n') if ssid in line]
        for line in auth_line:
            if "Authentication" in line:
                auth_method = line.split(":")[1].strip()
                return auth_method
        
    return "Unknown"

# Get the default WiFi interface on Windows
def get_wifi_interface():
    wifi = PyWiFi()
    interfaces = wifi.interfaces()
    for iface in interfaces:
        if iface.status() == const.IFACE_CONNECTED:  # Check if the interface is connected
            return iface.name
    return None

# Main loop to show results live every 5 seconds
def main():
    wifi_interface = get_wifi_interface()
    if not wifi_interface:
        print("No Wi-Fi interface found.")
        return
    
    print(f"Using interface: {wifi_interface}")
    
    while True:
        networks = scan_wifi(wifi_interface)
        auth_method = get_authentication()

        print("Networks found:")
        print(f"{'BSSID':<20} {'SSID':<30} {'Power':<10} {'Channel':<8} {'Authentication'}")
        print("-" * 80)
        
        for network in networks:
            print(f"{network['BSSID']:<20} {network['SSID']:<30} {network['Power']:<10} {network['Channel']:<8} {auth_method}")

        time.sleep(5)  # Update every 5 seconds
        os.system('cls' if os.name == 'nt' else 'clear')  # Clear the screen to refresh

if __name__ == "__main__":
    main()
