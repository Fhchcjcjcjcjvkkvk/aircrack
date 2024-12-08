import time
import os
import pywifi
from pywifi import PyWiFi, const, Profile

# Function to get the network authentication details using netsh
def get_authentication(bssid):
    command = f'netsh wlan show network bssid {bssid}'
    result = os.popen(command).read()
    auth_line = [line for line in result.split('\n') if "Authentication" in line]
    if auth_line:
        return auth_line[0].split(":")[1].strip()
    return "Unknown"

# Function to scan WiFi networks
def scan_wifi():
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]  # Assuming the first interface
    iface.scan()
    time.sleep(2)  # Wait for scan results
    networks = iface.scan_results()
    return networks

# Function to display the network details
def display_networks():
    while True:
        networks = scan_wifi()
        os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen for live update
        print(f"{'BSSID':<20} {'ESSID':<30} {'Signal':<10} {'Authentication':<30}")
        print("-" * 90)
        
        for network in networks:
            bssid = network.bssid
            essid = network.ssid
            signal = network.signal
            auth = get_authentication(bssid)
            
            # Display the information
            print(f"{bssid:<20} {essid:<30} {signal:<10} {auth:<30}")
        
        time.sleep(5)  # Wait for 5 seconds before the next scan

if __name__ == "__main__":
    display_networks()
