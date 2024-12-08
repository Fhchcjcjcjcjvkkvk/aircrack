import time
import subprocess
import pywifi
from pywifi import PyWiFi

# Function to get Wi-Fi authentication type using netsh
def get_wifi_auth(bssid):
    command = "netsh wlan show networks mode=bssid"
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    networks_info = result.stdout.split("\n")
    
    auth_type = "Unknown"
    for line in networks_info:
        if "BSSID" in line and bssid in line:
            # Extract the authentication type for the current BSSID
            for line in networks_info:
                if "Authentication" in line:
                    auth_type = line.split(":")[1].strip()
                    break
    return auth_type

# Function to scan Wi-Fi networks using pywifi
def scan_wifi():
    wifi = PyWiFi()  # Create a PyWiFi instance
    iface = wifi.interfaces()[0]  # Get the first available interface

    iface.scan()  # Start scanning
    time.sleep(2)  # Wait for the scan to complete

    results = iface.scan_results()  # Get the list of available networks
    print("\nBSSID              PWR  Beacons  CH   AUTH")

    # Display network details in columns: BSSID, PWR, Beacons, CH, AUTH
    for network in results:
        ssid = network.ssid  # ESSID
        bssid = network.bssid  # BSSID
        signal_strength = network.signal  # Signal strength (PWR)
        channel = network.channel  # Channel (CH)
        beacon_count = network.beacon  # Beacons

        # Get authentication type from netsh
        auth_type = get_wifi_auth(bssid)

        # Print formatted output
        print(f"{bssid:<18} {signal_strength:>3} {beacon_count:>8} {channel:>3} {auth_type:>4}")

# Function to continuously scan every 5 seconds
def live_scan():
    while True:
        scan_wifi()  # Scan for available networks
        time.sleep(5)  # Wait 5 seconds before the next scan

# Start the live scanning
if __name__ == "__main__":
    live_scan()
