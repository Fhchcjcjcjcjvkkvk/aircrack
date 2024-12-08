import time
import subprocess
import pywifi
from pywifi import PyWiFi

# Function to get Wi-Fi authentication type and channel using netsh
def get_wifi_details():
    # Running the netsh command to get network details
    command = "netsh wlan show networks mode=bssid"
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    networks_info = result.stdout.split("\n")

    network_details = []
    current_bssid = None
    current_ssid = None
    current_auth = None
    current_channel = None
    current_signal = None
    current_beacon = None

    # Parse the output from netsh to extract network details
    for line in networks_info:
        if "BSSID" in line:
            if current_bssid:  # Store the previous network details before moving to the next one
                network_details.append((current_bssid, current_ssid, current_signal, current_beacon, current_channel, current_auth))

            # Start a new network entry
            current_bssid = line.split(":")[1].strip()
        elif "SSID" in line:
            current_ssid = line.split(":")[1].strip()
        elif "Authentication" in line:
            current_auth = line.split(":")[1].strip()
        elif "Channel" in line:
            current_channel = line.split(":")[1].strip()
        elif "Signal" in line:
            current_signal = line.split(":")[1].strip()
        elif "Beacons" in line:
            current_beacon = line.split(":")[1].strip()

    if current_bssid:  # Don't forget the last network
        network_details.append((current_bssid, current_ssid, current_signal, current_beacon, current_channel, current_auth))

    return network_details

# Function to scan Wi-Fi networks using pywifi and display real-time data
def scan_wifi():
    wifi = PyWiFi()  # Create a PyWiFi instance
    iface = wifi.interfaces()[0]  # Get the first available interface

    iface.scan()  # Start scanning
    time.sleep(2)  # Wait for the scan to complete

    results = iface.scan_results()  # Get the list of available networks
    print("\nBSSID              PWR  Beacons  CH   AUTH")

    network_details = get_wifi_details()  # Get network details using netsh

    # Display network details in columns: BSSID, PWR, Beacons, CH, AUTH
    for network in results:
        ssid = network.ssid  # ESSID
        bssid = network.bssid  # BSSID
        signal_strength = network.signal  # Signal strength (PWR)
        beacon_count = network.beacon  # Beacons

        # Find the authentication type and channel using netsh info
        auth_type = "Unknown"
        channel = "Unknown"
        for detail in network_details:
            if detail[0] == bssid:
                auth_type = detail[5]  # Authentication
                channel = detail[4]  # Channel
                break

        # Print formatted output for each network
        print(f"{bssid:<18} {signal_strength:>3} {beacon_count:>8} {channel:>3} {auth_type:>4}")

# Function to continuously scan every 4 seconds and update
def live_scan():
    while True:
        print("\033[H\033[J", end="")  # Clears the console screen (works in most terminals)
        scan_wifi()  # Scan for available networks
        time.sleep(4)  # Wait 4 seconds before the next scan

# Start the live scanning
if __name__ == "__main__":
    live_scan()
