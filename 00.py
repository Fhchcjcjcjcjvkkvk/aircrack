import time
import subprocess
import pywifi
from pywifi import PyWiFi

# Function to get Wi-Fi authentication type using netsh
def get_wifi_details():
    # Running the netsh command to get network details
    command = "netsh wlan show networks mode=bssid"
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    networks_info = result.stdout.split("\n")

    network_details = []
    current_bssid = None
    current_ssid = None
    current_auth = None
    current_signal = None

    # Parse the output from netsh to extract network details
    for line in networks_info:
        if "BSSID" in line:
            if current_bssid:  # Store the previous network details before moving to the next one
                network_details.append((current_bssid, current_ssid, current_signal, current_auth))

            # Start a new network entry
            current_bssid = line.split(":")[1].strip()
        elif "SSID" in line:
            current_ssid = line.split(":")[1].strip()
        elif "Authentication" in line:
            current_auth = line.split(":")[1].strip()
        elif "Signal" in line:
            current_signal = line.split(":")[1].strip()

    if current_bssid:  # Don't forget the last network
        network_details.append((current_bssid, current_ssid, current_signal, current_auth))

    return network_details

# Function to scan Wi-Fi networks using pywifi and display real-time data
def scan_wifi():
    wifi = PyWiFi()  # Create a PyWiFi instance
    iface = wifi.interfaces()[0]  # Get the first available interface

    iface.scan()  # Start scanning
    time.sleep(2)  # Wait for the scan to complete

    results = iface.scan_results()  # Get the list of available networks
    print("\nBSSID              PWR   ESSID              AUTH")

    network_details = get_wifi_details()  # Get network details using netsh

    # Display network details in columns: BSSID, PWR, ESSID, AUTH
    for network in results:
        bssid = network.bssid  # BSSID
        signal_strength = network.signal  # Signal strength (PWR)
        ssid = network.ssid  # ESSID

        # Find the authentication type using netsh info
        auth_type = "Unknown"
        for detail in network_details:
            if detail[0] == bssid:
                auth_type = detail[3]  # Authentication
                break

        # Print formatted output for each network
        print(f"{bssid:<18} {signal_strength:>3} {ssid:<20} {auth_type:>4}")
    
    return results

# Function to perform the scan and only show if there is new data
def check_for_changes(last_scan_results):
    current_scan_results = scan_wifi()
    
    # Compare the results with the previous scan to check for any changes
    if current_scan_results != last_scan_results:
        return current_scan_results
    else:
        return None

# Function to perform a single scan and wait for changes
def single_scan():
    last_scan_results = None

    while True:
        print("\033[H\033[J", end="")  # Clears the console screen
        new_data = check_for_changes(last_scan_results)
        
        if new_data:  # Only print if there is new data
            last_scan_results = new_data  # Update last scan data

        time.sleep(4)  # Wait before scanning again

# Start the single scan
if __name__ == "__main__":
    single_scan()
