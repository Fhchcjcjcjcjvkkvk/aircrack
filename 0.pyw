import time
import os
import subprocess
from scapy.all import sniff
from pywifi import PyWiFi, const
from threading import Thread

# Function to get authentication info via netsh
def get_authentication(bssid):
    command = f'netsh wlan show network bssid {bssid}'
    output = subprocess.check_output(command, shell=True, text=True)
    for line in output.splitlines():
        if "Authentication" in line:
            return line.split(":")[1].strip()
    return "Unknown"

# Function to process the sniffed packets
def process_packet(packet):
    if packet.haslayer("Dot11Beacon"):
        bssid = packet[Dot11].addr3
        essid = packet[Dot11Elt].info.decode("utf-8", errors="ignore")
        signal_strength = packet.dBm_AntSignal if hasattr(packet, "dBm_AntSignal") else "N/A"
        channel = ord(packet[Dot11Elt:3].info)  # Channel is in the 3rd Dot11Elt

        # Get Authentication via netsh
        auth = get_authentication(bssid)

        # Print the network details
        print(f"BSSID: {bssid} | ESSID: {essid} | Signal: {signal_strength}dBm | Channel: {channel} | Auth: {auth}")

# Function to scan Wi-Fi networks using Scapy
def wifi_scan():
    print("Starting Wi-Fi scan... Press CTRL+C to stop.")
    sniff(iface="WiFi", prn=process_packet, store=0)

# Function to run PyWiFi to get available networks every 5 seconds
def live_scan():
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]  # Assume the first interface is the Wi-Fi interface

    while True:
        iface.scan()
        networks = iface.scan_results()

        # Print available networks with PyWiFi info
        for network in networks:
            print(f"PyWiFi BSSID: {network['BSSID']} | ESSID: {network['ssid']} | Signal: {network['signal']}dBm")

        time.sleep(5)  # Wait for 5 seconds before scanning again

# Start the Scapy sniffing in a separate thread
scapy_thread = Thread(target=wifi_scan, daemon=True)
scapy_thread.start()

# Start the PyWiFi live scanning in the main thread
live_scan()
