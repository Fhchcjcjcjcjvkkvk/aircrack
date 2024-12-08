#include <stdio.h>
#include <windows.h>
#include <wlanapi.h>
#include <iphlpapi.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "iphlpapi.lib")

#define LOSS_THRESHOLD 10 // Time window in seconds for packet loss tracking
#define BUFFER_SIZE 8192

// Structure to track packet loss per SSID
typedef struct {
    char ssid[256];
    int last_seq;
    int lost_count;
    time_t timestamps[BUFFER_SIZE];
    int timestamp_count;
} PacketTracking;

PacketTracking tracking[100];
int tracking_count = 0;

// Function to find or initialize tracking for a given SSID
PacketTracking* get_tracking(const char* ssid) {
    for (int i = 0; i < tracking_count; i++) {
        if (strcmp(tracking[i].ssid, ssid) == 0) {
            return &tracking[i];
        }
    }

    // Initialize new tracking entry
    PacketTracking* new_tracking = &tracking[tracking_count++];
    strncpy(new_tracking->ssid, ssid, sizeof(new_tracking->ssid));
    new_tracking->last_seq = -1;
    new_tracking->lost_count = 0;
    new_tracking->timestamp_count = 0;
    return new_tracking;
}

// Function to update packet loss tracking
int track_lost_packets(PacketTracking* track, int seq_num) {
    time_t current_time = time(NULL);

    // Calculate lost packets if sequence is not contiguous
    if (track->last_seq != -1 && seq_num != track->last_seq + 1) {
        int lost_count = seq_num - track->last_seq - 1;
        track->lost_count += lost_count;
    }

    // Update last sequence number
    track->last_seq = seq_num;

    // Add timestamp and maintain the sliding window
    if (track->timestamp_count < BUFFER_SIZE) {
        track->timestamps[track->timestamp_count++] = current_time;
    }

    // Remove old timestamps
    int valid_count = 0;
    for (int i = 0; i < track->timestamp_count; i++) {
        if (current_time - track->timestamps[i] <= LOSS_THRESHOLD) {
            track->timestamps[valid_count++] = track->timestamps[i];
        }
    }
    track->timestamp_count = valid_count;

    return track->lost_count;
}

// Function to scan Wi-Fi networks
void scan_wifi_networks() {
    HANDLE hClient = NULL;
    DWORD dwMaxClient = 2;
    DWORD dwCurVersion = 0;
    DWORD dwResult = 0;
    PWLAN_AVAILABLE_NETWORK_LIST pNetworkList = NULL;
    PWLAN_AVAILABLE_NETWORK pNetwork = NULL;
    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    PWLAN_INTERFACE_INFO pIfInfo = NULL;

    dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
    if (dwResult != ERROR_SUCCESS) {
        printf("Error opening handle: %ld\n", dwResult);
        return;
    }

    dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
    if (dwResult != ERROR_SUCCESS) {
        printf("Error enumerating interfaces: %ld\n", dwResult);
        return;
    }

    for (int i = 0; i < (int)pIfList->dwNumberOfItems; i++) {
        pIfInfo = &pIfList->InterfaceInfo[i];

        dwResult = WlanGetAvailableNetworkList(
            hClient, &pIfInfo->InterfaceGuid, 0, NULL, &pNetworkList);
        if (dwResult != ERROR_SUCCESS) {
            printf("Error getting network list: %ld\n", dwResult);
            continue;
        }

        printf("%-30s %-10s %-15s\n", "SSID", "Signal", "Lost Packets");
        printf("%s\n", "============================================");

        for (int j = 0; j < (int)pNetworkList->dwNumberOfItems; j++) {
            pNetwork = &pNetworkList->Network[j];

            char ssid[256] = {0};
            strncpy(ssid, (char*)pNetwork->dot11Ssid.ucSSID, pNetwork->dot11Ssid.uSSIDLength);

            PacketTracking* track = get_tracking(ssid);

            // Simulated packet loss tracking (real implementation would involve raw sockets)
            int seq_num = rand() % 100; // Random sequence number
            int lost_count = track_lost_packets(track, seq_num);

            printf("%-30s %-10d %-15d\n", ssid, pNetwork->wlanSignalQuality, lost_count);
        }

        WlanFreeMemory(pNetworkList);
    }

    WlanFreeMemory(pIfList);
    WlanCloseHandle(hClient, NULL);
}

int main() {
    while (1) {
        scan_wifi_networks();
        Sleep(3000); // Refresh every 3 seconds
    }

    return 0;
}
