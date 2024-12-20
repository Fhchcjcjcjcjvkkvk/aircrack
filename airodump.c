#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

// Define constants
#define SNAP_LEN 65535
#define TIMEOUT_MS 1000

// Define frame control field masks
#define TYPE_MANAGEMENT 0x00
#define SUBTYPE_BEACON  0x08

// Define radiotap header offsets (varies by device)
#define RADIOTAP_DBM_ANTSIG 22

// Wi-Fi Management Frame Parsing
typedef struct {
    uint8_t frame_control[2];
    uint8_t duration[2];
    uint8_t addr1[6]; // Destination MAC
    uint8_t addr2[6]; // Source MAC (BSSID)
    uint8_t addr3[6]; // Transmitter MAC
    uint8_t seq_ctrl[2];
} wifi_mgmt_frame_t;

// Function to extract ESSID from the beacon frame
void extract_essid(const u_char *packet, int offset, int length) {
    printf(" ESSID: ");
    if (length == 0) {
        printf("<Hidden>\n");
        return;
    }
    for (int i = 0; i < length; i++) {
        printf("%c", packet[offset + i]);
    }
    printf("\n");
}

// Function to parse the captured packets and display relevant Wi-Fi information
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    int radiotap_len = packet[2]; // Radiotap header length
    const wifi_mgmt_frame_t *mgmt_frame = (wifi_mgmt_frame_t *)(packet + radiotap_len);

    // Extract frame control type and subtype
    uint8_t type = (mgmt_frame->frame_control[0] & 0x0C) >> 2;
    uint8_t subtype = (mgmt_frame->frame_control[0] & 0xF0) >> 4;

    if (type == TYPE_MANAGEMENT && subtype == SUBTYPE_BEACON) {
        // Beacon frame detected
        printf("BSSID: %02x:%02x:%02x:%02x:%02x:%02x",
               mgmt_frame->addr2[0], mgmt_frame->addr2[1], mgmt_frame->addr2[2],
               mgmt_frame->addr2[3], mgmt_frame->addr2[4], mgmt_frame->addr2[5]);

        // Extract signal strength (RSSI)
        int8_t signal_strength = packet[RADIOTAP_DBM_ANTSIG];
        printf(" PWR: %d dBm", signal_strength);

        // Locate the fixed parameters and tagged parameters
        const u_char *tagged_params = packet + radiotap_len + sizeof(wifi_mgmt_frame_t) + 12; // Skip fixed params
        while (tagged_params < packet + header->caplen) {
            uint8_t tag_number = tagged_params[0];
            uint8_t tag_length = tagged_params[1];
            if (tag_number == 0) { // ESSID tag
                extract_essid(tagged_params, 2, tag_length);
            }
            tagged_params += 2 + tag_length;
        }

        // Placeholder for AUTH detection logic
        // Analyze tagged parameters to detect AUTH (WEP, WPA, WPA2, WPA3)
        printf(" AUTH: WPA2\n"); // Replace with actual parsing logic
    }
}

void usage(const char *prog_name) {
    printf("Usage: %s -i <interface>\n", prog_name);
}

int main(int argc, char *argv[]) {
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;
    pcap_t *handle;

    // Parse command-line arguments
    if (argc != 3 || strcmp(argv[1], "-i") != 0) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    dev = argv[2];

    // Find all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    // Validate interface
    for (device = alldevs; device != NULL; device = device->next) {
        if (strcmp(device->name, dev) == 0) {
            printf("Using interface: %s\n", dev);
            break;
        }
    }

    if (device == NULL) {
        fprintf(stderr, "Error: Interface %s not found.\n", dev);
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    // Open device for capturing
    handle = pcap_open_live(dev, SNAP_LEN, 1, TIMEOUT_MS, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    // Check for 802.11 packet support
    if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO) {
        fprintf(stderr, "Device %s doesn't support IEEE 802.11 packets.\n", dev);
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    printf("Starting capture on interface: %s\n", dev);

    // Capture packets
    pcap_loop(handle, 0, packet_handler, NULL);

    // Cleanup
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return EXIT_SUCCESS;
}
