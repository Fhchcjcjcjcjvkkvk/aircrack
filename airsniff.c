#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <unistd.h>

#define EAPOL_TYPE 0x888e
#define WPA_HANDSHAKE_TIMEOUT 120  // 2 minutes timeout
#define WPA_HANDSHAKE_FRAME_COUNT 4  // 4 EAPOL frames for WPA handshake

// Structure to store sniff options
typedef struct {
    char *interface;
    char *filename;
    char *ap_mac;
} sniff_options;

// EAPOL frame detection
int eapol_frame_count = 0;
unsigned char ap_mac_addr[6];

// Callback function for packet processing
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    sniff_options *options = (sniff_options *)user_data;
    struct ether_header *eth_header = (struct ether_header *)packet;
    
    // Check if the packet is an EAPOL packet (EtherType 0x888e)
    if (ntohs(eth_header->ether_type) == EAPOL_TYPE) {
        // Extract source MAC address (AP MAC)
        unsigned char *src_mac = eth_header->ether_shost;

        // Compare with the AP MAC address
        if (memcmp(src_mac, ap_mac_addr, 6) == 0) {
            printf("EAPOL packet detected from AP MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
            
            // Increment EAPOL frame count
            eapol_frame_count++;

            // Check if we have 4 EAPOL frames, which indicates WPA handshake completion
            if (eapol_frame_count == WPA_HANDSHAKE_FRAME_COUNT) {
                printf("WPA HANDSHAKE FOUND!\n");
                pcap_breakloop(NULL);  // Stop capturing after finding the handshake
            }
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 7) {
        printf("Usage: ./airsniff -a ap_mac --write filename.pcap interface\n");
        return 1;
    }

    sniff_options options;
    options.ap_mac = NULL;
    options.filename = NULL;
    options.interface = NULL;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0) {
            options.ap_mac = argv[++i];
        } else if (strcmp(argv[i], "--write") == 0) {
            options.filename = argv[++i];
        } else {
            options.interface = argv[i];
        }
    }

    if (options.ap_mac == NULL || options.filename == NULL || options.interface == NULL) {
        printf("Invalid arguments.\n");
        return 1;
    }

    // Convert AP MAC address to byte array
    sscanf(options.ap_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &ap_mac_addr[0], &ap_mac_addr[1], &ap_mac_addr[2], &ap_mac_addr[3], &ap_mac_addr[4], &ap_mac_addr[5]);

    // Open the capture interface
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(options.interface, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        printf("Error opening device %s: %s\n", options.interface, errbuf);
        return 1;
    }

    // Open the output pcap file for writing
    pcap_dumper_t *dumper;
    dumper = pcap_dump_open(handle, options.filename);
    if (dumper == NULL) {
        printf("Error opening file %s: %s\n", options.filename, errbuf);
        return 1;
    }

    // Set up the timeout for 2 minutes (120 seconds)
    time_t start_time = time(NULL);
    time_t current_time;

    // Set the packet capture filter to capture only EAPOL packets
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ether proto 0x888e", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        printf("Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    // Set up packet sniffing callback
    pcap_loop(handle, 0, packet_handler, (unsigned char *)&options);

    // Loop for 2 minutes
    while (1) {
        current_time = time(NULL);
        if (difftime(current_time, start_time) >= WPA_HANDSHAKE_TIMEOUT) {
            break;
        }
    }

    // If no WPA handshake found within 2 minutes, print nothing
    if (eapol_frame_count < WPA_HANDSHAKE_FRAME_COUNT) {
        printf("No WPA handshake found within 2 minutes.\n");
    }

    // Clean up and close pcap handles
    pcap_close(handle);
    pcap_dump_close(dumper);

    return 0;
}
