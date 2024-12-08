#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void list_active_interfaces() {
    char command[] = "iw dev | grep Interface";  // Command to list active interfaces

    // Execute the command to list interfaces
    int ret = system(command);
    if (ret == -1) {
        perror("Error executing command");
    } else {
        printf("Active wireless interfaces listed above\n");
    }
}

void activate_monitor_mode(const char *interface) {
    char command[256];

    // Disable the interface before switching to monitor mode
    snprintf(command, sizeof(command), "sudo ip link set %s down", interface);
    if (system(command) == -1) {
        perror("Error bringing interface down");
        return;
    }

    // Set the interface to monitor mode using iw
    snprintf(command, sizeof(command), "sudo iw dev %s set type monitor", interface);
    if (system(command) == -1) {
        perror("Error setting monitor mode");
        return;
    }

    // Enable the interface again
    snprintf(command, sizeof(command), "sudo ip link set %s up", interface);
    if (system(command) == -1) {
        perror("Error bringing interface up");
        return;
    }

    // Print the success message when monitor mode is successfully activated
    printf("SPY MODE ACTIVATED! = %s\n", interface);
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        // If no arguments are provided, list active wireless interfaces
        list_active_interfaces();
    } else if (argc == 2) {
        // If an interface is provided, activate monitor mode on it
        const char *interface = argv[1];
        activate_monitor_mode(interface);
    } else {
        fprintf(stderr, "Usage: %s [interface]\n", argv[0]);
        return 1;
    }

    return 0;
}
