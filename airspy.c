#include <windows.h>
#include <stdio.h>
#include <string.h>

#define MAX_BUFFER 1024
#define WM_USER_UPDATE  (WM_USER + 1)

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void scanNetworks(HWND hwndList);
void updateListView(HWND hwndList, const char* networks);

int main() {
    const char szClassName[] = "WiFiScanner";
    HWND hwnd;
    MSG Msg;
    WNDCLASSEX wc;
    
    // Initialize the window class
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszMenuName = NULL;
    wc.lpszClassName = szClassName;
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    if (!RegisterClassEx(&wc)) {
        MessageBox(NULL, "Window Registration Failed!", "Error!", MB_ICONEXCLAMATION | MB_OK);
        return 0;
    }

    // Create window
    hwnd = CreateWindowEx(WS_EX_CLIENTEDGE, szClassName, "WiFi Network Scanner",
                          WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 500, 400,
                          NULL, NULL, wc.hInstance, NULL);

    if (hwnd == NULL) {
        MessageBox(NULL, "Window Creation Failed!", "Error!", MB_ICONEXCLAMATION | MB_OK);
        return 0;
    }

    // Create a list view for network information
    HWND hwndList = CreateWindow(WC_LISTVIEW, "", WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
                                 10, 10, 460, 300, hwnd, NULL, wc.hInstance, NULL);

    // Set up columns for BSSID, ESSID, Authentication, Channel, and Beacon Count
    LVCOLUMN lvc;
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;
    lvc.cx = 120;
    lvc.pszText = "BSSID";
    ListView_InsertColumn(hwndList, 0, &lvc);
    lvc.pszText = "ESSID";
    ListView_InsertColumn(hwndList, 1, &lvc);
    lvc.pszText = "Authentication";
    ListView_InsertColumn(hwndList, 2, &lvc);
    lvc.pszText = "Channel";
    ListView_InsertColumn(hwndList, 3, &lvc);
    lvc.pszText = "Beacon Count";
    ListView_InsertColumn(hwndList, 4, &lvc);

    // Set up a timer to refresh the list every 10 seconds
    SetTimer(hwnd, 1, 10000, NULL); // 10-second timer to refresh

    // Show the window
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    // Message loop
    while (GetMessage(&Msg, NULL, 0, 0)) {
        TranslateMessage(&Msg);
        DispatchMessage(&Msg);
    }

    return Msg.wParam;
}

// Window Procedure function
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HWND hwndList;

    switch (msg) {
        case WM_CREATE:
            hwndList = GetDlgItem(hwnd, 1);
            break;

        case WM_TIMER:
            if (wp == 1) {
                // Scan for networks when the timer triggers
                scanNetworks(hwndList);
            }
            break;

        case WM_USER_UPDATE:
            // Refresh the list of networks
            updateListView(hwndList, (const char*)lp);
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, msg, wp, lp);
    }
    return 0;
}

// Function to scan networks using netsh
void scanNetworks(HWND hwndList) {
    char command[] = "netsh wlan show networks mode=bssid";
    char buffer[MAX_BUFFER];
    char result[MAX_BUFFER];
    FILE* fp = _popen(command, "r");

    if (!fp) {
        MessageBox(hwndList, "Failed to execute netsh command!", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Read the output of the netsh command
    result[0] = '\0';
    while (fgets(buffer, MAX_BUFFER, fp) != NULL) {
        strcat(result, buffer);
    }
    fclose(fp);

    // Send the result to the window for updating the list view
    SendMessage(hwndList, WM_USER_UPDATE, 0, (LPARAM)strdup(result));
}

// Function to update the list view with network information
void updateListView(HWND hwndList, const char* networks) {
    // Split the networks string by lines
    char* network = strtok((char*)networks, "\n");
    ListView_DeleteAllItems(hwndList);  // Clear the existing list

    while (network != NULL) {
        // Extract the BSSID, ESSID, Authentication, Channel, and Beacon Count information
        char bssid[50], essid[50], auth[50], channel[50], beaconCount[50];
        int beaconCountValue = 0;

        // Parse BSSID
        if (sscanf(network, "BSSID %s", bssid) == 1) {
            network = strtok(NULL, "\n");

            // Parse ESSID
            if (strstr(network, "SSID")) {
                sscanf(network, "SSID : %s", essid);
            }
            network = strtok(NULL, "\n");

            // Parse Authentication
            if (strstr(network, "Authentication")) {
                sscanf(network, "Authentication : %s", auth);
            }
            network = strtok(NULL, "\n");

            // Parse Channel
            if (strstr(network, "Channel")) {
                sscanf(network, "Channel : %s", channel);
            }
            network = strtok(NULL, "\n");

            // Parse Beacon Count (Typically found in the scan output for each network)
            if (strstr(network, "Beacons")) {
                // Extract beacon count by parsing the line with "Beacons"
                if (sscanf(network, "Beacons : %d", &beaconCountValue) == 1) {
                    sprintf(beaconCount, "%d", beaconCountValue);
                }
            }
        }

        // Add the network info to the list view
        LVITEM lvItem;
        lvItem.mask = LVIF_TEXT;
        lvItem.iItem = ListView_GetItemCount(hwndList);
        lvItem.iSubItem = 0;
        lvItem.pszText = bssid;
        ListView_InsertItem(hwndList, &lvItem);
        ListView_SetItemText(hwndList, lvItem.iItem, 1, essid);
        ListView_SetItemText(hwndList, lvItem.iItem, 2, auth);
        ListView_SetItemText(hwndList, lvItem.iItem, 3, channel);
        ListView_SetItemText(hwndList, lvItem.iItem, 4, beaconCount);

        network = strtok(NULL, "\n");
    }
}
