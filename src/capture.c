#include <stdio.h>
#include <pcap/pcap.h>

// Callback executed for each captured packet
void callback_analyse(u_char *user, const struct pcap_pkthdr *header, const u_char *packet){
    printf("Packet received. Length : %u\n", (unsigned int)header->len);
}

// Start packet capture and process packets via callback
void start_capture(){

    // --- Initialisation ---
    char *device = "eth0";
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live(device, 65535, 1, 1000, errbuf);

    if(handle == NULL){
        fprintf(stderr, "Error while opening device %s: %s\n", device, errbuf);
        return;
    }

    // --- Listening ---
    printf("Listening on interface %s...", device);

    // Infinite capture loop
    pcap_loop(handle, -1, callback_analyse, NULL);

    // Cleanup
    pcap_close(handle);
}
