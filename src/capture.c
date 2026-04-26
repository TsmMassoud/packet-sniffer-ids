#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include "capture.h"

// Callback executed for each captured packet
void callback_analyse(u_char *user, const struct pcap_pkthdr *header, const u_char *packet){
    // Print 
    printf("Packet received. Length : %u\n", (unsigned int)header->len);

    // Transfer to parser
    parse_packet(packet,header);
}

// Function : Search default interface
int get_default_interface(char *iface, size_t len) {
    FILE *fp = popen("ip route show default 2>/dev/null", "r"); // ask system (command line)
    if (!fp) return 0;

    char line[256];

    if (fgets(line, sizeof(line), fp) == NULL) {
        pclose(fp);
        return 0;
    }

    pclose(fp);

    // Search "dev XXX"
    char *dev = strstr(line, "dev ");
    if (!dev) return 0;

    dev += 4; // dev [interface]

    sscanf(dev, "%s", iface);

    return 1;
}

// Verify if an interface exists
int interface_exists(pcap_if_t *alldevs,const char *name){
    pcap_if_t *d;
    for(d = alldevs; d!= NULL;d = d->next){
        if(strcmp(name,d->name) == 0){
            return 1;
        }
    }
    return 0;
}

// Start packet capture and process packets via callback
void start_capture(){

    // --- Initialisation ---
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char device[64] = "";
    char errbuf[PCAP_ERRBUF_SIZE];

    // Get default interface 
    if (!get_default_interface(device, sizeof(device))) {
        fprintf(stderr, "Error: cannot detect default interface\n");
        return;
    }

    printf("Default route interface : %s\n",device);

    // Get pcap interfaces
    if(pcap_findalldevs(alldevs,errbuf) == -1){
        fprintf(stderr,"Error pcap_findalldevs() : %s\n",errbuf);
        return;
    }

    // Verify if it exists in pcap
    if(!interface_exists(alldevs,device)){
        fprintf(stderr,"Interface %s not found in pcap_list\n",device);
        pcap_freealldevs(alldevs);
        return;
    }


    // Free device list
    pcap_freealldevs(alldevs);

    // Open device
    pcap_t *handle = pcap_open_live(device, 65535, 1, 1000, errbuf);

    if(!handle){
        fprintf(stderr, "Error while opening device %s: %s\n", device, errbuf);
        return;
    }

    // --- Listening ---
    printf("Listening on interface %s...\n", device);

    // Capture loop
    pcap_loop(handle, -1, callback_analyse, NULL);

    // Cleanup
    pcap_close(handle);

}
