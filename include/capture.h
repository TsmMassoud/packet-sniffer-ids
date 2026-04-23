#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap/pcap.h>

/* Buffer error size */
#define PCAP_ERRBUF_SIZE 256

/* Callback function called for every snap received */
void callback_analyse(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

/* Main function for capture */
void start_capture(void);

#endif 