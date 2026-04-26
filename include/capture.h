#ifndef CAPTURE_H
#define CAPTURE_H

/**
 * @file capture.h
 * @brief Packet capture module using libpcap
 * @author Massoud
 */

#include <pcap/pcap.h>

#include "../include/parser.h"

/**
 * @brief Size of PCAP error buffer
 */
#define PCAP_ERRBUF_SIZE 256

/**
 * @brief Callback function called for each captured packet
 *
 * @param user   User data passed to pcap_loop (can be NULL)
 * @param header Packet metadata (timestamp, length, etc.)
 * @param packet Raw packet data
 */
void callback_analyse(u_char *user,
                       const struct pcap_pkthdr *header,
                       const u_char *packet);

/**
 * @brief Start packet capture on default interface
 *
 * Automatically detects the default network interface
 * (based on system routing table) and starts capturing packets.
 */
void start_capture(void);

/**
 * @brief Get default network interface (Internet route)
 *
 * @param iface Output buffer to store interface name
 * @param len   Size of buffer
 * @return 1 if success, 0 if failure
 */
int get_default_interface(char *iface, size_t len);

/**
 * @brief Check if an interface exists in pcap list
 *
 * @param alldevs List of pcap interfaces
 * @param name    Interface name to search
 * @return 1 if found, 0 otherwise
 */
int interface_exists(pcap_if_t *alldevs, const char *name);

#endif /* CAPTURE_H */