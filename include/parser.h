#ifndef PARSER_H
#define PARSER_H

/**
 * @file parser.h
 * @brief Network packet parsing module
 * @author Massoud
 */

#include <pcap/pcap.h>
#include <netinet/in.h>

/**
 * @brief Parse a raw network packet and extract IP information
 *
 * This function extracts the IPv4 header from a raw Ethernet frame
 * and prints source and destination IP addresses.
 *
 * @param packet Raw packet data captured by libpcap
 * @param header Packet metadata (timestamp, length, etc.)
 */
void parse_packet(const u_char *packet,
                  const struct pcap_pkthdr *header);

#endif /* PARSER_H */