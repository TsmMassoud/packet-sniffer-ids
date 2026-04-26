#include <netinet/ip.h> // For struct ip
#include <netinet/in.h> // For addr struct (like sockaddr_in)
#include <pcap/pcap.h>
#include <arpa/inet.h> // For conversion like inet_ntoa
#include <stdio.h>
#include <pcap/pcap.h>

void parse_packet(const u_char *packet,const struct pcap_pkthdr *header){

    // + 14 TO IP
    const u_char *new_packet = packet + 14;
    struct ip *ip_header = (struct ip*)new_packet; // to struct ip


    // Extract IP_src and IP_dest
    char *ip_src,*ip_dest;
    ip_src = inet_ntoa(ip_header->ip_src);
    ip_dest = inet_ntoa(ip_header->ip_dst);


    // Print Ip addr
    printf("IP source : %s\n",ip_src);
    printf("IP destination : %s\n",ip_dest);

}

