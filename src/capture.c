#include <stdio.h>
#include <pcap/pcap.h>

/* Callback function which sends snaps to parser lately */

void callback_analyse(u_char *user, const struct pcap_pkthdr *header, const u_char *packet){
    printf("Packet received. Length : %u\n",(unsigned int)header->len);
}


/* Function : capture snap and call a callback function for every snap received */
void start_capture(){
    
    /******************************/
    /******* INITIALISATION *******/
    /******************************/

    char *device = "eth0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(device,65535,1,1000,errbuf);

    if(handle == NULL){
        fprintf(stderr,"Error while opening device %s: %s\n",device,errbuf);
        return;
    }

    /* -------------------------- */

    /******************************/
    /********* LISTENING **********/
    /******************************/

    printf("Listening on interface %s...",device);

    /* Capture */
    pcap_loop(handle,-1,callback_analyse,NULL);

    /* -------------------------- */

    /* Close pcap */
    pcap_close(handle);


}
