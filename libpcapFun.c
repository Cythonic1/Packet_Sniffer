#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <net/ethernet.h>

// Function to print the LinkedList
void printLinkedList(pcap_if_t *list ){

    pcap_if_t *next_p;
    next_p = list;
    while (next_p != NULL){
        fprintf(stdout, "The name of the interface is : %s\n", next_p->name);
        next_p = next_p->next;

    }
}


void printPacketHeader(const u_char *packet, struct pcap_pkthdr packetHeader){
    fprintf(stdout, "Packet Capture Length %d\n",packetHeader.caplen);
    fprintf(stdout, "Packet Total Length %d\n",packetHeader.len);
}

typedef struct IPHeader {
    uint8_t versionAndIhl;
    uint8_t tos;
    uint16_t totalLength;
    uint16_t identification;
    uint16_t fragmentOffSetAndFlags;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t headerChecksum;
    uint32_t srcIP;
    uint32_t destIP;
} IPHeader_t;


// the numberOfBitsToPrint is starting from zero as well as the offset
void printBits(void *someint , int size, int numberOfBitsToPrint, int offSet){
    long long i,j;
    unsigned char *byte = (unsigned char *)someint; // Cast to unsigned char pointer
    for(i = 0; i < size; i++){
        for(j = 7; j >= 0; j--){
            unsigned char bit = (byte[i] >> j)&1;
            if (offSet != 0){
                if (j <= offSet){
                    fprintf(stdout, ".");
                }else{
                    fprintf(stdout, "%d", bit);
                }
            }else{
                if (j > numberOfBitsToPrint){
                    fprintf(stdout, ".");
                }else{
                    fprintf(stdout, "%d", bit);
                }
            }
        }
        printf(" ");
    }
    /*printf("\n");*/
}
void printIpHeader(const u_char *packetBody){
    const u_char *ipHeader, *tcpHeader, *payloadLen;
    int etherHeaderLen = sizeof(struct ether_header);
    ipHeader = packetBody + etherHeaderLen;
    // The example below shows how we can extract the lower 4 bits from the first byte 
    // in the IP header example if we have 01010011 the results gonna be 0011.
    int ipHeaderLen = ((*ipHeader) & 0x0F);
    printf("The ip header length in 32-bit %d;\n", ipHeaderLen);
    printf("The ip header length in words %d;\n", ipHeaderLen * 4);
    // we mutilplay by 4 to change from 32 bit to words 
    ipHeaderLen = ipHeaderLen * 4;
    int protocolType = *(ipHeader + 9);


    fprintf(stdout, "The ip header type : %d\n", (*(ipHeader + 9)));
    // conver it into switch for better managment
    if (protocolType != IPPROTO_TCP){
        fprintf(stderr, "This packet it not TCP packet\n");
    }

    IPHeader_t *parser = (IPHeader_t *)ipHeader;
    printBits(&parser->versionAndIhl, sizeof(parser->versionAndIhl), 3, 0);
    fprintf(stdout, " ihl: %u (Header Length: %u bytes)\n", (parser->versionAndIhl & 0x0F), (parser->versionAndIhl & 0x0F) * 4);

    printBits(&parser->versionAndIhl, sizeof(parser->versionAndIhl), 3, 3);
    fprintf(stdout, "Ip version: %u\n", parser->versionAndIhl >> 4); // the ">>" is used to get the first 4 bits

    printBits(&parser->tos, sizeof(parser->tos), 5, 1);
    fprintf(stdout, "Defrentiated service codepoint : %u\n", parser->tos >> 6);

    printBits(&parser->tos, sizeof(parser->tos), 1, 0);
    fprintf(stdout, "Explicit conjection notification: %u\n", (parser->tos & 0x03));
    
    printBits(&parser->totalLength, sizeof(parser->totalLength), 15, 0);
    fprintf(stdout, "Total length %u\n", parser->totalLength);

    printBits(&parser->identification, sizeof(parser->identification),15, 0);
    fprintf(stdout, "identification : %u\n", parser->identification);

    /*uint16_t fragmentOffSetAndFlags = ntohs(parser->fragmentOffSetAndFlags);*/
    /*printBits(&fragmentOffSetAndFlags, sizeof(fragmentOffSetAndFlags), 15, 0);*/
    /*uint8_t flags = (fragmentOffSetAndFlags >> 13) & 0x07;*/
    /*fprintf(stdout, "flags: %u\n", flags);*/
    
    printBits(&parser->ttl, sizeof(parser->ttl), 7, 0);
    fprintf(stdout, "time to ive: %u\n", parser->ttl);

    printBits(&parser->protocol, sizeof(parser->protocol), 7, 0);
    fprintf(stdout, "the Protocol type is %u\n", parser->protocol);

    printBits(&parser->headerChecksum, sizeof(parser->headerChecksum), 15, 0);
    fprintf(stdout, "CheckSum: %u\n", parser->headerChecksum);
    
    uint32_t srcIP = ntohl(parser->srcIP);
    printf("Source IP address: %u.%u.%u.%u\n",
           (srcIP >> 24) & 0xFF, // First byte
           (srcIP >> 16) & 0xFF, // Second byte
           (srcIP >> 8) & 0xFF,  // Third byte
           srcIP & 0xFF);        // Fourth byte

    uint32_t destIP = ntohl(parser->destIP);
    printf("Destinitation IP address: %u.%u.%u.%u\n",
           (destIP >> 24) & 0xFF, // First byte
           (destIP >> 16) & 0xFF, // Second byte
           (destIP >> 8) & 0xFF,  // Third byte
           destIP & 0xFF);        // Fourth byte
}

void packetHandler(u_char  *args, const struct pcap_pkthdr *packetHeader, const u_char *packetBody){
    struct ether_header *etherHeader;
    etherHeader = (struct ether_header *) packetBody;
    int etherHeaderType = ntohs(etherHeader->ether_type);
    if(etherHeaderType == ETHERTYPE_IP){
        fprintf(stdout, "This packet is an IP packet\n");
        printIpHeader(packetBody);
        fprintf(stdout, "------------------------------------\n");
    }else if(etherHeaderType == ETHERTYPE_ARP){
        fprintf(stdout, "This packet is an ARP packet\n");
        fprintf(stdout, "------------------------------------\n");
    }else if(etherHeaderType == ETHERTYPE_REVARP){
        fprintf(stdout, "This packet is a Reverse ARP  packet\n");
        fprintf(stdout, "------------------------------------\n");
    }
    /*printPacketHeader(packetBody, *packetHeader);*/
    return ;
}
int main(int argc , char **argv){
    // Gonna hold the list of devices
    pcap_if_t *devicesList;

    // Buffer to hold the error value
    char errorBuffer[PCAP_ERRBUF_SIZE];



    if(pcap_findalldevs(&devicesList, errorBuffer) == PCAP_ERROR){
        fprintf(stderr, "Not able to find the NICs");
        return 1;
    }
    printLinkedList(devicesList);

    // **Getting more info about the network device**;
    char ip[16] = {0};
    char subNetMask[16] = {0};
    bpf_u_int32 ip_address; // To hold the IP address as an integer
    bpf_u_int32 subNetMask_raw; // Same as the above but for the submask
    int lookUpReturnCode;
    struct in_addr address;
    char *deviceName = devicesList->name; // devices list will point at the first device which is the device i want

    lookUpReturnCode = pcap_lookupnet(deviceName, &ip_address, &subNetMask_raw,  errorBuffer);
    if(lookUpReturnCode == -1){
        fprintf(stderr, "Error while getting devices info\n");
        fprintf(stderr, "%s\n", errorBuffer);
        return 1;
    }

    address.s_addr = ip_address;
    strncpy(ip, inet_ntoa(address), 15);
    ip[15] = '\0';
    if(ip[0] == '\0'){
        fprintf(stderr, "Error in inet_ntoa\n");
        return 1;
    }


    address.s_addr = subNetMask_raw;
    strncpy(subNetMask, inet_ntoa(address), 15);
    subNetMask[15] = '\0';
    if(subNetMask[0] == '\0'){
        fprintf(stderr, "Error in inet_ntoa\n");
        return 1;
    }

    fprintf(stdout, "The device name is %s\n", deviceName);
    fprintf(stdout, "The device ip address is %s\n", ip);
    fprintf(stdout, "The device subnet mask is %s\n", subNetMask);

    /*pcap_freealldevs(devicesList);*/

    // ** Capture Live packets with the interface we have ** 

    pcap_t *handler;
    const u_char *packet;
    struct pcap_pkthdr packetHeader;
    int packetCountLimit = 1;
    int packetTimeOut = 90000; // In milliseconds

    handler = pcap_open_live(
        deviceName,
        BUFSIZ,
        packetCountLimit,
        packetTimeOut,
        errorBuffer
    );

    // This will attept to listen for a single packet at a time if the timeout passes it will return null.
    pcap_loop(handler, 0, packetHandler, NULL);
    /*if(packet == NULL){*/
    /*    fprintf(stderr, "No packet Found\n");*/
    /*    return 1;*/
    /*}*/

    printPacketHeader(packet, packetHeader);

    return 0;
}
