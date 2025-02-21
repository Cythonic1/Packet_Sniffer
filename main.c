#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include "./protocols.h"

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

void printMacAddress(uint8_t mac[], size_t size){
    for (int i = 0; i < size ; i++) {
        if(i == (size - 1)){
            fprintf(stdout, "%02X", mac[i]);
            break;
        }
        fprintf(stdout, "%02X:", mac[i]);
    }
    printf("\n");

}
// the numberOfBitsToPrint is starting from zero as well as the offset
void printBits(void *someint , int size, int numberOfBitsToPrint, int offSet){
    long long i,j;
    unsigned char *byte = (unsigned char *)someint; // Cast to unsigned char pointer
    int counterbytes = (size*8) -1 ;
    for(i = 0; i < size; i++){
        for(j = 7; j >= 0; j--){
            unsigned char bit = (byte[i] >> j)&1;
            counterbytes--;
            if (offSet != 0){
                if (counterbytes <= offSet){
                    fprintf(stdout, ".");
                }else{
                    fprintf(stdout, "%d", bit);
                }
            }else{
                if (counterbytes >= numberOfBitsToPrint){
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

unsigned char *parserDomainName(const u_char *packetBody, int offset){

    packetBody = packetBody + offset;
    int lenCounter = 0;
    int lableCounter = 0;
    while(packetBody [offset] != 0){
        int lableLen = packetBody[offset] ;
        printf("Lable len is %02x \n", (unsigned char)lableLen);
        lenCounter += lableLen;
        lableCounter += 1;
        offset += (lableLen+1);
    }
    // char *domainName = (char *) malloc((sizeof(char) * lenCounter) + lableCounter + 1);
    // if(domainName == NULL){
    //     perror("Error while allocating for the domainName\n");
    //     return NULL;
    // }
    // printf("The len of the question is : %d\n",lenCounter );
    // int offsetBack = 0;

    // while(packetBody[offsetBack] != 0){
    //     int lableLen = packetBody[offsetBack] ;
    //     printf("Lable len is %02x \n", (unsigned char)lableLen);
    //     lenCounter += lableLen;
    //     strncpy(domainName, packetBody, lableLen);
    //     // You could remove the need for the lable counter
    //     // if you do it this way becuase now on every index the len will be the index zero
    //     // seince we add the lable len for the pointer it self we return the pointer then we will
    //     // have the packetBody starting from the index of the qClass
    //     packetBody+= lableLen;
    //     offsetBack += (lableLen+1);
    // }

    return NULL;
}
void paresDNSQuestionHeader(uint16_t numberOfQuestion,const u_char *packetBody,  DNS_t *dns ){
    // There is a bit before the name indecate the size of the name
    // so we need to read that byte first in order to parse everything.
    dns->questions = (QuestionDNS *) malloc(sizeof(QuestionDNS) * numberOfQuestion);
    if(dns->questions == NULL){
        perror("Error while allocating for questions\n");
        return ;
    }
    printf("The number of question is :%u \n", numberOfQuestion);

    // printf(" Question name len : %d", dnsQuestionHeader[0]);
    parserDomainName(packetBody, 0);
    free(dns->questions);
    return;
}

void printDNSHeader(const u_char *packetBody){
    DNS_t *dns = (DNS_t *)malloc(sizeof(DNS_t));
    if(dns == NULL){
        perror("Error while allocating for dns\n");
    }
    dns->header = (HeaderDNS_t *) packetBody;
    fprintf(stdout, "\tPacket ID: %u\n", ntohs(dns->header->id));
    printBits(&dns->header->flags, sizeof(dns->header->flags), 15, 0);
    fprintf(stdout, "\tflags: \n");
    fprintf(stdout, "\tQdcount : %u\n", ntohs(dns->header->qdcount));
    fprintf(stdout, "\tancount:  %u\n", ntohs(dns->header->ancount));
    fprintf(stdout, "\tnscount : %u\n", ntohs(dns->header->nscount));
    fprintf(stdout, "\tarcount : %u\n", ntohs(dns->header->arcount));
    packetBody = packetBody + sizeof(HeaderDNS_t);
    paresDNSQuestionHeader(ntohs(dns->header->qdcount), packetBody ,dns);
    free(dns);
}
void printTCPHeader(const u_char *packetBody ){

    TCPHeader_t *tcp = (TCPHeader_t *) packetBody;

    fprintf(stdout, "Source Port: %u\n", ntohs(tcp->srcPort));
    fprintf(stdout, "Destinitation Port: %u\n", ntohs(tcp->destPort));
    fprintf(stdout, "Sequence Number : %u\n", ntohl(tcp->sequenceNumber));
    fprintf(stdout, "Acknowledgment number : %u\n", ntohl(tcp->ackNumber));
    fprintf(stdout, "Data offset : %u\n", (tcp->doRsvFlags >> 4) * 4);

    // Parse data offset, reserved bits, and flags
    uint16_t doRsvFlags = ntohs(tcp->doRsvFlags);
    uint8_t data_offset = (doRsvFlags >> 12) & 0xF;
    uint8_t reserved = (doRsvFlags >> 9) & 0x7;
    uint8_t ns_flag = (doRsvFlags >> 8) & 0x1;
    uint8_t cwr_flag = (doRsvFlags >> 7) & 0x1;
    uint8_t ece_flag = (doRsvFlags >> 6) & 0x1;
    uint8_t urg_flag = (doRsvFlags >> 5) & 0x1;
    uint8_t ack_flag = (doRsvFlags >> 4) & 0x1;
    uint8_t psh_flag = (doRsvFlags >> 3) & 0x1;
    uint8_t rst_flag = (doRsvFlags >> 2) & 0x1;
    uint8_t syn_flag = (doRsvFlags >> 1) & 0x1;
    uint8_t fin_flag = doRsvFlags & 0x1;
    fprintf(stdout, "Data Offset (Header Length): %u bytes\n", data_offset * 4);
    fprintf(stdout, "Reserved Bits: %u\n", reserved);
    printBits(&tcp->doRsvFlags, sizeof(tcp->doRsvFlags), 8, 0);
    fprintf(stdout, "Flags: [NS=%u, CWR=%u, ECE=%u, URG=%u, ACK=%u, PSH=%u, RST=%u, SYN=%u, FIN=%u]\n",
            ns_flag, cwr_flag, ece_flag, urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag);

    fprintf(stdout, "window  : %u\n", ntohs(tcp->window));
    fprintf(stdout, "CheckSum  : %u\n", ntohs(tcp->checkSum));
    fprintf(stdout, "urgent Pointer  : %u\n", ntohs(tcp->urgentPointer));

    return ;
}

void printDHCPHeader(const u_char *packetBody ){
    DHCP_t *dhcp = (DHCP_t *) packetBody;
    fprintf(stdout, "messages Type: %u\n", dhcp->op);
    fprintf(stdout, "Hardware Type: %u\n", dhcp->htype);
    fprintf(stdout, "Hardware Address Length : %u\n", dhcp->hlen);
    fprintf(stdout, "hops : %u\n", dhcp->htop);
    fprintf(stdout, "Transcation Id: 0x%x\n",ntohl(dhcp->xid) );
    fprintf(stdout, "Second elapsed : %u\n", ntohs(dhcp->secs));
    uint16_t flagBits = ntohs(dhcp->flags);
    printBits(&flagBits, sizeof(dhcp->flags), 1, 14);
    fprintf(stdout, " Bootp flags : %u\n", flagBits  & 1);
    printBits(&flagBits, sizeof(dhcp->flags), 14, 0);
    fprintf(stdout, "reserved : 0x%x\n", (flagBits & 0x7FFF));
    struct in_addr ciaddr, giaddr, siaddr, yiaddr;
    ciaddr.s_addr = dhcp->ciaddr;
    yiaddr.s_addr = dhcp->yiaddr;
    siaddr.s_addr = dhcp->siaddr;
    giaddr.s_addr = dhcp->giaddr;
    fprintf(stdout, "Client IP address : %s\n", inet_ntoa(ciaddr));
    fprintf(stdout, "Your (client) IP address : %s\n", inet_ntoa(yiaddr));
    fprintf(stdout, "Next Server IP address: %s\n", inet_ntoa(siaddr));
    fprintf(stdout, "Relay agent IP address : %s\n", inet_ntoa(giaddr));
    fprintf(stdout, "Client Mac Address : ");
    printMacAddress(dhcp->macAddress, 6);
    fprintf(stdout, "Server host name : %s\n", dhcp->sname);
    fprintf(stdout, "Boot file name  : %s\n", dhcp->file);

}

void printUDPHeader(const u_char *packetBody ){

    UDPHeader_t *udp = (UDPHeader_t *) packetBody;
    uint16_t udpHeaderSize = sizeof(UDPHeader_t);
    fprintf(stdout, "Source Port: %u\n", ntohs(udp->srcPort));
    fprintf(stdout, "Destinitation Port: %u\n", ntohs(udp->destPort));
    fprintf(stdout, "Length: %u\n", ntohs(udp->length));
    fprintf(stdout, "CheckSum  : %u\n", ntohs(udp->checkSum));
    packetBody += udpHeaderSize;
    if (ntohs(udp->srcPort) == 68 || ntohs(udp->srcPort) == 67) {
        fprintf(stdout, "This is a DHCP packet\n");
        printDHCPHeader(packetBody);
    }

    if (ntohs(udp->srcPort) == 53 || ntohs(udp->srcPort) == 53) {
        fprintf(stdout, "This is a DNS packet: \n");
        printDNSHeader(packetBody);
    }
    return ;
}

void printARPHeader(const u_char *packetBody){
    packetBody = packetBody + sizeof(struct ether_header);
    ARP_t *arp = (ARP_t *) packetBody;

    struct in_addr srcAddr, destAddr;

    fprintf(stdout, "Hardware Type : %u\n", ntohs(arp->HardwareType));
    fprintf(stdout, "Protocol Type : %u\n", ntohs(arp->ProtocolType));
    fprintf(stdout, "Hardware Address Length : %u\n", arp->HardwareAddressLength);
    fprintf(stdout, "Protocl Address Length : %u\n", arp->ProtocolAddressLength);
    fprintf(stdout, "Operation: %u\n", ntohs(arp->Operation));

    fprintf(stdout, "Sender Hardware Address : ");
    printMacAddress(arp->SenderHardwareAddress, 6);

    uint32_t senderAddr;
    memcpy(&senderAddr, arp->SenderProtocolAddress,4);
    srcAddr.s_addr = senderAddr;
    fprintf(stdout, "Sender protocol Address : %s\n", inet_ntoa(srcAddr));

    fprintf(stdout, "Target Hardware Address : ");
    printMacAddress(arp->TargetHardwareAddress, 6);

    uint32_t targetAddr;
    memcpy(&targetAddr, arp->TargetProtocolAddress,4);
    destAddr.s_addr = targetAddr;
    fprintf(stdout, "Target protocol Address : %s\n", inet_ntoa(destAddr));
}


void printIpHeader(const u_char *packetBody) {
    int etherHeaderLen = sizeof(struct ether_header);
    packetBody = packetBody + etherHeaderLen;
    // The example below shows how we can extract the lower 4 bits from the first
    // byte in the IP header example if we have 01010011 the results gonna be
    // 0011.
    int ipHeaderLen = ((*packetBody) & 0x0F);
    printf("The ip header length in 32-bit %d;\n", ipHeaderLen);
    printf("The ip header length in words %d;\n", ipHeaderLen * 4);
    // we mutilplay by 4 to change from 32 bit to words
    ipHeaderLen = ipHeaderLen * 4;
    int protocolType = *(packetBody + 9);

    fprintf(stdout, "The ip header type : %d\n", (*(packetBody + 9)));
    // conver it into switch for better managment
    if (protocolType != IPPROTO_TCP) {
        fprintf(stderr, "This packet it not TCP packet\n");
    }

    IPHeader_t *parser = (IPHeader_t *)packetBody;
    printBits(&parser->versionAndIhl, sizeof(parser->versionAndIhl), 3, 0);
    fprintf(stdout, " ihl: %u (Header Length: %u bytes)\n",
            (parser->versionAndIhl & 0x0F), (parser->versionAndIhl & 0x0F) * 4);

    printBits(&parser->versionAndIhl, sizeof(parser->versionAndIhl), 3, 3);
    fprintf(stdout, "Ip version: %u\n",
            parser->versionAndIhl >> 4); // the ">>" is used to get the first 4 bits

    printBits(&parser->tos, sizeof(parser->tos), 5, 1);
    fprintf(stdout, "Defrentiated service codepoint : %u\n", parser->tos >> 6);

    printBits(&parser->tos, sizeof(parser->tos), 1, 0);
    fprintf(stdout, "Explicit conjection notification: %u\n",
            (parser->tos & 0x03));

    uint16_t totalLength = ntohs(parser->totalLength);
    printBits(&totalLength, sizeof(parser->totalLength), 15, 0);
    fprintf(stdout, "Total length %u\n", totalLength);

    uint16_t identification = ntohs(parser->identification);
    printBits(&parser->identification, sizeof(parser->identification), 15, 0);
    fprintf(stdout, "identification : %u\n", identification);

    /*uint16_t fragmentOffSetAndFlags = ntohs(parser->fragmentOffSetAndFlags);*/
    /*printBits(&fragmentOffSetAndFlags, sizeof(fragmentOffSetAndFlags), 15, 0);*/
    /*uint8_t flags = (fragmentOffSetAndFlags >> 13) & 0x07;*/
    /*fprintf(stdout, "flags: %u\n", flags);*/

    printBits(&parser->ttl, sizeof(parser->ttl), 7, 0);
    fprintf(stdout, "time to ive: %u\n", parser->ttl);

    printBits(&parser->protocol, sizeof(parser->protocol), 7, 0);
    fprintf(stdout, "the Protocol type is %u\n", parser->protocol);

    uint16_t checkSum = ntohs(parser->headerChecksum);
    printBits(&checkSum, sizeof(parser->headerChecksum), 15, 0);
    fprintf(stdout, "CheckSum: %u\n", checkSum);

    struct in_addr srcAddr, destAddr;
    srcAddr.s_addr = parser->srcIP;
    destAddr.s_addr = parser->destIP;
    printf("Source IP address: %s\n", inet_ntoa(srcAddr));
    printf("Destination IP address: %s\n", inet_ntoa(destAddr));

    packetBody = packetBody + ipHeaderLen;
    
    if (parser->protocol == 6) {
        /*int tcpHeaderLen = etherHeaderLen + ipHeaderLen ;*/
        printTCPHeader(packetBody);
    } else if (parser->protocol == 17) {
        printUDPHeader(packetBody);
    } else {
        fprintf(stdout, "Protocol is : %i", parser->protocol);
        fprintf(stderr, "Not supported Protocol\n");
    }
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
        /*printARPHeader(packetBody);*/
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
    struct pcap_pkthdr packetHeader = {.caplen = 0, .len = 0, .ts = {.tv_sec = 0, .tv_usec = 0}};
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
