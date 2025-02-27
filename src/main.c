#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
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




int isCompressedLabel(uint16_t bytes) {
    if ((bytes & 0xC000) == 0xC000) {
        return bytes & 0x3FFF; // Return 14-bit offset
    }
    return -1;
}


/*Simple explnation of this function
 * First we getting packetBody which is the packet in the current state
 * for example the packet after parsing the question header will start from
 * the answer header and so one.
 * start of Packet is the beggning of the dns header which is getting from
 * parsing DNS header function. lastly a double pointer to where we want to save
 * the domain name
 *
 * Function Flow:
 * First we check if there  is any compression we handle it immediate
*/
const u_char *parseDomainName(const u_char *packetBody, const u_char *startOfPacket, unsigned char **domainNameOut) {
    // Handle immediate compression case
    if ((packetBody[0] & 0xC0) == 0xC0) {
        uint16_t offset = ntohs(*(uint16_t *)packetBody) & 0x3FFF;
        // 1100 1100 1100 1100
        // 0011 1111 1111 1111
        // Parse the name at the compression point
        parseDomainName(startOfPacket + offset, startOfPacket, domainNameOut);
        return packetBody + 2; // Skip the compression pointer (2 bytes)
    }

    // First pass: Calculate total length needed for domain name
    int totalLen = 0;
    int labelCount = 0;
    const u_char *ptr = packetBody;

    while (*ptr != 0) {
        // Check for compression pointer
        if ((*ptr & 0xC0) == 0xC0) {
            uint16_t offset = ntohs(*(uint16_t *)ptr) & 0x3FFF;
            // We need to follow the compression pointer
            const u_char *targetPtr = startOfPacket + offset;

            // Continue counting from the compression target
            while (*targetPtr != 0) {
                if ((*targetPtr & 0xC0) == 0xC0) {
                    // Handle nested compression
                    uint16_t nestedOffset = ntohs(*(uint16_t *)targetPtr) & 0x3FFF;
                    targetPtr = startOfPacket + nestedOffset;
                    continue;
                }

                int labelLen = *targetPtr;
                totalLen += labelLen;
                labelCount++;
                targetPtr += (labelLen + 1);
            }

            ptr += 2; // Skip compression pointer
            break;
        }

        int labelLen = *ptr;
        totalLen += labelLen;
        labelCount++;
        ptr += (labelLen + 1);
    }

    // Allocate memory for domain name (length + dots + null terminator)
    *domainNameOut = (unsigned char *)calloc(totalLen + labelCount, sizeof(char));
    if (*domainNameOut == NULL) {
        perror("Error allocating memory for domain name");
        return NULL;
    }


    // Construct the domain it self
    ptr = packetBody;
    char *outPtr = (char *)*domainNameOut;
    int isFirstLabel = 1;

    while (*ptr != 0) {
        // IF the pointer is compress
        if ((*ptr & 0xC0) == 0xC0) {
            uint16_t offset = ntohs(*(uint16_t *)ptr) & 0x3FFF;
            const u_char *targetPtr = startOfPacket + offset;

            // To check for contiues lables and nested pointers
            int isFirstCompressedLabel = 1;

            while (*targetPtr != 0) {
                if ((*targetPtr & 0xC0) == 0xC0) {
                    // Handle nested compression
                    uint16_t nestedOffset = ntohs(*(uint16_t *)targetPtr) & 0x3FFF;
                    targetPtr = startOfPacket + nestedOffset;
                    continue;
                }

                int labelLen = *targetPtr;

                // Add dot between labels
                // if (!isFirstLabel && !isFirstCompressedLabel) {
                //     *outPtr++ = '.';
                // }
                *outPtr++ = '.';
                // Copy label content
                memcpy(outPtr, targetPtr + 1, labelLen);
                outPtr += labelLen;
                targetPtr += (labelLen + 1);

                isFirstLabel = 0;
                isFirstCompressedLabel = 0;
            }

            ptr += 2; // Skip compression pointer
            break;
        }

        int labelLen = *ptr;

        // Add dot between labels
        if (!isFirstLabel) {
            *outPtr++ = '.';
        }

        // *outPtr++ = '.';
        // Copy label content
        memcpy(outPtr, ptr + 1, labelLen);
        outPtr += labelLen;
        ptr += (labelLen + 1);

        isFirstLabel = 0;
    }

    *outPtr = '\0'; // Null-terminate the string

    // Move past the null terminator if we didn't use compression
    if (*ptr == 0) {
        ptr++;
    }

    return ptr;
}

const u_char *parseDNSQuestions(uint16_t numberOfQuestions, const u_char *packetBody,
                               const u_char *startOfPacket, DNS_t *dns) {
    if (numberOfQuestions == 0) {
        return packetBody;
    }

    dns->questions = (QuestionDNS_t *)calloc(numberOfQuestions, sizeof(QuestionDNS_t));
    if (dns->questions == NULL) {
        perror("Error allocating memory for questions");
        return NULL;
    }

    printf("Number of questions: %u\n", numberOfQuestions);

    for (int i = 0; i < numberOfQuestions; i++) {
        // Parse domain name
        packetBody = parseDomainName(packetBody, startOfPacket, &dns->questions[i].qname);
        if (packetBody == NULL) {
            // Clean up already allocated resources
            for (int j = 0; j < i; j++) {
                free(dns->questions[j].qname);
            }
            free(dns->questions);
            dns->questions = NULL;
            return NULL;
        }

        // Parse qtype and qclass
        dns->questions[i].qtype = ntohs(*(uint16_t *)packetBody);
        packetBody += 2;
        dns->questions[i].qclass = ntohs(*(uint16_t *)packetBody);
        packetBody += 2;

        // Log the parsed question
        printf("Question #%d:\n", i+1);
        printf("  Domain: %s\n", dns->questions[i].qname);
        printf("  Type: %u\n", dns->questions[i].qtype);
        printf("  Class: %u\n", dns->questions[i].qclass);
    }

    return packetBody;
}

const char *getRecordTypeName(uint16_t type) {
    switch (type) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        default: return "UNKNOWN";
    }
}


const u_char *parseDNSAuthoritative(uint16_t numberOfAuthoritive, const u_char *packetBody, const u_char *startOfPacket, DNS_t *dns){
    if(packetBody == NULL || startOfPacket == NULL){
        return 0;
    }
    dns->authorities = (ResourceRecord *)malloc(sizeof(ResourceRecord));

    if(dns->authorities == NULL){
        return 0;
    }
    const u_char *currentPtr = packetBody;

    fprintf(stdout, "The number of Authoritive records are %u",numberOfAuthoritive);

    for(int i = 0 ; i < numberOfAuthoritive; i++){
        currentPtr = parseDomainName(currentPtr, startOfPacket, &dns->authorities[i].name);
        if (currentPtr == NULL) {
            for(int j = 0 ; j < i; j++){
                free(dns->authorities[i].name);
                if(dns->authorities[i].rdata){
                    free(dns->authorities[i].rdata);
                }
            }
        }

        dns->authorities[i].type = ntohs(*(uint16_t *) currentPtr);
        currentPtr += 2;
        dns->authorities[i].class_ = ntohs(*(uint16_t *) currentPtr);
        currentPtr += 2;
        dns->authorities[i].ttl = ntohs(*(uint32_t *) currentPtr);
        currentPtr += 4;
        dns->authorities[i].rdlength = ntohs(*(uint16_t *) currentPtr);
        currentPtr += 2;
        printf("  Domain: %s\n", dns->authorities[i].name);
        printf("  Type: %u\n", dns->authorities[i].type);
        printf("  Class: %u\n", dns->authorities[i].class_);
        printf("  ttl: %u\n", dns->authorities[i].ttl);
        printf("  Length : %u\n", dns->authorities[i].rdlength);
    }

    return currentPtr;

}
const u_char *parseDNSAnswers(uint16_t numberOfAnswers, const u_char *packetBody,
                             const u_char *startOfPacket, DNS_t *dns) {
    if (numberOfAnswers == 0) {
        return packetBody;
    }

    dns->answers = (ResourceRecord *)calloc(numberOfAnswers, sizeof(ResourceRecord));
    if (dns->answers == NULL) {
        perror("Error allocating memory for answers");
        return NULL;
    }

    printf("Number of answers: %u\n", numberOfAnswers);
    const u_char *currentPtr = packetBody;

    for (int i = 0; i < numberOfAnswers; i++) {
        // Parse the domain name this record refers to
        currentPtr = parseDomainName(currentPtr, startOfPacket, &dns->answers[i].name);
        if (currentPtr == NULL) {
            // Clean up already allocated resources
            for (int j = 0; j < i; j++) {
                free(dns->answers[j].name);
                if (dns->answers[j].rdata) {
                    free(dns->answers[j].rdata);
                }
            }
            free(dns->answers);
            dns->answers = NULL;
            return NULL;
        }

        // Parse record type and class
        dns->answers[i].type = ntohs(*(uint16_t *)currentPtr);
        currentPtr += 2;
        dns->answers[i].class_ = ntohs(*(uint16_t *)currentPtr);
        currentPtr += 2;

        // Parse TTL and data length
        dns->answers[i].ttl = ntohl(*(uint32_t *)currentPtr);
        currentPtr += 4;
        dns->answers[i].rdlength = ntohs(*(uint16_t *)currentPtr);
        currentPtr += 2;

        // Log the answer header information
        printf("Answer #%d:\n", i+1);
        printf("  Name: %s\n", dns->answers[i].name);
        printf("  Type: %s (%u)\n", getRecordTypeName(dns->answers[i].type), dns->answers[i].type);
        printf("  Class: %u\n", dns->answers[i].class_);
        printf("  TTL: %u seconds\n", dns->answers[i].ttl);
        printf("  Data length: %u bytes\n", dns->answers[i].rdlength);

        // Process the data based on record type
        switch (dns->answers[i].type) {
            case 1: { // A record (IPv4 address)
                struct in_addr addr;
                memcpy(&addr.s_addr, currentPtr, 4);
                dns->answers[i].rdata = (unsigned char *)malloc(INET_ADDRSTRLEN);
                if (dns->answers[i].rdata == NULL) {
                    perror("Error allocating memory for A record");
                    goto cleanup;
                }
                inet_ntop(AF_INET, &addr, (char *)dns->answers[i].rdata, INET_ADDRSTRLEN);
                printf("  IPv4: %s\n", (char *)dns->answers[i].rdata);
                currentPtr += 4;
                break;
            }

            case 5: { // CNAME record
                unsigned char *cname;
                const u_char *next = parseDomainName(currentPtr, startOfPacket, &cname);
                if (next == NULL) {
                    perror("Error parsing CNAME record");
                    goto cleanup;
                }

                dns->answers[i].rdata = cname;
                printf("  CNAME: %s\n", (char *)cname);
                currentPtr = next;
                break;
            }

            case 28: { // AAAA record (IPv6 address)
                struct in6_addr addr6;
                memcpy(&addr6, currentPtr, 16);
                dns->answers[i].rdata = (unsigned char *)malloc(INET6_ADDRSTRLEN);
                if (dns->answers[i].rdata == NULL) {
                    perror("Error allocating memory for AAAA record");
                    goto cleanup;
                }
                inet_ntop(AF_INET6, &addr6, (char *)dns->answers[i].rdata, INET6_ADDRSTRLEN);
                printf("  IPv6: %s\n", (char *)dns->answers[i].rdata);
                currentPtr += 16;
                break;
            }

            default: {
                // For other record types, just store the binary data
                dns->answers[i].rdata = (unsigned char *)malloc(dns->answers[i].rdlength);
                if (dns->answers[i].rdata == NULL) {
                    perror("Error allocating memory for record data");
                    goto cleanup;
                }
                memcpy(dns->answers[i].rdata, currentPtr, dns->answers[i].rdlength);
                printf("  Data: [%u bytes of binary data]\n", dns->answers[i].rdlength);
                currentPtr += dns->answers[i].rdlength;
            }
        }

        continue;

    cleanup:
        // Clean up on error
        for (int j = 0; j <= i; j++) {
            free(dns->answers[j].name);
            if (j < i && dns->answers[j].rdata) {
                free(dns->answers[j].rdata);
            }
        }
        free(dns->answers);
        dns->answers = NULL;
        return NULL;
    }

    return currentPtr;
}



int parseDNSPacket(const u_char *packetData) {
    // if (length < sizeof(HeaderDNS_t)) {
    //     fprintf(stderr, "Packet too short for DNS header\n");
    //     return -1;
    // }

    DNS_t dns = {NULL};
    dns.header = (HeaderDNS_t *)packetData;
    const u_char *startOfPacket = packetData;
    const u_char *currentPtr = packetData + sizeof(HeaderDNS_t);

    printf("DNS Header:\n");
    printf("  ID: 0x%04x\n", ntohs(dns.header->id));
    printf("  Flags: 0x%04x ", ntohs(dns.header->flags));
    printBits(&dns.header->flags, sizeof(dns.header->flags), 15, 0);

    uint16_t flags = ntohs(dns.header->flags);
    printf("    QR: %s\n", (flags & 0x8000) ? "Response" : "Query");
    printf("    Opcode: %d\n", (flags >> 11) & 0xF);
    printf("    AA: %s\n", (flags & 0x0400) ? "Yes" : "No");
    printf("    TC: %s\n", (flags & 0x0200) ? "Yes" : "No");
    printf("    RD: %s\n", (flags & 0x0100) ? "Yes" : "No");
    printf("    RA: %s\n", (flags & 0x0080) ? "Yes" : "No");
    printf("    Z: %d\n", (flags >> 4) & 0x7);
    printf("    RCODE: %d\n", flags & 0xF);

    printf("  Questions: %u\n", ntohs(dns.header->qdcount));
    printf("  Answer RRs: %u\n", ntohs(dns.header->ancount));
    printf("  Authority RRs: %u\n", ntohs(dns.header->nscount));
    printf("  Additional RRs: %u\n", ntohs(dns.header->arcount));

    // Parse questions
    if (ntohs(dns.header->qdcount) > 0) {
        currentPtr = parseDNSQuestions(ntohs(dns.header->qdcount), currentPtr, startOfPacket, &dns);
        if (currentPtr == NULL) {
            fprintf(stderr, "Error parsing DNS questions\n");
            return -1;
        }
    }

    // Parse answers
    if (ntohs(dns.header->ancount) > 0) {
        currentPtr = parseDNSAnswers(ntohs(dns.header->ancount), currentPtr, startOfPacket, &dns);
        if (currentPtr == NULL) {
            fprintf(stderr, "Error parsing DNS answers\n");
            // Clean up questions
            for (int i = 0; i < ntohs(dns.header->arcount); i++) {
                free(dns.answers[i].name);
            }
            free(dns.answers);
            return -1;
        }
    }

    // Parse Authority
    if (ntohs(dns.header->nscount) > 0) {
        currentPtr = parseDNSAuthoritative(ntohs(dns.header->nscount), currentPtr, startOfPacket, &dns);
        if (currentPtr == NULL) {
            fprintf(stderr, "Error parsing DNS answers\n");
            // Clean up questions
            for (int i = 0; i < ntohs(dns.header->nscount); i++) {
                free(dns.authorities[i].name);
                if(dns.authorities[i].rdata){
                    free(dns.authorities[i].rdata);
                }
            }
            free(dns.authorities);
            return -1;
        }
    }

    // Clean up allocated resources
    if (dns.questions) {
        for (int i = 0; i < ntohs(dns.header->qdcount); i++) {
            free(dns.questions[i].qname);
        }
        free(dns.questions);
    }

    if (dns.answers) {
        for (int i = 0; i < ntohs(dns.header->ancount); i++) {
            free(dns.answers[i].name);
            if (dns.answers[i].rdata) {
                free(dns.answers[i].rdata);
            }
        }
        free(dns.answers);
    }

    if (dns.authorities) {
        for (int i = 0; i < ntohs(dns.header->arcount); i++) {
            free(dns.authorities[i].name);
            if (dns.authorities[i].rdata) {
                free(dns.answers[i].rdata);
            }
        }
        free(dns.authorities);
    }
    return 0;
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

    if (ntohs(udp->srcPort) == 53 || ntohs(udp->destPort) == 53) {
        fprintf(stdout, "This is a DNS packet: \n");
        parseDNSPacket(packetBody);
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
    int ipHeaderLen = ((*packetBody) & MASK_LAST_FOUR_BITS);
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
            (parser->versionAndIhl & MASK_LAST_FOUR_BITS), (parser->versionAndIhl & MASK_LAST_FOUR_BITS) * 4);

    printBits(&parser->versionAndIhl, sizeof(parser->versionAndIhl), 3, 2);
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
        printARPHeader(packetBody);
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
    const u_char *packet = NULL;
    struct pcap_pkthdr packetHeader = {.caplen = 0, .len = 0, .ts = {.tv_sec = 0, .tv_usec = 0}};
    int packetCountLimit = 2000;
    int packetTimeOut = 900; // In milliseconds

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
