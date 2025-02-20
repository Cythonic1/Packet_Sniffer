#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

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

typedef struct TCPHeader{
    uint16_t srcPort;
    uint16_t destPort;
    uint32_t sequenceNumber;
    uint32_t ackNumber;
    uint16_t doRsvFlags;
    uint16_t window;
    uint16_t checkSum;
    uint16_t urgentPointer;

} TCPHeader_t;

typedef struct UDPHeader{
    uint16_t srcPort;
    uint16_t destPort;
    uint16_t length;
    uint16_t checkSum;
} UDPHeader_t;

typedef struct ARP {
    uint16_t HardwareType;              
    uint16_t ProtocolType;              
    uint8_t HardwareAddressLength;      
    uint8_t ProtocolAddressLength;      
    uint16_t Operation;                 
    uint8_t SenderHardwareAddress[6];   
    uint8_t SenderProtocolAddress[4];   
    uint8_t TargetHardwareAddress[6];   
    uint8_t TargetProtocolAddress[4];   
} ARP_t;


typedef struct DHCP{
    uint8_t op; // Operation code 
    uint8_t htype; // hardware type
    uint8_t hlen; // Hardware address length
    uint8_t htop; // The number of hops to travel before drop the packet
    /*Transaction ID, a random number chosen by the*/
    /*client, used by the client and server to associate*/
    /*messages and responses between a client and a*/
    /*server*/
    uint32_t xid;
    /*Filled in by client, seconds elapsed since client*/
    /*began address acquisition or renewal process*/
    uint16_t secs;
    /* we only care about the first bit in the flag header the rest are zeros check RFC 2131 */
    uint16_t flags;
    /*Client IP address; only filled in if client is in BOUND, RENEW or REBINDING state and can respond to ARP requests*/
    uint32_t ciaddr;
    /* Your IP address :) */
    uint32_t yiaddr;
    /*IP address of next server to use in bootstrap; returned in DHCPOFFER, DHCPACK by server.*/
    uint32_t siaddr;
    /*Relay agent IP address, used in booting via a relay agent.*/
    uint32_t giaddr;
    /* client Hardware Address */
    uint8_t macAddress[6];
    uint8_t padding[6];
    /*host name (Optional) */
    char sname[64];
    /* Boot File name */
    char file[128];

    // Decode the option header
    /*
     * To do so you need to find fisrt the magic bytes which they are 99, 130, 83 and 99 (accoring to RFC 2131) 
     * after you find it the first byte tell us the number of the option and depdnece on that
     * we can tell which option we deal with and we can decode it based on its know length or we can use the second byte to find t     * length of the option.
     * */
}DHCP_t;



typedef struct HeaderDNS {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
}HeaderDNS_t;

typedef struct QuestionDNS {
    // Find a way to get the len before parsing
    unsigned char* qname;
    uint16_t qtype;
    uint16_t qclass;

}QuestionDNS;

/* This reprsent the answer, authority, and additional headers
    as they all share the same headers */

typedef struct ResourceRecord {
    unsigned char *name;
    uint16_t type;
    uint16_t class_;
    uint32_t ttl;
    uint16_t rdlength;
    unsigned char *rdata;
}ResourceRecord;

typedef struct DNS {
    HeaderDNS_t *header;
    QuestionDNS *questions;    
    ResourceRecord *answers;   
    ResourceRecord *authorities; 
    ResourceRecord *additionals; 
} DNS_t;
