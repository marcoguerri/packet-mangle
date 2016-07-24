#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/kernel.h>
#else
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#endif

#include <linux/tcp.h>
#include <linux/ip.h>

#define TCP_PHDR_LEN     12

#define TCP_PHDR_SADDR_OFF 0
#define TCP_PHDR_SADDR_LEN 4
#define TCP_PHDR_DADDR_OFF 4
#define TCP_PHDR_DADDR_LEN 4
#define TCP_PHDR_RES_OFF 8
#define TCP_PHDR_RES_LEN 1
#define TCP_PHDR_PROTO_OFF 9
#define TCP_PHDR_PROTO_LEN 1
#define TCP_PHDR_LEN_OFF 10
#define TCP_PHDR_LEN_LEN 2

uint16_t 
tcp_checksum(uint8_t *buffer, uint32_t len)
{
    uint32_t checksum = 0x00000000;
    uint16_t *word_ptr  = (uint16_t*)buffer;

    while(len > 1)
    {
        /* 
         * 2 bytes chunks should be summed up as big endian integers.
         * This code will not work on big endian architectures, htons will do nothing
         */
        checksum += htons(*word_ptr);
        word_ptr++;
        len -= 2;
    }
    
    /*
     * If the lenght is not a multiple of 2 (normally 2 is 2,
     * therefore this means the lenght is odd), add some padding to the remainder 
     * and add it to the checksum.
     */
    
    if(len > 0)
    {
        /* One missing byte, padding on the right and adding */
        checksum += (*((uint8_t*)word_ptr) << 8);
    }

     /* Performs one's complement sum: if there is carry, sum it back with 
     * the checksum */ 
    
    if(checksum & 0xFFFF0000)
        checksum  += checksum >> 16;
  
    return ~(uint16_t)(checksum & 0x0000FFFF);

}

/**
 * Populates the pseudo_header pointer passed as argument with a 12-byte buffer representing the TCP pseudo-header.
 * The pseudo-header is structured as follows when using IPv4:
 * - Source Address (4 bytes)
 * - Destination Address (4 bytes)
 * - Reserved for the future (all 0s, 1 byte)
 * - Protocol field from the IP header
 * - TCP lenght, including TCP header and payload (not including TCP pseudo header). This
 * - field is not part of the TCP header, therefore must be computed
 */

uint8_t
tcp_build_pseudoheader(struct iphdr* ip_header, uint16_t tcp_len, uint8_t* pseudo_header)
{

    if(!pseudo_header)
        return -1;

    uint16_t l = htons(tcp_len);
    memcpy(pseudo_header + TCP_PHDR_SADDR_OFF, &ip_header->saddr, TCP_PHDR_SADDR_LEN);
    memcpy(pseudo_header + TCP_PHDR_DADDR_OFF, &ip_header->daddr, TCP_PHDR_DADDR_LEN);
    memset(pseudo_header + TCP_PHDR_RES_OFF, 0, TCP_PHDR_RES_LEN);
    memcpy(pseudo_header + TCP_PHDR_PROTO_OFF, &ip_header->protocol, TCP_PHDR_PROTO_LEN);
    /* PAY ATTENTION to endianness! */
    memcpy(pseudo_header + TCP_PHDR_LEN_OFF, &l, TCP_PHDR_LEN_LEN);

    return 0;
}


/*
int main()
{
    struct iphdr ip;
    struct icmphdr* icmp;
    
    char *dst_addr = "192.168.0.1";
    char *src_addr = "192.168.0.2";
    
    ip.protocol    = 16;

    ip.saddr       = inet_addr(src_addr);
    ip.daddr       = inet_addr(dst_addr);

    uint8_t tcp_payload[] = { 0x45, 0x00, 0x00, 0x30, 0x44, 0x22, 0x40, 0x00, 0x80, 0x06, 
                              0x00, 0x00, 0x8c, 0x7c, 0x19, 0xac, 0xae, 0x24, 0x1e, 0x2b, 
                              0x22};


    uint16_t checksum = tcp_checksum(buffer, 21);
    printf("Checksum is %x\n", checksum);
    
    uint8_t* tcp_pseudoheader = tcp_build_pseudoheader(&ip, 55);

    uint8_t* buffer = (uint8_t*

}
*/





