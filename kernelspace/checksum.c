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
#include "checksum.h"

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
 * Populates the pseudo_header pointer passed as argument with a 
 * 12-byte buffer representing the TCP pseudo-header.
 * The pseudo-header is structured as follows when using IPv4:
 * - Source Address (4 bytes)
 * - Destination Address (4 bytes)
 * - Reserved for the future (all 0s, 1 byte)
 * - Protocol field from the IP header
 * - TCP lenght, including TCP header and payload (not including TCP pseudo header). This
 * - field is not part of the TCP header, therefore must be calculated
 */

void
tcp_build_pseudoheader(struct iphdr* ip_header, uint16_t tcp_len, struct tcp_pseudohdr_t *pseudo_hdr )
{
    if(!pseudo_hdr)
        return;
    
    pseudo_hdr->saddr = ip_header->saddr;
    pseudo_hdr->daddr = ip_header->daddr;
    pseudo_hdr->reserved = 0x00;
    pseudo_hdr->protocol = ip_header->protocol;
    pseudo_hdr->tcp_header_len = htons(tcp_len); /* Lenght in big endian */
}
