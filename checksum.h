#ifndef __CHECKSUM_H__
#define __CHECKSUM_H__

#include <linux/types.h>

struct __attribute__((packed)) tcp_pseudohdr_t {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_header_len;
};

uint16_t tcp_checksum(uint8_t *buffer, uint32_t len);
void tcp_build_pseudoheader(struct iphdr* ip_header, uint16_t tcp_payload_len, struct tcp_pseudohdr_t* pseudo_hdr);

#endif
