#ifndef __CHECKSUM_H__
#define __CHECKSUM_H__

uint16_t tcp_checksum(uint8_t *buffer, uint32_t len);
uint8_t* tcp_build_pseudoheader(struct iphdr* ip_header, uint16_t tcp_payload_len, uint8_t* pseudo_header);

#endif
