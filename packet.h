#ifndef PACKET_H
#define PACKET_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

struct ip_header {
    uint8_t     ihl_version;
    uint8_t     tos;
    uint16_t	tot_len;
    uint16_t	id;
    uint16_t	frag_off;
    uint8_t     ttl;
    uint8_t     protocol;
    uint16_t	check;
    uint32_t	saddr;
    uint32_t	daddr;
};

#endif