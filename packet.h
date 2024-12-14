#ifndef PACKET_H
#define PACKET_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

enum packet_protocol {
    TCP,
    UDP
};

struct packet_header {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_pt;
    uint16_t dst_pt;
    uint16_t len;
    uint8_t prot;
};

enum packet_op {
    DROP,
    ACCEPT
};

typedef struct n {
    struct packet_header data;
    struct n* next;
} node_t;

typedef struct ll {
    int list_size;
    node_t* head;
} linked_list_t;



#endif