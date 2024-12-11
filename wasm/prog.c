#include <stdint.h>

#include "prog.h"

/*
 * Called by the runtime to handle an incoming IPv4 packet.
 */
uint32_t
filter(void)
{
    return header->prot == TCP && header->dst_pt == 80 ? DROP : ACCEPT;
}