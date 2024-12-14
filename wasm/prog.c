#include <stdint.h>

#include "prog.h"

/*
 * Called by the runtime to handle an incoming IPv4 packet.
 */
uint32_t
filter(void)
{
    return packet_list->head->data.prot == TCP && packet_list->head->data.dst_pt == 80 ? DROP : ACCEPT;
}