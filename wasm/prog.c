#include <stdint.h>

#include "prog.h"

/*
 * Called by the runtime to handle an incoming IPv4 packet.
 */
uint32_t
filter(void)
{
    print_int(header->protocol);

    header->ttl--;

    return 1;
}