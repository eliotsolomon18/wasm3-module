#include <stdint.h>

int32_t print_int(int32_t i) __attribute__((
    __import_module__("custom"),
    __import_name__("print_int")
));

int32_t
two()
{
    print_int(3);
    return (2);
}