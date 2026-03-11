#include "flags.h"
#include "simple_flash.h"
#include "host_messaging.h"

extern uint32_t __FLASH_FLAGS_START[];

int flag_set(flag_t flag, uint32_t value) {
    print_debug("setting flag...");
    return flash_simple_write((uint32_t)(__FLASH_FLAGS_START + flag), &value, 1);
}

uint32_t flag_get(flag_t flag) {
    print_debug("getting flag...");
    uint32_t ret;
    flash_simple_read((uint32_t)(__FLASH_FLAGS_START + flag), &ret, 1);
    print_debug("got flag!");
    return ret;
}