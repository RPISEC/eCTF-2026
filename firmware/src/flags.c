#include "flags.h"
#include "simple_flash.h"
#include "host_messaging.h"

extern uint64_t __FLASH_FLAGS_START[];

int flag_set(flag_t flag, uint64_t value) {
    print_debug("setting flag...");
    return flash_simple_write((uint64_t)(__FLASH_FLAGS_START + flag * 2), &value, sizeof(uint64_t));
}

uint64_t flag_get(flag_t flag) {
    print_debug("getting flag...");
    uint64_t ret;
    flash_simple_read((uint64_t)(__FLASH_FLAGS_START + flag * 2), &ret, sizeof(uint64_t));
    print_debug("got flag!");
    return ret;
}