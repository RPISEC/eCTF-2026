#include "memory_tools.h"
#include <stdint.h>

extern uint32_t __stack_guard_start;
extern uint32_t __stack_guard_end;

void init_stack_guard(void) {
    for (uint32_t *p = &__stack_guard_start; p < &__stack_guard_end; ++p) {
        *p = 0xDEADBEEF;
    }
}

bool stack_overflow_detected(void) {
    for (uint32_t *p = &__stack_guard_start; p < &__stack_guard_end; ++p) {
        if (*p != 0xDEADBEEF)
            return true;
    }
    return false;
}
