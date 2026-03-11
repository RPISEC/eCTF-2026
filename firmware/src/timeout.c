/**
 * @file "timeout.c"
 * @author Jeremy Goldberger
 * @brief Lockout file
 * @date 2026
 */

#include "timeout.h"
#include "timer.h"
#include "flags.h"
#include "simple_flash.h"

#define PERSISTENT_TIMEOUT_FLAG_ADDR __attribute__((section(".persistent_flags")))
 
static const char DIRTY_BIT = 0x01;
static const char CLEAN_BIT = 0x00;

/**
 * @brief Times out the user for `time` millseconds, and sets a persistent flag.
 *        This function is synchronous and will busy wait for the duration of
 *        the timeout.
 * @param time Time to timeout, in millseconds
 */
void timeout(int time) {
    timer_reset();
    flag_set(FLAG_LOCKOUT, DIRTY_BIT);
    while (timer_get_ms() < time) {
        // TODO jitter to avoid skipping the jump.
    }
    flag_set(FLAG_LOCKOUT, CLEAN_BIT);
}

/**
 * @brief Checks if the persistent timeout bit is set.
 */
bool is_timed_out() {
    return flag_get(FLAG_LOCKOUT) == CLEAN_BIT;
}