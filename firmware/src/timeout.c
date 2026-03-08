/**
 * @file "timeout.c"
 * @author Jeremy Goldberger
 * @brief Lockout file
 * @date 2026
 */

#include "timeout.h"
#include "timer.h"
#include "simple_flash.h"

#define PERSISTENT_TIMEOUT_FLAG_ADDR 0xdeadbeef
 
static const char DIRTY_BIT = 0x00;
static const char CLEAN_BIT = 0x01;

/**
 * @brief Times out the user for `time` millseconds, and sets a persistent flag.
 *        This function is synchronous and will busy wait for the duration of
 *        the timeout.
 * @param time Time to timeout, in millseconds
 */
void timeout(int time) {
    reset_timer();
    // Set dirty bit
    int res = flash_simple_write(PERSISTENT_TIMEOUT_FLAG_ADDR, &DIRTY_BIT, 1);
    if (res != 0) {
        // Handle debug info
    }
    while (get_timer_ms() < time) {
        // TODO jitter to avoid skipping the jump.
    }
    // Unset dirty bit
    int res = flash_simple_write(PERSISTENT_TIMEOUT_FLAG_ADDR, &DIRTY_BIT, 1);
    if (res != 0) {
        // Handle debug info
    }
}

/**
 * @brief Checks if the persistent timeout bit is set.
 */
bool is_timed_out() {
    char timeout_flag = 0;
    flash_simple_read(PERSISTENT_TIMEOUT_FLAG_ADDR, &timeout_flag, 1);
    return timeout_flag != CLEAN_BIT;
}