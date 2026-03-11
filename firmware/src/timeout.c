/**
 * @file "timeout.c"
 * @author Jeremy Goldberger
 * @brief Lockout file
 * @date 2026
 */

#include "timeout.h"
#include "timer.h"
#include "simple_flash.h"

/**
 * @brief Times out the user for `time` millseconds, and sets a persistent flag.
 *        This function is synchronous and will busy wait for the duration of
 *        the timeout.
 * @param time Time to timeout, in millseconds
 */
void timeout(int time) {
    reset_timer();
    while (get_timer_ms() < time) {
        // TODO jitter to avoid skipping the jump.
    }
}