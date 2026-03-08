/**
 * @file "timeout.h"
 * @author Jeremy Goldberger
 * @brief Lockout header
 * @date 2026
 */


#ifndef __TIMEOUT_H__
#define __TIMEOUT_H__

#include <stdbool.h>

#define PIN_TIMEOUT 4000

void timeout(int time);
bool is_timed_out();

#endif //__TIMEOUT_H__