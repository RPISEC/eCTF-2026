/**
 * @file "timeout.h"
 * @author Jeremy Goldberger
 * @brief Lockout header
 * @date 2026
 */


#ifndef __TIMEOUT_H__
#define __TIMEOUT_H__

#include <stdbool.h>

#define TIMEOUT_PIN 4000
#define TIMEOUT_BOOT 900

void timeout(int time);

#endif //__TIMEOUT_H__
