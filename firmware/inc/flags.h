// flags.c

#ifndef __FLAGS_H__
#define __FLAGS_H__

#include "stdint.h"

typedef enum {
    FLAG_LOCKOUT
} flag_t;

int flag_set(flag_t flag, uint32_t value);

uint32_t flag_get(flag_t flag);

#endif // __FLAGS_H__