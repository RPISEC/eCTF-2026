#ifndef __SIMPLE_TRNG__
#define __SIMPLE_TRNG__

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <ti/devices/msp/msp.h>
#include <ti/driverlib/dl_trng.h>

bool trng_init(void);
uint32_t trng_get_u32(void);
void trng_shutdown(void);

#endif // __SIMPLE_TRNG__

