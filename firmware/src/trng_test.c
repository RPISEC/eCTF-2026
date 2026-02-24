#include "host_messaging.h"
#include <wolfssl/wolfcrypt/random.h>

void test_trng_callback(void) {
    WC_RNG rng;
    byte buf[512];

    wc_InitRng(&rng);
    wc_RNG_GenerateBlock(&rng, buf, sizeof(buf));
    wc_FreeRng(&rng);

    print_debug("the following bytes should be random:");
    print_hex_debug(buf, sizeof(buf));
}
