#ifndef __USER_SETTINGS_H__
#define __USER_SETTINGS_H__

// tells wolfssl that we will handle RNG on the baremetal target
#define NO_DEV_RANDOM
#define WC_NO_DEFAULT_DEVID
#define WOLFSSL_SMALL_STACK
// we only need the wolfcrypt library, not all of wolfssl
#define WOLFCRYPT_ONLY

// callback settings for hardware integration
#define WOLF_CRYPTO_CB
// one for the trng and one for the hardware crypto accelerator
#define MAX_CRYPTO_DEVID_CALLBACKS 2

// crypto algorithms
#define HAVE_AESGCM

// timing resistance settings
#define TFM_TIMING_RESISTANT
#define WC_RSA_BLINDING
#define ECC_TIMING_RESISTANT

#endif // __USER_SETTINGS_H__