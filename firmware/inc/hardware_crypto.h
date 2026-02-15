#ifndef _HARDWARE_CRYPTO_H_
#define _HARDWARE_CRYPTO_H_

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

// HARDWARE_CRYPTO_DEVICE_ID can be any unique positive integer, but must be used consistently in wolfcrypt init functions
#define HARDWARE_CRYPTO_DEVICE_ID 1  

// size in bytes
# define AES_AUTH_TAG_SIZE 16

int init_hardware_crypto(void);
int callbackHardwareCrypto(int devId, wc_CryptoInfo* info, void* ctx);

#endif // _HARDWARE_CRYPTO_H_