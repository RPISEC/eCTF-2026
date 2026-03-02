#ifndef __HARDWARE_CRYPTO_H__
#define __HARDWARE_CRYPTO_H__

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

// HARDWARE_CRYPTO_DEVICE_ID can be any unique positive integer, but must be used consistently in wolfcrypt init functions
#define HARDWARE_CRYPTO_DEVICE_ID 1

// size in bytes
#define AES_AUTH_TAG_SIZE 16
#define KEY_SIZE 32
#define IV_SIZE 12

int init_hardware_crypto(void);
int callbackHardwareCrypto(int devId, wc_CryptoInfo* info, void* ctx);

#endif // __HARDWARE_CRYPTO_H__
