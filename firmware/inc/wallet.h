#ifndef __WALLET_H__
#define __WALLET_H__
#include <stdbool.h>
#include <stdint.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#define PERM_R 0x01
#define PERM_W 0x02
#define PERM_C 0x04

typedef uint8_t key32_t[32];
typedef uint8_t key33_t[33];

WARN_UNUSED_RESULT int wallet_unlock(const unsigned char *pin);
void wallet_lock(void);

bool wallet_has_perms(uint16_t group_id, uint8_t perms);
bool check_pin(const unsigned char *pin);


WARN_UNUSED_RESULT int get_k_storage(key32_t *key, uint16_t group_id);
WARN_UNUSED_RESULT int get_w_priv(key32_t *key, uint16_t group_id);
WARN_UNUSED_RESULT int get_c_priv(key32_t *key, uint16_t group_id);
WARN_UNUSED_RESULT int get_w_pub(key33_t *key, uint16_t group_id);
WARN_UNUSED_RESULT int get_c_pub(key33_t *key, uint16_t group_id);

#endif // __WALLET_H__
