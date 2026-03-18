#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/pwdbased.h>

#include "secrets.h"
#include "wallet.h"
#include "macros.h"
#include "simple_crypto.h"

typedef uint8_t key32_t[32];

// clear wallet
typedef struct __attribute__((packed)) {
    uint16_t group_id[MAX_NUM_GROUPS];
    uint8_t perms[MAX_NUM_GROUPS];

    key32_t w_pub[MAX_NUM_GROUPS];
    key32_t c_pub[MAX_NUM_GROUPS];
} clear_wallet_t;

// private wallet
typedef struct __attribute__((packed)) {
    key32_t k_storage[MAX_NUM_GROUPS]; // only if R or W else all-zero
    key32_t w_priv[MAX_NUM_GROUPS];    // only if W else all-zero
    key32_t c_priv[MAX_NUM_GROUPS];    // only if C else all-zero
} keystore_t;

// whole wallet on flash
typedef struct __attribute__((packed)) {
    clear_wallet_t clear;

    uint8_t pin_salt[16];
    uint8_t wallet_iv[12];
    uint8_t wallet_ct[sizeof(keystore_t)];
    uint8_t wallet_tag[16];
} wallet_flash_t;

static wallet_flash_t *wallet = (wallet_flash_t *)&wallet_flash;

static keystore_t keystore;
static bool is_locked = true;

/* For a given group id, find its wallet index. */
static int8_t get_group_index(uint16_t group_id) {
    for (int i = 0; i < PROVISIONED_NUM_GROUPS; i++) {
        if (group_id == wallet->clear.group_id[i]) {
            return i;
        }
    }

    /* Group not found, return error. */
    return -1;
}

/* Pin is encoded as 6 hex digit chars.
 * Returns 0 on success. */
WARN_UNUSED_RESULT int wallet_unlock(const unsigned char *pin) {
    static key32_t pin_key; // Safer in global memory
    int ret;

    ret = wc_PBKDF2(pin_key, pin, 6, wallet->pin_salt, PIN_SALT_LEN,
                    WALLET_ITERS, sizeof(key32_t), WC_HASH_TYPE_SHA256);
    JITTER;
    if (ret != 0) {
        return -1;
    }

    ret = decrypt_sym(wallet->wallet_ct, KS_CT_LEN, pin_key, wallet->wallet_iv,
                      wallet->wallet_tag, (uint8_t *)&(wallet->clear),
                      CLEAR_STORAGE_LEN, (uint8_t *)&keystore);
    if (ret != 0) {
        return -2;
    }

    is_locked = false;

    memset(pin_key, 0, sizeof(key32_t));
    return 0;
}

void wallet_lock(void) {
    memset(&keystore, 0, sizeof(keystore_t));

    is_locked = true;
}

/* Checks if given group has ANY of the specified perms. */
bool wallet_has_perms(uint16_t group_id, uint8_t perms) {
    int index = get_group_index(group_id);

    if (index < 0 || index >= MAX_NUM_GROUPS)
        return false; // Group does not exist

    uint8_t group_perms = wallet->clear.perms[index];
    return !!(group_perms & perms);
}

/* Pin must point to a 6-byte buffer. Returns true for correct pin, false
 * otherwise*/
bool check_pin(const unsigned char *pin) {
    int chk = wallet_unlock(pin);
    if (chk != 0) {
        return false;
    }

    wallet_lock();
    return true;
};

/* Returns 0 on success. */
WARN_UNUSED_RESULT int get_k_storage(key32_t *key, uint16_t group_id) {
    if (is_locked)
        return -1;

    int index = get_group_index(group_id);
    if (index < 0 || index >= MAX_NUM_GROUPS)
        return -2;

    if (!wallet_has_perms(group_id, PERM_R | PERM_W))
        return -3;

    memcpy(key, keystore.k_storage[index], sizeof(key32_t));

    return 0;
}

/* Returns 0 on success. */
WARN_UNUSED_RESULT int get_c_priv(key32_t *key, uint16_t group_id) {
    if (is_locked)
        return -1;

    int index = get_group_index(group_id);
    if (index < 0 || index >= MAX_NUM_GROUPS)
        return -2;

    if (!wallet_has_perms(group_id, PERM_C))
        return -3;

    memcpy(key, keystore.c_priv[index], sizeof(key32_t));

    return 0;
}

/* Returns 0 on success. */
WARN_UNUSED_RESULT int get_w_priv(key32_t *key, uint16_t group_id) {
    if (is_locked)
        return -1;

    int index = get_group_index(group_id);
    if (index < 0 || index >= MAX_NUM_GROUPS)
        return -2;

    if (!wallet_has_perms(group_id, PERM_W))
        return -3;

    memcpy(key, keystore.w_priv[index], sizeof(key32_t));

    return 0;
}

/* Returns 0 on success. */
WARN_UNUSED_RESULT int get_w_pub(key32_t *key, uint16_t group_id) {
    int index = get_group_index(group_id);
    if (index < 0 || index >= MAX_NUM_GROUPS)
        return -2;

    memcpy(key, wallet->clear.w_pub[index], sizeof(key32_t));

    return 0;
}

/* Returns 0 on success. */
WARN_UNUSED_RESULT int get_c_pub(key32_t *key, uint16_t group_id) {
    int index = get_group_index(group_id);
    if (index < 0 || index >= MAX_NUM_GROUPS)
        return -2;

    memcpy(key, wallet->clear.c_pub[index], sizeof(key32_t));

    return 0;
}
