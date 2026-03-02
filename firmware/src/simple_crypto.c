/**
 * @file "simple_crypto.c"
 * @author Ben Janis
 * @brief Simplified Crypto API Implementation
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */


#include "simple_crypto.h"
#include "security.h"
#include <stdint.h>
#include <string.h>
#include "hardware_crypto.h"



/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts plaintext using a symmetric cipher
 *
 * @param plaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param len The length of the plaintext to encrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE containing
 *          the key to use for encryption
 * @param iv A pointer to a buffer of length IV_SIZE containing
 *          the iv to use for encryption
 * @param ciphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t* iv, uint8_t *ciphertext) {
    Aes aes; // Context for encryption
    int ret; // Library result
    uint8_t auth_tag[AES_AUTH_TAG_SIZE];

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    ret = wc_AesInit(&aes, NULL, HARDWARE_CRYPTO_DEVICE_ID);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ret;
    }
    // Set the key for encryption
    ret = wc_AesGcmSetKey(&aes, key, KEY_SIZE);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ret;
    }

    ret = wc_AesGcmEncrypt(
        &aes,
        ciphertext,
        plaintext,  len,
        iv,         IV_SIZE,
        auth_tag,   AES_AUTH_TAG_SIZE,
        NULL,       0
    );
    wc_AesFree(&aes);
    if (ret != 0)
        return ret;
    return 0;
}

/** @brief Decrypts ciphertext using a symmetric cipher
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *          ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for decryption
 * @param iv A pointer to a buffer of length IV_SIZE containing
 *          the iv to use for encryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *          plaintext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t* iv, uint8_t *plaintext) {
    Aes aes; // Context for encryption
    int ret; // Library result
    uint8_t auth_tag[AES_AUTH_TAG_SIZE];

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    ret = wc_AesInit(&aes, NULL, HARDWARE_CRYPTO_DEVICE_ID);
    if (ret != 0) {
        return ret;
        wc_AesFree(&aes);
    }
    // Set the key for encryption
    ret = wc_AesGcmSetKey(&aes, key, KEY_SIZE);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ret;
    }

    ret = wc_AesGcmDecrypt(
        &aes,
        plaintext,
        ciphertext,  len,
        iv,         IV_SIZE,
        auth_tag,   AES_AUTH_TAG_SIZE,
        NULL,       0
    );
    wc_AesFree(&aes);
    if (ret != 0)
        return ret;
    return 0;
}

/** @brief Hashes arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 *          to be hashed
 * @param len The length of the plaintext to hash
 * @param hash_out A pointer to a buffer of length HASH_SIZE (16 bytes) where the resulting
 *          hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int hash(void *data, size_t len, uint8_t *hash_out) {
    // Pass values to hash
    return wc_Md5Hash((uint8_t *)data, len, hash_out);
}
