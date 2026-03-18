/**
 * @file "simple_crypto.h"
 * @author Ben Janis
 * @brief Simplified Crypto API Header
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifndef __SIMPLE_CRYPTO_H__
#define __SIMPLE_CRYPTO_H__

#include <stdbool.h>
#include <stdint.h>

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hash.h>

/******************************** MACRO DEFINITIONS ********************************/
#define BLOCK_SIZE AES_BLOCK_SIZE
// #define KEY_SIZE 16

/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts plaintext using a symmetric cipher
 *
 * @param plaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param len The length of the plaintext to encrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for encryption
 * @param ciphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int encrypt_sym(uint8_t *plaintext, size_t len, const uint8_t *key,
                const uint8_t *iv, uint8_t *auth_tag, const uint8_t *aad,
                size_t aad_len, uint8_t *ciphertext);

/** @brief Decrypts ciphertext using a symmetric cipher
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *           ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Must be a multiple of
 *           BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *           the key to use for decryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *           plaintext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, const uint8_t *key, const uint8_t *iv,
                const uint8_t *auth_tag, const uint8_t *aad, size_t aad_len,
                uint8_t *plaintext);

/** @brief Signs arbitrary-length data
 *
 * @param in A pointer to a buffer of length in_size containing the data
 *          to be signed
 * @param in_size The size of the data to sign
 * @param sig The 72-byte buffer to hold the signature
 * @param sig_len A pointer to the signature length to be stored
 * @param priv The 32-byte P256 private signing key
 * @param pub The 33-byte P256 public signing key
 *
 * @return 0 on success, non-zero for other error
 */
int sign_msg(const uint8_t *in, int in_size, uint8_t *sig, uint32_t *sig_len,
             const uint8_t *priv, const uint8_t *pub);

/** @brief Verifies a data signature
 *
 * @param data A pointer to a buffer of length in_size containing the signed data
 * @param data_size The size of the data to sign
 * @param sig The signature of length sig-len
 * @param sig_len The signature length
 * @param pub The 33-byte P256 public signing key
 *
 * @return 0 on success, non-zero for other error
 */
int verify_msg(const uint8_t *data, int data_size, const uint8_t *sig, uint32_t sig_len, const uint8_t *pub);
#endif // __SIMPLE_CRYPTO_H__
