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
#include "hardware_crypto.h"
#include "ti_msp_dl_config.h"
#include <stdint.h>
#include <string.h>
#include <wolfssl/wolfcrypt/signature.h>

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
 * @param auth_tag A pointer to a buffer of length AES_AUTH_TAG_SIZE where the
 *          resulting auth tag will be written to
 * @param ciphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int encrypt_sym(uint8_t *plaintext, size_t len, const uint8_t *key,
                const uint8_t *iv, uint8_t *auth_tag, const uint8_t *aad,
                size_t aad_len, uint8_t *ciphertext) {
    Aes *aes; // Context for encryption
    int ret; // Library result

    // Ensure valid length
    if (len <= 0)
        return -1;

    aes = wc_AesNew(NULL, HARDWARE_CRYPTO_DEVICE_ID, &ret);
    if (ret != 0) {
        wc_AesDelete(aes, &aes);
        return ret;
    }
    // Set the key for encryption
    ret = wc_AesGcmSetKey(aes, key, AES_KEY_SIZE);
    if (ret != 0) {
        wc_AesDelete(aes, &aes);
        return ret;
    }

    ret = wc_AesGcmEncrypt(aes, ciphertext, plaintext, len, iv, AES_IV_SIZE,
                           auth_tag, AES_AUTH_TAG_SIZE, aad, aad_len);
    // wc_AesFree(&aes);
    wc_AesDelete(aes, &aes);
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
 * @param auth_tag A pointer to a buffer of length AES_AUTH_TAG_SIZE where the
 *          resulting auth tag will be written to
 * @param plaintext A pointer to a buffer of length len where the resulting
 *          plaintext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, const uint8_t *key, const uint8_t *iv,
                const uint8_t *auth_tag, const uint8_t *aad, size_t aad_len,
                uint8_t *plaintext) {
    Aes *aes; // Context for encryption
    int ret; // Library result

    // Ensure valid length
    if (len <= 0)
        return -1;

    aes = wc_AesNew(NULL, HARDWARE_CRYPTO_DEVICE_ID, &ret);
    if (ret != 0) {
        wc_AesDelete(aes, &aes);
        return ret;
    }
    // Set the key for encryption
    ret = wc_AesGcmSetKey(aes, key, AES_KEY_SIZE);
    if (ret != 0) {
        wc_AesDelete(aes, &aes);
        return ret;
    }

    ret = wc_AesGcmDecrypt(aes, plaintext, ciphertext, len, iv, AES_IV_SIZE,
                           auth_tag, AES_AUTH_TAG_SIZE, aad, aad_len);
    wc_AesDelete(aes, &aes);
    if (ret != 0)
        return ret;
    return 0;
}

/** @brief Signs arbitrary-length data
 *
 * @param in A pointer to a buffer of length in_size containing the data
 *          to be signed
 * @param in_size The size of the data to sign
 * @param sig The 72-byte buffer to hold the signature
 * @param priv The 32-byte P256 private signing key
 * @param pub The 33-byte P256 public signing key
 *
 * @return 0 on success, non-zero for other error
 */
int sign_msg(const uint8_t *in, int in_size, uint8_t *sig, uint32_t *sig_len,
             const uint8_t *priv, const uint8_t *pub) {
    WC_RNG *rng;
    ecc_key *key;
    int ret;

    key = wc_ecc_key_new(NULL);
    if (key == NULL) {
        return -1;
    }

    ret = wc_ecc_import_private_key_ex(priv, 32, pub, 33, key, ECC_SECP256R1);
    if (ret < 0) {
        wc_ecc_key_free(key);
        return -2;
    }

    rng = wc_rng_new(NULL, 0, NULL);
    if (rng == NULL) {
        wc_ecc_key_free(key);
        return -3;
    }

    *sig_len = 72;
    ret = wc_SignatureGenerate_ex(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_ECC, in,
                               in_size, sig, sig_len, key, sizeof(*key), rng, 0);

    if (ret < 0) {
        wc_ecc_key_free(key);
        wc_rng_free(rng);
        return -5;
    }

    wc_ecc_key_free(key);
    wc_rng_free(rng);
    return 0;
}

/** @brief Verifies a data signature
 *
 * @param data A pointer to a buffer of length in_size containing the signed data
 * @param data_size The size of the data to sign
 * @param sig The 72-byte signature
 * @param pub The 33-byte P256 public signing key
 *
 * @return 0 on success, non-zero for other error
 */
int verify_msg(const uint8_t *data, int data_size, const uint8_t *sig, uint32_t sig_len, const uint8_t *pub) {
    ecc_key *key;
    int ret;

    key = wc_ecc_key_new(NULL);
    if (key == NULL) {
        return -1;
    }

    ret = wc_ecc_import_x963_ex(pub, 33, key, ECC_SECP256R1);
    if (ret < 0) {
        wc_ecc_key_free(key);
        return -2;
    }

    ret = wc_SignatureVerify(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_ECC, data,
                             data_size, sig, sig_len, key, sizeof(*key));

    if (ret < 0) {
        wc_ecc_key_free(key);
        return -3;
    }

    wc_ecc_key_free(key);
    return 0;
}
