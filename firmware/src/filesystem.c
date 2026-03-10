/**
 * @file filesystem.c
 * @author Samuel Meyers
 * @brief eCTF flash-based filesystem management
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <stdint.h>

#include "filesystem.h"
#include "simple_crypto.h"
#include "simple_flash.h"
#include "simple_trng.h"
#include "host_messaging.h" // DEBUG REMOVE ME
#include "wallet.h"
#include "wolfssl/wolfcrypt/ed25519.h"

int load_fat() {
    flash_simple_read((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
    return 0;
}

int store_fat() {
    flash_simple_erase_page(_FLASH_FAT_START);
    return flash_simple_write((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
}

/** @brief Initialize the filesystem
 *
 *
 * @return 0 upon success. A negative value on error.
*/
int init_fs() {
    return load_fat();
}

/** @brief Check whether a file is in use
 *
 *  @param slot The slot to check
 *
 * @return True if the slot is in use. False otherwise.
*/
bool is_slot_in_use(slot_t slot) {
    file_headers_t temp_file_headers;
    get_file_headers(slot, &temp_file_headers);
    return temp_file_headers.in_use == FILE_IN_USE;
}

/** @brief Create a new file object in memory
 *
 *  @param slot The slot to check
 *
 * @return 0 upon success. A negative value otherwise.
*/
int create_file(
    file_t *dest,
    group_id_t group_id,
    char *name,
    uint16_t contents_len,
    uint8_t *contents
) {
    memset(dest, 0, sizeof(file_t));

    dest->headers.in_use = FILE_IN_USE;
    dest->headers.group_id = group_id;
    dest->headers.contents_len = contents_len;

    // name must be null terminated, and the contents are defined by a length
    strcpy(dest->headers.name, name);
    memcpy(dest->contents, contents, contents_len);

    return 0;
}

/** @brief Encrypt a file in memory
 *
 *  @param file The file to encrypt
 *  @param k_storage The AES 256-bit key to use for encryption
 *
 * @return 0 upon success. A negative value otherwise.
*/
int encrypt_file(file_t *file, const uint8_t *k_storage) {
    // Generate random IV
    for (int i = 0; i < AES_IV_SIZE / 4; i++) {
        uint32_t rand = trng_get_u32();
        if (rand == 0) {
            return -1;
        }
        memcpy(&file->headers.iv[i * 4], &rand, 4);
    }
    print_debug("iv generated");

    // Encrypt
    int ret = encrypt_sym(file->contents, file->headers.contents_len, k_storage,
                          file->headers.iv, file->headers.auth_tag, NULL, 0,
                          file->contents); // Encrypt in place
    if (ret < 0) {
        return -2;
    }

    return 0;
}

/** @brief Sign a file in memory
 *
 *  @param file The file to sign
 *  @param w_priv The ED25519 256-bit private key
 *  @param w_pub The ED25519 256-bit public key
 *
 * @return 0 upon success. A negative value otherwise.
*/
int sign_file(file_t *file, const uint8_t *w_priv, const uint8_t *w_pub) {
    ed25519_key *key;
    uint32_t sign_len;
    int ret;

    key = malloc(sizeof(ed25519_key));
    if (key == NULL) {
        print_error("insufficient memory for ed25519 key");
        return -1;
    }
    ret = wc_ed25519_import_private_key(w_priv, sizeof(key32_t), w_pub, sizeof(key32_t), key);
    if (ret < 0) {
        print_error("failed to import w_priv");
        free(key);
        return -2;
    }

    sign_len = sizeof(file->signature);
    ret = wc_ed25519_sign_msg((uint8_t *)file, sizeof(file_t) - 64,
                              file->signature, &sign_len, key);
    if (sign_len != 64) {
        print_error("incorrect signature length");
    }

    if (ret < 0) {
        print_hex_debug(&ret, sizeof(ret));
        print_error("failed to sign");
        free(key);
        return -3;
    }

    free(key);
    return 0;
}

/** @brief Create a new file object on flash
 *
 *  @param slot The slot to write the file to
 *  @param src The sourc file to store
 *  @param uuid The UUID to store in the FAT
 *
 * @return 0 upon success. A negative value otherwise.
*/
int write_file(slot_t slot, file_t *src, const uint8_t *uuid) {
    unsigned int length, flash_addr;
    int ret;

    flash_addr = FILE_START_PAGE_FROM_SLOT(slot);
    length = FILE_TOTAL_SIZE(src->headers.contents_len);

    // Update the FAT for the new file
    memcpy(&FILE_ALLOCATION_TABLE[slot].uuid, uuid, UUID_SIZE);
    FILE_ALLOCATION_TABLE[slot].flash_addr = flash_addr;
    FILE_ALLOCATION_TABLE[slot].length = length;
    store_fat();

    // erase the pages that will store the file
    for (int i = 0; i < FILE_PAGE_COUNT; i++) {
        flash_simple_erase_page(flash_addr + (FLASH_PAGE_SIZE * i));
    }

    // now write the file
    return flash_simple_write(FILE_ALLOCATION_TABLE[slot].flash_addr, src, sizeof(file_t));
}

/** @brief Read a file from persistent storage into memory
 *
 *  @param slot The slot to read
 *  @param dest The destination address to store the file
 *  @param key The AES key to decrypt with. If NULL, skip this step.
 *
 * @return 0 upon success. A negative value otherwise.
*/
int read_file(slot_t slot, file_t *dest, uint8_t* key) {
    int flash_addr, file_size;

    flash_addr = FILE_ALLOCATION_TABLE[slot].flash_addr;
    file_size = FILE_ALLOCATION_TABLE[slot].length;
    if (flash_addr < 0 || file_size < 0) {
        return -1;
    }
    flash_simple_read(flash_addr, dest, file_size);

    // If no key is provided, return it still encrypted. This is useful for receive.
    if (key == NULL) {
        return 0;
    }
    // Otherwise, decrypt it like normal.
    int ret = decrypt_sym(dest->contents, dest->headers.contents_len, key,
                          dest->headers.iv, dest->headers.auth_tag, NULL, 0,
                          dest->contents); // Decrypt in place
    if (ret != 0)
        return ret;
    return 0;
}

/** @brief Get a read-only pointer to a file's metadata
 *
 *  @param slot The slot to get metadata for
 *
 * @return A filesystem_entry_t * on success. NULL on error.
*/
const filesystem_entry_t *get_file_metadata(slot_t slot) {
    return &FILE_ALLOCATION_TABLE[slot];
}

/** @brief Get a read-only pointer to a file's headers. This returns a file_t,
 *         but the contents are garbage data and should not be accessed.
 *  @param slot The slot to get headers for
*/
const int get_file_headers(slot_t slot, file_headers_t *file_headers) {
    int flash_addr, file_size;

    flash_addr = FILE_ALLOCATION_TABLE[slot].flash_addr;
    file_size = FILE_ALLOCATION_TABLE[slot].length;
    if (flash_addr < 0 || file_size < 0) {
        return -1;
    }
    flash_simple_read(flash_addr, file_headers, sizeof(file_headers_t));
    return 0;
}
