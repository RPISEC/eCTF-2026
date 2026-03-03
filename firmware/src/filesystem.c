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
#include "simple_flash.h"
#include "simple_trng.h"
#include "simple_crypto.h"
#include "host_messaging.h" // DEBUG REMOVE ME

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
    file_t temp_file;
    get_file_headers(slot, &temp_file);
    return temp_file.in_use == FILE_IN_USE;
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

    dest->in_use = FILE_IN_USE;
    dest->group_id = group_id;
    dest->contents_len = contents_len;
    for (int i = 0; i < AES_IV_SIZE / 4; i++) {
        uint32_t rand = trng_get_u32();
        memcpy(&dest->iv[i*4], &rand, 4);
    }

    // name must be null terminated, and the contents are defined by a length
    strcpy(dest->name, name);
    memcpy(dest->contents, contents, contents_len);

    return 0;
}

/** @brief Create a new file object in memory
 *
 *  @param slot The slot to write the file to
 *  @param src The sourc file to store
 *  @param uuid The UUID to store in the FAT
 *  @param key The AES key to encrypt with. An IV is generated.
 *
 * @return 0 upon success. A negative value otherwise.
*/
int write_file(slot_t slot, file_t *src, uint8_t *uuid, uint8_t* key) {
    unsigned int length, flash_addr;

    flash_addr = FILE_START_PAGE_FROM_SLOT(slot);
    // Length, rounded to nearest AES block size
    length = FILE_TOTAL_SIZE(src->contents_len + (AES_BLOCK_SIZE - src->contents_len % AES_BLOCK_SIZE));
    
    // If no key is provided, write it unencrypted. This is useful for recieve,
    // when it is already encrypted.
    if (key != NULL) {
        // Generate random IV
        for (int i = 0; i < AES_IV_SIZE / 4; i++) {
            uint32_t rand = trng_get_u32();
            memcpy(&src->iv[i*4], &rand, 4);
        }
        print_debug("iv generated");

        // Encrypt
        int ret = encrypt_sym(src->contents,
            src->contents_len + (AES_BLOCK_SIZE - src->contents_len % AES_BLOCK_SIZE),
            key, src->iv, src->auth_tag, NULL, 0, src->contents); // Encrypt in place
        if (ret != 0)
            return ret;
        print_debug("encrypted");
    }

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
    return flash_simple_write(FILE_ALLOCATION_TABLE[slot].flash_addr, src, length);
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

    // If no key is provided, return it still encrypted. This is useful for recieve.
    if (key == NULL) {
        return 0;
    }
    // Otherwise, decrypt it like normal.
    int ret = decrypt_sym(dest->contents,
        dest->contents_len + (AES_BLOCK_SIZE - dest->contents_len % AES_BLOCK_SIZE),
        key, dest->iv, dest->auth_tag, NULL, 0, dest->contents); // Decrypt in place
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
const int get_file_headers(slot_t slot, file_t *file_headers) {
    int flash_addr, file_size;

    flash_addr = FILE_ALLOCATION_TABLE[slot].flash_addr;
    file_size = FILE_ALLOCATION_TABLE[slot].length;
    if (flash_addr < 0 || file_size < 0) {
        return -1;
    }
    flash_simple_read(flash_addr, file_headers, sizeof(file_t) - MAX_CONTENTS_SIZE);
    return 0;
}
