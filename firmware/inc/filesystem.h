/**
 * @file filesystem.h
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

#ifndef __FILESYSTEM_H__
#define __FILESYSTEM_H__

#include <stdbool.h>
#include "simple_flash.h"
#include "hardware_crypto.h"

// #include "commands.h"

typedef unsigned char slot_t;
typedef uint16_t group_id_t;


/**********************************************************
 ********** BEGIN FUNCTIONALLY DEFINED ELEMENTS ***********
 **********************************************************/

// Everything in this section is defined by the functional requirements. Your design may
// not change the FAT scheme, address, or size of the elements. You may change the
// implementation to utilize the FAT however you like, and you may use any allocation
// scheme to determine where to store files. The pointers to files, along with their
// UUIDs MUST be at this location in flash or your design will not be functionally
// compliant.

#define MAX_FILE_COUNT 8
#define MAX_NAME_SIZE 32
#define MAX_CONTENTS_SIZE 8192

// _FLASH_FAT_START is defined by the functional specs to be the start of where the FAT
// will be stored. It is address 0x0003a000, the last flash page. Your team may NOT
// change this location as the data structure location must be known by the secure
// bootloader.
#define _FLASH_FAT_START 0x0003a000

// size of file UUID
#define UUID_SIZE 16

// This struct is functionally defined
typedef struct {
    char uuid[UUID_SIZE];
    uint16_t length;
    uint16_t padding;
    unsigned int flash_addr;
} filesystem_entry_t;

static filesystem_entry_t FILE_ALLOCATION_TABLE[MAX_FILE_COUNT];

/**********************************************************
 *********** END FUNCTIONALLY DEFINED ELEMENTS ************
 **********************************************************/


/*
The reference design allocates files for each slot as follows:
0: 0x10000-0x12400
1: 0x12400-0x14800
2: 0x14800-0x16c00
3: 0x16c00-0x19000
4: 0x19000-0x1b400
5: 0x1b400-0x1d800
6: 0x1d800-0x1fc00
7: 0x1fc00-0x22000
*/
// Calculate the flash address for a given file slot. 9 pages are allocated for each
// file.
#define FILE_START_PAGE_FROM_SLOT(slot) FILES_START_ADDR + (STORED_FILE_SIZE*slot)

// Calculate the total size of a file in flash, including its metadata
#define FILE_TOTAL_SIZE(len) len + offsetof(file_t, contents)

// Each file will take up a whole number of pages
#define FILE_PAGE_COUNT ((sizeof(file_t) + (FLASH_PAGE_SIZE - 1)) / FLASH_PAGE_SIZE)
#define STORED_FILE_SIZE FLASH_PAGE_SIZE*FILE_PAGE_COUNT

// first flash address for files
#define FILES_START_ADDR 0x28000

#define FILE_IN_USE 0xdeadbeef
// used to actually define the file object
typedef struct __attribute__((packed)) {
    uint32_t in_use; // FILE_IN_USE if in use
    group_id_t group_id;
    uint16_t contents_len;
    uint8_t iv[AES_IV_SIZE];
    uint8_t auth_tag[AES_AUTH_TAG_SIZE];
    char name[MAX_NAME_SIZE]; // must be at the end of the struct to match read packet format
} file_headers_t;

typedef struct __attribute__((packed)) {
    file_headers_t headers;
    uint8_t contents[MAX_CONTENTS_SIZE]; // encrypted
    uint8_t signature[64];
} file_t;

/** @brief Initialize the filesystem
 *
 *
 * @return 0 upon success. A negative value on error.
*/
int init_fs();

/** @brief Check whether a file is in use
 *
 *  @param slot The slot to check
 *
 * @return True if the slot is in use. False otherwise.
*/
bool is_slot_in_use(slot_t slot);

/** @brief Create a new file object in memory
 *
 *  @param slot The slot to check
 *
 * @return 0 upon success. A negative value otherwise.
*/
int create_file(file_t *dest, group_id_t group_id, char *name, uint16_t contents_len, uint8_t *contents);

/** @brief Encrypt a file in memory
 *
 *  @param file The file to encrypt
 *  @param k_storage The AES 256-bit key to use for encryption
 *
 * @return 0 upon success. A negative value otherwise.
*/
int encrypt_file(file_t *file, const uint8_t *k_storage);

/** @brief Sign a file in memory
 *
 *  @param file The file to sign
 *  @param w_priv The ED25519 256-bit private key
 *  @param w_pub The ED25519 256-bit public key
 *
 * @return 0 upon success. A negative value otherwise.
*/
int sign_file(file_t *file, const uint8_t *w_priv, const uint8_t *w_pub);

/** @brief Create a new file object on flash
 *
 *  @param slot The slot to write the file to
 *  @param src The sourc file to store
 *  @param uuid The UUID to store in the FAT
 *
 * @return 0 upon success. A negative value otherwise.
*/
int write_file(slot_t slot, file_t *src, const uint8_t *uuid);

/** @brief Read a file from persistent storage into memory
 *
 *  @param slot The slot to read
 *  @param dest The destination address to store the file
 *
 * @return 0 upon success. A negative value otherwise.
*/
int read_file(slot_t slot, file_t *dest);

/** @brief Verify a file's signature in memory
 *
 *  @param file The file to verify.
 *  @param w_pub The ED25519 256-bit public key.
 *
 * @return 0 upon success. A negative value otherwise.
*/
int verify_file(file_t *file, const uint8_t *w_pub);

/** @brief Decrypt a file's contents in memory
 *
 *  @param file The file to decrypt.
 *  @param dest The AES 256-bit key to decrypt with.
 *
 * @return 0 upon success. A negative value otherwise.
*/
int decrypt_file(file_t *file, const uint8_t *k_storage);

/** @brief Get a read-only pointer to a file's metadata
 *
 *  @param slot The slot to get metadata for
 *
 * @return A filesystem_entry_t * on success. NULL on error.
*/
const filesystem_entry_t *get_file_metadata(slot_t slot);

/** @brief Get a read-only pointer to the file's header. The contents will
 *         be filled with garbage data and should not be accessed.
 * 
 * @param slot The slot to get headers for.
 * 
 */
const int get_file_headers(slot_t slot, file_headers_t *file_headers);

#endif // __FILESYSTEM_H__
