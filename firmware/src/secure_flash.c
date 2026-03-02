/**
 * @file "secure_flash.c"
 * @author Jeremy Goldberger
 * @brief Secure Flash Interface Implementation
 * @date 2026
 *
 * Secure flash based off of simple_flash that implements at rest encryption
 */

#include "simple_flash.h"
#include "secure_flash.h"
#include "simple_crypto.h"


/**
 * @brief Flash Secure Read
 *
 * @param address: uint32_t, address of flash page to read
 * @param buffer: void*, pointer to buffer for data to be read into
 * @param size: uint32_t, number of bytes to read from flash
 * @param key: uint8_t[32], 32 byte key for AES encryption
 * @param iv: uint8_t[12], 12 byte iv for AES encryption
 *
 * This function reads data from the specified flash page into the buffer
 * with the specified amount of bytes
*/
void flash_secure_read(uint32_t address, void* buffer, uint32_t size, uint8_t key[32], uint8_t iv[12]) {
    memcpy(buffer, (void *)address, size);

    int ret = decrypt_sym(buffer, size, key, iv, buffer); // Encrypt in place
    if (ret != 0)
        return ret;
    return 0;
}

/**
 * @brief Flash Simple Write
 *
 * @param address: uint32_t, address of flash page to write
 * @param buffer: void*, pointer to buffer to write data from
 * @param size: uint32_t, number of bytes to write from flash
 *
 * @return int: return negative if failure, zero if success
 *
 * This function writes data to the specified flash page from the buffer passed
 * with the specified amount of bytes. Flash memory can only be written in one
 * way e.g. 1->0. To rewrite previously written memory see the
 * flash_simple_erase_page documentation.
*/
int flash_secure_write(uint32_t address, void* buffer, uint32_t size, uint8_t key[32], uint8_t iv[12]) {
    int ret = encrypt_sym(buffer, size, key, iv, buffer); // Encrypt in place
    flash_simple_write(address, buffer, size);
    return 0;
}
