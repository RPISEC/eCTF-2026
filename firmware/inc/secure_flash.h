/**
 * @file "secure_flash.h"
 * @author Jeremy Goldberger
 * @brief Secure Flash Interface Header
 * @date 2026
 */

#ifndef __SECURE_FLASH_H__
#define __SECURE_FLASH_H__

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <ti/devices/msp/msp.h>
#include <ti/driverlib/driverlib.h>
#include <ti/driverlib/m0p/dl_core.h>

#define FLASH_PAGE_SIZE DL_FLASHCTL_SECTOR_SIZE /* 1024 */

/**
 * @brief Flash secure Read
 *
 * @param address: uint32_t, address of flash page to read
 * @param buffer: void*, pointer to buffer for data to be read into
 * @param size: uint32_t, number of bytes to read from flash
 *
 * This function reads data from the specified flash page into the buffer
 * with the specified amount of bytes
*/
void flash_secure_read(uint32_t address, void* buffer, uint32_t size, uint8_t key[32], uint8_t iv[12]);
/**
 * @brief Flash secure Write
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
 * flash_secure_erase_page documentation.
*/
int flash_secure_write(uint32_t address, void* buffer, uint32_t size, uint8_t key[32], uint8_t iv[12]);

#endif //__SECURE_FLASH_H__
