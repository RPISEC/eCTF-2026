/**
 * @file "simple_flash.c"
 * @author Samuel Meyers
 * @brief Simple Flash Interface Implementation
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "simple_flash.h"

/**
 * @brief Flash Simple Erase Page
 *
 * @param address: uint32_t, address of flash page to erase
 *
 * @return int: return negative if failure, zero if success
 *
 * This function erases a page of flash such that it can be updated.
 * Flash memory can only be erased in a large block size called a page (or sector).
 * Once erased, memory can only be written one way e.g. 1->0.
 * In order to be re-written the entire page must be erased.
*/
int flash_simple_erase_page(uint32_t address) {
    volatile DL_FLASHCTL_COMMAND_STATUS cmdStatus;
    DL_FlashCTL_executeClearStatus(FLASHCTL);
    DL_FlashCTL_unprotectSector(FLASHCTL, address, DL_FLASHCTL_REGION_SELECT_MAIN);

    cmdStatus = DL_FlashCTL_eraseMemoryFromRAM(
        FLASHCTL, address, DL_FLASHCTL_COMMAND_SIZE_SECTOR);
    if (cmdStatus == DL_FLASHCTL_COMMAND_STATUS_FAILED) {
        return -1;
    }
    // returns a boolean, so handle that accordingly
    bool ret = DL_FlashCTL_waitForCmdDone(FLASHCTL);
    if (ret == false) {
        return -1;
    }
    return 0;
}

/**
 * @brief Flash Simple Read
 *
 * @param address: uint32_t, address of flash page to read
 * @param buffer: void*, pointer to buffer for data to be read into
 * @param size: uint32_t, number of bytes to read from flash
 *
 * This function reads data from the specified flash page into the buffer
 * with the specified amount of bytes
*/
void flash_simple_read(uint32_t address, void* buffer, uint32_t size) {
    // flash is memory mapped, and the flash controller has no read functionality
    memcpy(buffer, (void *)address, size);
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
int flash_simple_write(uint32_t address, void* buffer, uint32_t size) {
    volatile DL_FLASHCTL_COMMAND_STATUS cmdStatus;
    DL_FlashCTL_executeClearStatus(FLASHCTL);
    DL_FlashCTL_unprotectSector(FLASHCTL, address, DL_FLASHCTL_REGION_SELECT_MAIN);

    // program function expects size to be the number of 32-bit words
    uint32_t size_32b = (size % 4 == 0) ? (size / 4) : (size / 4) + 1;
    // it also expects it to be an even number
    size_32b = (size_32b % 2 == 0) ? size_32b : size_32b + 1;

    // write the data into a correctly sized region to ensure no undefined behavior
    uint32_t write_data[size_32b];
    memset(write_data, 0xff, size_32b*4);
    memcpy(write_data, buffer, size);

    // if memory section is corrected, make sure to write the ECC (you have been warned)
    cmdStatus = DL_FlashCTL_programMemoryBlockingFromRAM64WithECCGenerated(
        FLASHCTL, address, (uint32_t *)write_data, size_32b, DL_FLASHCTL_REGION_SELECT_MAIN
    );
    if (cmdStatus == DL_FLASHCTL_COMMAND_STATUS_FAILED) {
        return -1;
    }
    // returns a boolean, so handle that accordingly
    bool ret = DL_FlashCTL_waitForCmdDone(FLASHCTL);
    if (ret == false) {
        return -1;
    }
    return 0;
}
