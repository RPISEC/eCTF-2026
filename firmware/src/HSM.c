/**
 * @file    HSM.c
 * @author  Samuel Meyers
 * @brief   Boot code and main function for the HSM
 * @date    2026
 *
 * This source file is part of an example system for MITRE's 2026
 * Embedded CTF (eCTF). This code is being provided only for
 * educational purposes for the 2026 MITRE eCTF competition, and may not
 * meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <wolfssl/wolfcrypt/wc_port.h>

#include "simple_flash.h"
#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "ti_msp_dl_config.h"
#include "status_led.h"
#include "simple_uart.h"
#include "hardware_crypto.h"
#include "simple_trng.h"

#ifdef AES_TEST
#include "aes_test.h"
#endif


/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

static unsigned char uart_buf[MAX_MSG_SIZE];

static const uint8_t big_array[] = {
    0x18, 0x6a, 0x7f, 0xd2, 0xa0, 0x6c, 0xb6, 0x75, 0xb8, 0x48, 0xb8, 0xd7,
    0x2d, 0x8a, 0x9e, 0x7a, 0x4c, 0xb0, 0x09, 0x3f, 0x35, 0xb8, 0xad, 0x31,
    0xa3, 0xf1, 0xa1, 0x84, 0x2e, 0xda, 0x89, 0xd4, 0xbf, 0xdb, 0xa2, 0xc3,
    0x19, 0x8b, 0x17, 0xd0, 0x30, 0x5e, 0xa5, 0xa1, 0x2f, 0xa0, 0x6c, 0x86,
    0x87, 0x5a, 0xa0, 0x5e, 0xaf, 0x15, 0x6c, 0x4a, 0x19, 0xde, 0x2c, 0x54,
    0x0c, 0x25, 0x89, 0x12, 0xa6, 0x05, 0x14, 0x01, 0x25, 0x06, 0x84, 0x78,
    0x01, 0xbe, 0x65, 0x6f, 0x80, 0x3b, 0xcb, 0xef, 0x9a, 0x9a, 0x07, 0xf2,
    0xa4, 0x64, 0x90, 0x67, 0x17, 0xf8, 0xcf, 0x65, 0xd1, 0x4d, 0xb7, 0xdb,
    0x96, 0x90, 0xeb, 0x69, 0x4b, 0x6c, 0x79, 0xc3, 0x99, 0xc0, 0xf8, 0xa6,
    0x63, 0x0c, 0xee, 0x31, 0xa9, 0xd8, 0xb2, 0x56, 0x33, 0x0c, 0x15, 0xf0,
    0xe6, 0x50, 0xeb, 0x5f, 0xa4, 0xc4, 0x60, 0x65, 0x83, 0xcf, 0x47, 0xad,
    0x84, 0x55, 0x2e, 0xed, 0x59, 0x5f, 0x09, 0x65, 0xb5, 0xfb, 0x58, 0x54,
    0xc0, 0x4c, 0x61, 0xd7, 0x14, 0xa9, 0xcf, 0x8b, 0xd5, 0x44, 0x20, 0x2f,
    0x27, 0x65, 0x5c, 0xf0, 0x36, 0x2e, 0x25, 0x69, 0xf3, 0x14, 0xdb, 0x80,
    0x1d, 0x02, 0x69, 0x6b, 0xd1, 0x7a, 0x1b, 0x76, 0x80, 0x07, 0xb8, 0xdf,
    0xda, 0x39, 0x7c, 0x7b, 0xd4, 0x98, 0x2d, 0x9f, 0xd1, 0xc3, 0xdb, 0xcd,
    0x9d, 0xce, 0x14, 0x31, 0x93, 0x8e, 0x3c, 0x97, 0xef, 0xf0, 0x8d, 0xdb,
    0x80, 0x24, 0xdf, 0x45, 0xef, 0x00, 0x00, 0x53, 0xf8, 0xa8, 0x59, 0xed,
    0x65, 0x8d, 0xa0, 0x56, 0xa0, 0x86, 0x91, 0x9f, 0x77, 0xe3, 0x9b, 0x8e,
    0x43, 0xaa, 0x0b, 0xd9, 0x63, 0x38, 0xb2, 0xc2, 0x77, 0xd0, 0x13, 0xe3,
    0xb1, 0x97, 0x24, 0x29, 0x8b, 0xfd, 0x0a, 0xc7, 0xbd, 0xac, 0x41, 0x7e,
    0x97, 0x66, 0xb1, 0xab, 0xed, 0xaf, 0xe0, 0xd0, 0xb3, 0xed, 0xd5, 0x75,
    0x0b, 0x22, 0xda, 0xd9, 0xd2, 0xbb, 0xe2, 0x96, 0x9a, 0xb6, 0xa5, 0x94,
    0xa2, 0x87, 0xf2, 0xa2, 0xdb, 0xaf, 0x04, 0xaf, 0x5b, 0xf7, 0xbc, 0x3a,
    0x2d, 0x72, 0xa1, 0x15,
};

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Initializes peripherals for system boot.
*/
void init() {
    // Initialize all of the hardware components
    SYSCFG_DL_init();

    // need to initialize wolfcrypt before initializing wolfcrypt-dependent components
    wolfCrypt_Init();
    print_debug("wolfCrypt initialized\n");

    if(!trng_init()) {
        print_debug("trng init error");
    }

    if (!init_hardware_crypto()) {
        print_debug("hardware crypto init error");
    }

    init_fs();
}

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void) {
    char output_buf[128] = {0};
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // initialize the device
    init();

    // process commands forever
    while (1) {
        print_debug("Ready\n");

        STATUS_LED_ON();

        pkt_len = 0;
        result = read_packet(CONTROL_INTERFACE, &cmd, uart_buf, &pkt_len);

        if (result != MSG_OK) {
            STATUS_LED_OFF();
            switch (result)
            {
            case MSG_BAD_PTR:
                print_error("Bad cmd pointer\n");
                break;
            case MSG_NO_ACK:
                print_error("Failed to receive ACK from host\n");
                break;
            case MSG_BAD_LEN:
                print_error("Received bad length\n");
                break;
            default:
                print_error("Failed to receive cmd from host\n");
                break;
            }
            continue;
        }

        // Handle the requested command
        switch (cmd) {

        // Handle list command
        case LIST_MSG:
            STATUS_LED_OFF();
            #ifdef AES_TEST
            test_aes_gcm();
            test_aes_gcm_errors();
            #endif // AES_TEST
            list(pkt_len, uart_buf);
            break;

        // Handle read command
        case READ_MSG:
            STATUS_LED_OFF();
            read(pkt_len, uart_buf);
            break;

        // Handle write command
        case WRITE_MSG:
            STATUS_LED_OFF();
            write(pkt_len, uart_buf);
            break;

        // Handle receive command
        case RECEIVE_MSG:
            STATUS_LED_OFF();
            receive(pkt_len, uart_buf);
            break;

        // Handle interrogate command
        case INTERROGATE_MSG:
            STATUS_LED_OFF();
            print_hex_debug(big_array, sizeof(big_array));
            interrogate(pkt_len, uart_buf);
            break;

        // Handle listen command
        case LISTEN_MSG:
            STATUS_LED_OFF();
            listen(pkt_len, uart_buf);
            break;

        // Handle bad command
        default:
            STATUS_LED_OFF();
            sprintf(output_buf, "Invalid Command: %c\n", cmd);
            print_error(output_buf);
            break;
        }
    }
}
