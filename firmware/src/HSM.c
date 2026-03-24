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

#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include <ti/driverlib/m0p/dl_interrupt.h>
#include "ti_msp_dl_config.h"
#include "status_led.h"
#include "simple_uart.h"
#include "hardware_crypto.h"
#include "macros.h"
#include "simple_trng.h"
#include "wallet.h"
#include "timer.h"
#include "timeout.h"
#include "memory_tools.h"

#ifdef AES_TEST
#include "aes_test.h"
#endif

#ifdef TRNG_TEST
#include "trng_test.h"
#endif


/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

static unsigned char uart_buf[MAX_MSG_SIZE];

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Initializes peripherals for system boot.
*/
void init() {
    init_stack_guard();

    // Initialize all of the hardware components
    SYSCFG_DL_init();

    // need to initialize wolfcrypt before initializing wolfcrypt-dependent components
    if (wolfCrypt_Init() < 0) {
        print_debug("wolfcrypt init error");
    };

    if(!trng_init()) {
        print_debug("trng init error");
    }

    if (!init_hardware_crypto()) {
        print_debug("hardware crypto init error");
    }

    if  (!init_timer()) {
        print_debug("timer init error");
    }
    reset_timer();

    init_fs();

    if (generate_key_cx() < 0) {
        print_debug("failed to generate key for handshake");
    }

    // Don't skip timeout!
    JITTER;

    timeout(TIMEOUT_BOOT);
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
        if (stack_overflow_detected()) {
            print_error("!!! STACK OVERFLOW DETECTED !!!");
            Default_Handler();
        }

        STATUS_LED_ON();

        pkt_len = sizeof(uart_buf); // Max length
        memset(uart_buf, 0, sizeof(uart_buf));
        result = read_packet(CONTROL_INTERFACE, &cmd, uart_buf, &pkt_len);

        IF (result != MSG_OK)
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
        ENDIF
        JITTER;

        // Handle the requested command
        switch (cmd) {

        // Handle list command
        case LIST_MSG:
            STATUS_LED_OFF();
            #ifdef AES_TEST
            test_aes_gcm();
            test_aes_gcm_errors();
            #endif // AES_TEST
            #ifdef TRNG_TEST
            test_trng_callback();
            #endif // TRNG_TEST
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
