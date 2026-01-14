/**
 * @file host_messaging.c
 * @author Samuel Meyers
 * @brief eCTF Host Messaging Implementation
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <stdio.h>

#include "host_messaging.h"


/** @brief Read len bytes from UART, acknowledging after every 256 bytes.
 *
 *  @param buf Pointer to a buffer where the incoming bytes should be stored.
 *  @param len The number of bytes to be read.
 *
 *  @return MSG_OK on success. A negative value on error.
*/
int read_bytes(int uart_id, void *buf, uint16_t len) {
    int result;
    int i;

    for (i = 0; i < len; i++) {
        if (i % 256 == 0 && i != 0) { // Send an ACK after receiving 256 bytes
            write_ack(uart_id);
        }
        result = uart_readbyte(uart_id);
        if (result < 0) {  // if there was an error, return immediately
            return result;
        }
        ((uint8_t *)buf)[i] = result;
    }

    return MSG_OK;
}

/** @brief Read a msg header from UART.
 *
 *  @param hdr Pointer to a buffer where the incoming bytes should be stored.
*/
void read_header(int uart_id, msg_header_t *hdr) {
    hdr->magic = uart_readbyte(uart_id);
    // Any bytes until '%' will be read, but ignored.
    // Once we receive a '%', continue with processing the rest of the message.
    while (hdr->magic != MSG_MAGIC) {
        hdr->magic = uart_readbyte(uart_id);
    }
    hdr->cmd = uart_readbyte(uart_id);
    read_bytes(uart_id, &hdr->len, sizeof(hdr->len));
}

/** @brief Receive an ACK from UART.
 *
 *  @return MSG_OK on success. A negative value on error.
*/
int read_ack(int uart_id) {
    msg_header_t ack_buf = {0};

    read_header(uart_id, &ack_buf);
    if (ack_buf.cmd == ACK_MSG) {
        return MSG_OK;
    } else {
        return MSG_NO_ACK;
    }
}

/** @brief Write len bytes to console
 *
 *  @param buf Pointer to a buffer that stores the outgoing bytes.
 *  @param len The number of bytes to write.
 *  @param should_Ack True if the device should expect an ACK. This should be false for
 *                    debug and ACK messages.
 *
 *  @return MSG_OK on success, else other msg_status_t
*/
int write_bytes(int uart_id, const void *buf, uint16_t len, bool should_ack) {
    for (int i = 0; i < len; i++) {
        if (i % 256 == 0 && i != 0) {  // Expect an ACK after sending every 256 bytes
            if (should_ack && read_ack(uart_id) < 0) {
                return MSG_NO_ACK;
            }
        }
        uart_writebyte(uart_id, ((uint8_t *)buf)[i]);
    }

    fflush(stdout);

    return MSG_OK;
}

/** @brief Write len bytes to UART in hex. 2 bytes will be printed for every byte.
 *
 *  @param uart_id The id of the uart where the message is to be sent
 *  @param type Message type.
 *  @param buf Pointer to the bytes that will be printed.
 *  @param len The number of bytes to print.
 *
 *  @return MSG_OK on success, else other msg_status_t
*/
int write_hex(int uart_id, msg_type_t type, const void *buf, size_t len) {
    msg_header_t hdr;
    int i;

    char hexbuf[128];

    hdr.magic = MSG_MAGIC;
    hdr.cmd = type;
    hdr.len = len*2;

    write_bytes(uart_id, &hdr, MSG_HEADER_SIZE, false /* should_ack */);
    if (type != DEBUG_MSG && read_ack(uart_id) != MSG_OK) {
        // If the header was not ack'd, don't send the message
        return MSG_NO_ACK;
    }

    for (i = 0; i < len; i++) {
        if (i % (256 / 2) == 0 && i != 0) {
            if (type != DEBUG_MSG && read_ack(uart_id) != MSG_OK) {
                // If the block was not ack'd, don't send the rest of the message
                return MSG_NO_ACK;
            }
        }
        snprintf(hexbuf, sizeof(hexbuf), "%02x", ((uint8_t *)buf)[i]);
        write_bytes(uart_id, hexbuf, 2, false);
    }
    return MSG_OK;
}

/** @brief Send a message to the host, expecting an ack after every 256 bytes.
 *
 *  @param uart_id The id of the uart where the message is to be sent
 *  @param type The type of message to send.
 *  @param buf Pointer to a buffer containing the outgoing packet.
 *  @param len The size of the outgoing packet in bytes.
 *
 *  @return MSG_OK on success, else other msg_status_t
*/
int write_packet(int uart_id, msg_type_t type, const void *buf, uint16_t len) {
    msg_header_t hdr;
    int result;

    hdr.magic = MSG_MAGIC;
    hdr.cmd = type;
    hdr.len = len;

    result = write_bytes(uart_id, &hdr, MSG_HEADER_SIZE, false);

    // ACKs don't need a response
    if (type == ACK_MSG) {
        return result;
    }

    // If the header was not ack'd, don't send the message
    if (type != DEBUG_MSG && read_ack(uart_id) != MSG_OK) {
        return MSG_NO_ACK;
    }

    // If there is data to write, write it
    if (len > 0) {
        result = write_bytes(uart_id, buf, len, type != DEBUG_MSG);
        // If we still need to ACK the last block (write_bytes does not handle the final ACK)
        if (type != DEBUG_MSG && read_ack(uart_id) != MSG_OK) {
            return MSG_NO_ACK;
        }
    }

    return MSG_OK;
}

/** @brief Reads a packet from console UART.
 *
 *  @param uart_id The id of the uart where the message is to be sent
 *  @param cmd A pointer to the resulting opcode of the packet. Must not be null.
 *  @param buf A pointer to a buffer to store the incoming packet. Can be null.
 *  @param len A pointer to the resulting length of the packet. Can be null.
 *
 *  @return MSG_OK on success, else other msg_status_t
*/
int read_packet(int uart_id, msg_type_t* cmd, void *buf, uint16_t *len) {
    msg_header_t header = {0};

    // cmd must be a valid pointer
    if (cmd == NULL) {
        return MSG_BAD_PTR;
    }

    read_header(uart_id, &header);

    *cmd = header.cmd;

    if (len != NULL) {
        if (*len && header.len > *len) {
            *len = 0;
            return MSG_BAD_LEN;
        }

        *len = header.len;
    }

    if (header.cmd != ACK_MSG) {
        write_ack(uart_id);  // ACK the header
        if (header.len && buf != NULL) {
            if (read_bytes(uart_id, buf, header.len) != MSG_OK) {
                return MSG_NO_ACK;
            }
        }
        if (header.len) {
            if (write_ack(uart_id) != MSG_OK) { // ACK the final block (not handled by read_bytes)
                return MSG_NO_ACK;
            }
        }
    }
    return MSG_OK;
}
