/**
 * @file host_messaging.h
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

#ifndef __HOST_MESSAGING__
#define __HOST_MESSAGING__

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "simple_uart.h"

#define CMD_TYPE_LEN sizeof(char)
#define CMD_LEN_LEN sizeof(uint16_t)
#define MSG_MAGIC '%'       // '%' - 0x25

typedef enum {
    LIST_MSG = 'L',         // 'L' - 0x4c
    READ_MSG = 'R',         // 'R' - 0x52
    WRITE_MSG = 'W',        // 'W' - 0x57
    RECEIVE_MSG = 'C',      // 'C' - 0x43
    INTERROGATE_MSG = 'I',  // 'I' - 0x49
    LISTEN_MSG = 'N',       // 'N' - 0x4e
    ACK_MSG = 'A',          // 'A' - 0x41
    DEBUG_MSG = 'D',        // 'D' - 0x44
    ERROR_MSG = 'E',        // 'E' - 0x45
} msg_type_t;

#pragma pack(push, 1) // Tells the compiler not to pad the struct members
typedef struct {
    char magic;    // Should be MSG_MAGIC
    char cmd;      // msg_type_t
    uint16_t len;
} msg_header_t;
#pragma pack(pop) // Tells the compiler to resume padding struct members

typedef enum {
    MSG_OK = 0,
    MSG_BAD_PTR,
    MSG_NO_ACK,
    MSG_BAD_LEN,
    // <0 is UART error
} msg_status_t;

#define MSG_HEADER_SIZE sizeof(msg_header_t)

int write_bytes(int uart_id, const void *buf, uint16_t len, bool should_ack);

/** @brief Write len bytes to UART in hex. 2 bytes will be printed for every byte.
 *
 *  @param uart_id The id of the uart where the message is to be sent
 *  @param type Message type.
 *  @param buf Pointer to the bytes that will be printed.
 *  @param len The number of bytes to print.
 *
 *  @return 0 on success. A negative value on error.
*/
int write_hex(int uart_id, msg_type_t type, const void *buf, size_t len);

/** @brief Send a message to the host, expecting an ack after every 256 bytes.
 *
 *  @param uart_id The id of the uart where the message is to be sent
 *  @param type The type of message to send.
 *  @param buf Pointer to a buffer containing the outgoing packet.
 *  @param len The size of the outgoing packet in bytes.
 *
 *  @return 0 on success. A negative value on failure.
*/
int write_packet(int uart_id, msg_type_t type, const void *buf, uint16_t len);

/** @brief Reads a packet from console UART.
 *
 *  @param uart_id The id of the uart where the message is to be sent
 *  @param cmd A pointer to the resulting opcode of the packet. Must not be null.
 *  @param buf A pointer to a buffer to store the incoming packet. Can be null.
 *  @param len A pointer to the resulting length of the packet. Can be null.
 *
 *  @return 0 on success, a negative number on failure
*/
int read_packet(int uart_id, msg_type_t* cmd, void *buf, uint16_t *len);

// Macro definitions to print the specified format for error messages
#define print_error(msg) write_packet(CONTROL_INTERFACE, ERROR_MSG, msg, strlen(msg))

// Macro definitions to print the specified format for debug messages
#define print_debug(msg) write_packet(CONTROL_INTERFACE, DEBUG_MSG, msg, strlen(msg))
#define print_hex_debug(msg, len) write_hex(CONTROL_INTERFACE, DEBUG_MSG, msg, len)

// Macro definitions to write ack message
#define write_ack(uart_id) write_packet(uart_id, ACK_MSG, NULL, 0)

#endif
