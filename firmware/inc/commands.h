/**
 * @file commands.h
 * @author Samuel Meyers
 * @brief eCTF command handlers
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifndef __COMMANDS_H__
#define __COMMANDS_H__

#include "security.h"
#include "stdint.h"
#include "simple_flash.h"
#include "filesystem.h"
#include "secrets.h"

#define pkt_len_t uint16_t

// Pin will be 6 hex characters 0-9,a-f
typedef unsigned char pin_t[6];

#define MAX_MSG_SIZE sizeof(write_command_t)

// calculates the length of a list packet based on the number of files listed
#define LIST_PKT_LEN(num_files) (sizeof(num_files) + ((MAX_NAME_SIZE + sizeof(group_id_t) + sizeof(slot_t)) * num_files))

#pragma pack(push, 1) // Tells the compiler not to pad the struct members
// for more information on what struct padding does, see:
// https://www.gnu.org/software/c-intro-and-ref/manual/html_node/Structure-Layout.html

/**********************************************************
 ******************** FILE STRUCTS ************************
 **********************************************************/

typedef struct {
    slot_t slot;
    group_id_t group_id;
    char name[MAX_NAME_SIZE];
} file_metadata_t;

/**********************************************************
 ******************** COMMAND STRUCTS *********************
 **********************************************************/

typedef struct {
    pin_t pin;
} list_command_t;

typedef struct {
    pin_t pin;
    slot_t slot;
} read_command_t;

typedef struct {
    pin_t pin;
    slot_t slot;
    group_id_t group_id;
    char name[MAX_NAME_SIZE];
    uint8_t uuid[UUID_SIZE];
    uint16_t contents_len;
    uint8_t contents[MAX_CONTENTS_SIZE];
} write_command_t;

typedef struct {
    pin_t pin;
    slot_t read_slot;
    slot_t write_slot;
} receive_command_t;

typedef struct {
    slot_t slot;
    group_permission_t permissions[MAX_PERMS];
} receive_request_t;

typedef struct {
    uint8_t uuid[UUID_SIZE];
    file_t file;
} receive_response_t;

typedef struct {
    pin_t pin;
} interrogate_command_t;

/**********************************************************
 ******************** RESPONSE STRUCTS ********************
 **********************************************************/

typedef struct {
    uint32_t n_files;
    file_metadata_t metadata[MAX_FILE_COUNT];
} list_response_t;

typedef struct {
    char name[MAX_NAME_SIZE];
    uint8_t contents[MAX_CONTENTS_SIZE];
} read_response_t;

#pragma pack(pop) // Tells the compiler to resume padding struct members

/** @brief Perform the list operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int list(uint16_t pkt_len, uint8_t *buf);


/** @brief Perform the read operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int read(uint16_t pkt_len, uint8_t *buf);


/** @brief Perform the write operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int write(uint16_t pkt_len, uint8_t *buf);


/** @brief Perform the receive operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int receive(uint16_t pkt_len, uint8_t *buf);


/** @brief Perform the interrogate operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer to the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int interrogate(uint16_t pkt_len, uint8_t *buf);


/** @brief Perform the listen operation
 *
 * @return 0 upon success. A negative value on error.
*/
int listen(uint16_t pkt_len, uint8_t *buf);

#endif // __COMMANDS_H__
