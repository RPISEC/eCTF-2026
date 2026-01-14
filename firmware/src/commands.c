/**
 * @file commands.c
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

#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"

/* IMPORTANT COMPONENTS FROM HSM.c */
// extern file_t hsm_status[MAX_FILE_COUNT];
static file_t current_file;

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

/** @brief List out the files on the system.
 *      To be utilized by list and interrogate
 *
 *  @param file_list A pointer to the list_response_t variable in
 *      which to store the results
 */
void generate_list_files(list_response_t *file_list) {
    file_list->n_files = 0;
    file_t temp_file;

    // Loop through all files on the system
    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++) {
        // Check if the file is in use
        if (is_slot_in_use(i)) {
            read_file(i, &temp_file);

            file_list->metadata[file_list->n_files].slot = i;
            file_list->metadata[file_list->n_files].group_id = temp_file.group_id;
            strcpy(file_list->metadata[file_list->n_files].name, (char *)&temp_file.name);
            file_list->n_files++;
        }
    }
}


/**********************************************************
 ******************** COMMAND HANDLERS ********************
 **********************************************************/

/** @brief Perform the list operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int list(uint16_t pkt_len, uint8_t *buf) {
    list_command_t *command = (list_command_t*)buf;
    list_response_t file_list;

    memset(&file_list, 0, sizeof(file_list));

    // copy relevant fields into the final struct
    generate_list_files(&file_list);

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // write success packet with list
    pkt_len_t length = LIST_PKT_LEN(file_list.n_files);
    write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, length);
    return 0;
}


/** @brief Perform the read operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int read(uint16_t pkt_len, uint8_t *buf) {
    read_command_t *command = (read_command_t*)buf;
    read_response_t file_info;
    file_t curr_file;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // zeroizing memory is a pretty good practice
    memset(&file_info, 0, sizeof(read_response_t));

    if (read_file(command->slot, &curr_file) < 0) {
        print_error("Failed to read file");
        return -1;
    }
    // copy structure of the persistent file
    memcpy(file_info.name, &curr_file.name, strlen(curr_file.name));
    memcpy(file_info.contents, &curr_file.contents, curr_file.contents_len);

    if (!validate_permission(curr_file.group_id, PERM_READ)) {
        print_error("Invalid permission");
        return -1;
    }

    // write a success message with the file information
    pkt_len_t length = MAX_NAME_SIZE + curr_file.contents_len;
    write_packet(CONTROL_INTERFACE, READ_MSG, &file_info, length);
    return 0;
}


/** @brief Perform the write operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int write(uint16_t pkt_len, uint8_t *buf) {
    write_command_t *command = (write_command_t*)buf;
    int ret;
    file_t curr_file;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    if (!validate_permission(command->group_id, PERM_WRITE)) {
        print_error("Invalid permission");
        return -1;
    }

    create_file(
        &curr_file,
        command->group_id,
        command->name,
        command->contents_len,
        command->contents
    );

    // Store the file persistently
    if (write_file(command->slot, &curr_file, command->uuid) < 0) {
        print_error("Error storing file");
        return -1;
    }

    // Success message with an empty body
    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    return 0;
}


/** @brief Perform the receive operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int receive(uint16_t pkt_len, uint8_t *buf) {
    receive_command_t *command = (receive_command_t *)buf;
    receive_request_t request;
    receive_response_t recv_resp;
    msg_type_t cmd;
    uint16_t len_recv_msg;
    int ret;

    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // zeroize the buffers we will use
    memset(&recv_resp, 0, sizeof(recv_resp));
    memset(&request, 0, sizeof(request));

    // prep request to neighbor
    request.slot = command->read_slot;
    memcpy(&request.permissions, &global_permissions, sizeof(group_permission_t) * MAX_PERMS);

    // request the file from the neighboring device
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&request, sizeof(receive_request_t));

    // set essentially no limit to the receive message size
    len_recv_msg = 0xffff;

    // recieve the response message
    read_packet(TRANSFER_INTERFACE, &cmd, &recv_resp, &len_recv_msg);
    if (cmd != RECEIVE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }

    // write that file into the file system
    if (write_file(command->write_slot, &recv_resp.file, recv_resp.uuid) < 0) {
        print_error("Writing received file failed");
        return -1;
    }
    // empty success message
    write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);
    return 0;
}


/** @brief Perform the interrogate operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer to the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
 */
int interrogate(uint16_t pkt_len, uint8_t *buf) {
    interrogate_command_t *command = (interrogate_command_t*)buf;
    msg_type_t cmd;
    list_response_t final_list_buf;
    uint16_t len_recv_msg;

    // pin check
    if (!check_pin(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    // request the file list from the neighboring device
    write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, NULL, 0);

    // set essentially no limit to the receive message size
    len_recv_msg = 0xffff;

    // recieve the response message
    read_packet(TRANSFER_INTERFACE, &cmd, &final_list_buf, &len_recv_msg);
    if (cmd != INTERROGATE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }

    // return the final list to the user
    write_packet(CONTROL_INTERFACE, INTERROGATE_MSG, &final_list_buf, len_recv_msg);
    return 0;
}


/** @brief Perform the listen operation
 *
 * @return 0 upon success. A negative value on error.
*/
int listen(uint16_t pkt_len, uint8_t *buf) {
    uint8_t uart_buf[sizeof(receive_request_t)];
    msg_type_t cmd;
    pkt_len_t write_length, read_length;
    list_response_t file_list;
    receive_request_t *command;
    receive_response_t recv_resp;
    const filesystem_entry_t *metadata;

    read_length = sizeof(uart_buf);

    // Receive a packet from a neighboring hsm
    memset(uart_buf, 0, sizeof(uart_buf));
    read_packet(TRANSFER_INTERFACE, &cmd, uart_buf, &read_length);

    switch (cmd) {
        case INTERROGATE_MSG:
            // zeroize the buffers we will use
            memset(&file_list, 0, sizeof(file_list));

            // generate a list of files for the other device
            generate_list_files(&file_list);

            // TODO: the reference design does not implement *ANY* security
            // you will want to add something here to comply with SR1

            // send the list of files on this device
            write_length = LIST_PKT_LEN(file_list.n_files);
            write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &file_list, write_length);
            break;
        case RECEIVE_MSG:
            // get the request
            command = (receive_request_t *)uart_buf;

            // TODO: the reference design does not implement *ANY* security
            // you will want to add something here to comply with SR1

            // if this read fails, the other device will not receive a response and
            // may need to be reset before further testing can occur
            if (read_file(command->slot, &recv_resp.file) < 0) {
                print_error("Failed to read file");
                return -1;
            }

            metadata = get_file_metadata(command->slot);
            if (metadata == NULL) {
                print_error("Getting metadata failed");
                return -1;
            }

            memcpy(&recv_resp.uuid, &metadata->uuid, UUID_SIZE);

            // send the file to the neighbor hsm
            write_length = sizeof(receive_response_t);
            write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &recv_resp, write_length);
            break;
        default:
            print_error("Bad message type");
            return -1;
    }

    // blank success message
    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}
