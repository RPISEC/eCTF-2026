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

#include "commands.h"
#include "filesystem.h"
#include "host_messaging.h"
#include "simple_crypto.h"
#include "simple_trng.h"
#include "wallet.h"

#include <wolfssl/wolfcrypt/curve25519.h>


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
    file_headers_t temp_headers;

    // Loop through all files on the system
    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++) {
        // Check if the file is in use
        if (is_slot_in_use(i)) {
            get_file_headers(i, &temp_headers);

            file_list->metadata[file_list->n_files].slot = i;
            file_list->metadata[file_list->n_files].group_id = temp_headers.group_id;
            strcpy(file_list->metadata[file_list->n_files].name, (char *)&temp_headers.name);
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
    static list_response_t file_list;

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
    file_t *curr_file;
    key32_t k_storage, w_pub;
    int ret;

    if (wallet_unlock(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    curr_file = malloc(sizeof(file_t));
    if (curr_file == NULL) {
        print_error("Insufficient memory for file");
        return -2;
    }

    get_file_headers(command->slot, &curr_file->headers);

    if (!wallet_has_perms(curr_file->headers.group_id, PERM_R)) {
        print_error("Invalid permission");
        free(curr_file);
        return -3;
    }

    ret = get_w_pub(&w_pub, curr_file->headers.group_id);
    ret = get_k_storage(&k_storage, curr_file->headers.group_id);
    if (ret < 0) {
        print_error("Invalid key");
        free(curr_file);
        return -4;
    }

    wallet_lock();

    ret = read_file(command->slot, curr_file);
    if (ret < 0) {
        print_error("Failed to read file");
        free(curr_file);
        return -5;
    }

    ret = verify_file(curr_file, w_pub);
    if (ret < 0) {
        print_error("Failed to verify file");
        free(curr_file);
        return -6;
    }

    ret = decrypt_file(curr_file, k_storage);
    if (ret < 0) {
        print_error("Failed to decrypt file");
        free(curr_file);
        return -7;
    }

    memset(k_storage, 0, AES_KEY_SIZE);


    /* To save memory, we re-use the space for curr_file to store the packet.
     * This is safe as long as the packet struct matches a contiguous section of
     * the file struct. */
    const read_response_t *file_info = (read_response_t *)&curr_file->headers.name;
    pkt_len_t length = MAX_NAME_SIZE + curr_file->headers.contents_len;

    // write a success message with the file information
    write_packet(CONTROL_INTERFACE, READ_MSG, file_info, length);

    free(curr_file);
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
    file_t *curr_file;
    key32_t k_storage, w_priv, w_pub;

    if (wallet_unlock(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    /* get functions already check permissions */
    ret = get_w_priv(&w_priv, command->group_id);
    if (ret < 0) {
        print_error("Invalid permission");
    }

    ret = get_w_pub(&w_pub, command->group_id);

    ret = get_k_storage(&k_storage, command->group_id);
    if (ret < 0) {
        print_error("Invalid permission");
    }

    wallet_lock();

    curr_file = malloc(sizeof(file_t));
    if (curr_file == NULL) {
        print_error("Insufficient memory for file");
        return -1;
    }

    create_file(
        curr_file,
        command->group_id,
        command->name,
        command->contents_len,
        command->contents
    );

    if (encrypt_file(curr_file, k_storage) < 0) {
        print_error("Error encrypting file");
        free(curr_file);
        return -1;
    }

    if (sign_file(curr_file, w_priv, w_pub) < 0) {
        print_error("Error signing file");
        free(curr_file);
        return -2;
    }

    // Store the file persistently
    if (write_file(command->slot, curr_file, command->uuid) < 0) {
        print_error("Error storing file");
        free(curr_file);
        return -3;
    }

    memset(k_storage, 0, sizeof(key32_t));
    memset(w_priv, 0, sizeof(key32_t));

    // Success message with an empty body
    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    free(curr_file);
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
    // A side of connection
    receive_command_t *command = (receive_command_t *)buf;
    receive_request_t request;
    receive_response_t *recv_resp;
    msg_type_t cmd;
    uint16_t len_recv_msg;
    int ret;

    if (wallet_unlock(command->pin)) {
        print_error("Invalid pin");
        return -1;
    }

    memset(&request, 0, sizeof(request));

    // prep request to neighbor
    request.slot = command->read_slot;

    print_debug("Sending request");
    // request the file from the neighboring device
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&request, sizeof(receive_request_t));

    print_debug("Sent request");

    curve25519_key a_priv, b_pub;
    wc_curve25519_init(&a_priv);
    WC_RNG rng;
    wc_InitRng(&rng);

    ret = wc_curve25519_make_key(&rng, 32, &a_priv);
    if (ret != 0) {
        print_error("keygen failed");
        return -2;
    }

    print_debug("Generated keypair");

    receive_challenge_t chal_ctx;
    len_recv_msg = sizeof(chal_ctx);
    read_packet(TRANSFER_INTERFACE, &cmd, &chal_ctx, &len_recv_msg);
    if (cmd != RECEIVE_MSG) {
        print_error("Opcode mismatch");
        return -3;
    }
    if (chal_ctx.slot != request.slot) {
        print_error("Slot changed unexpectedly");
        return -4;
    }

    print_debug("Received challenge");

    uint32_t keysize = 32;
    wc_curve25519_export_public(&a_priv, chal_ctx.a_pub, &keysize);

    key32_t c_priv, c_pub;
    ret = get_c_pub(&c_pub, chal_ctx.group_id);
    ret = get_c_priv(&c_priv, chal_ctx.group_id);
    if (ret < 0) {
        print_error("Could not get receive key.");
        return -5;
    }

    sign_msg((uint8_t *)&chal_ctx, sizeof(chal_ctx) - 64, chal_ctx.signature, c_priv, c_pub);

    print_debug("Signed challenge");
    print_hex_debug(&chal_ctx, sizeof(chal_ctx));
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &chal_ctx, sizeof(chal_ctx));

    ret = wc_curve25519_import_public(chal_ctx.b_pub, 32, &b_pub);

    key32_t shared_key;
    uint32_t shared_size = 32;
    ret = wc_curve25519_shared_secret(&a_priv, &b_pub, shared_key, &shared_size);
    if (ret != 0 || shared_size != 32) {
        print_error("Shared key failed");
        return -6;
    }

    print_debug("Generated shared key");
    print_hex_debug(&shared_key, shared_size);

    // receive the response message
    //
    recv_resp = malloc(sizeof(*recv_resp));
    if (recv_resp == NULL) {
        print_error("Insufficient space to store recv_resp");
        return -7;
    }

    memset(recv_resp, 0, sizeof(*recv_resp));

    len_recv_msg = sizeof(*recv_resp);
    read_packet(TRANSFER_INTERFACE, &cmd, recv_resp, &len_recv_msg);
    if (cmd != RECEIVE_MSG) {
        free(recv_resp);
        print_error("Opcode mismatch");
        return -8;
    }

    print_debug("Received file packet");

    ret = decrypt_sym(recv_resp->uuid, UUID_SIZE + sizeof(file_t),
                shared_key, recv_resp->iv, recv_resp->auth_tag, NULL, 0,
                recv_resp->uuid);
    if (ret < 0) {
        free(recv_resp);
        print_error("Failed to decrypt received data");
        return -9;
    }

    print_debug("Decrypted packet");

    key32_t w_pub;
    ret = get_w_pub(&w_pub, chal_ctx.group_id);
    ret = verify_file(&recv_resp->file, w_pub);
    if (ret < 0) {
        free(recv_resp);
        print_error("Failed to verify file signature");
        return -10;
    }

    print_debug("Verified file");

    // write that file into the file system
    if (write_file(command->write_slot, &recv_resp->file, recv_resp->uuid) < 0) {
        free(recv_resp);
        print_error("Writing received file failed");
        return -11;
    }

    print_debug("Wrote file");

    // empty success message
    write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);

    free(recv_resp);
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

    // receive the response message
    read_packet(TRANSFER_INTERFACE, &cmd, &final_list_buf, &len_recv_msg);
    if (cmd != INTERROGATE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }

    // return the final list to the user
    write_packet(CONTROL_INTERFACE, INTERROGATE_MSG, &final_list_buf, len_recv_msg);
    return 0;
}

static int handle_receive(receive_request_t *recv_req) {
    // B side of connection
    msg_type_t cmd;
    pkt_len_t write_length, read_length;
    receive_challenge_t chal_ctx;
    const filesystem_entry_t *metadata;
    int ret;
    uint16_t len_recv_msg;

    print_debug("Received request");

    memset(&chal_ctx, 0, sizeof(chal_ctx));

    // Verify slot
    ret = is_slot_in_use(recv_req->slot);
    if (!ret) {
        // file does not exist or bad slot received
        chal_ctx.slot = -1;
        write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&chal_ctx, sizeof(chal_ctx));

        print_error("Bad slot requested");
        return -1;
    }
    chal_ctx.slot = recv_req->slot;

    print_debug("set slot");

    // Get group id
    file_headers_t temp_file_headers;
    ret = get_file_headers(recv_req->slot, &temp_file_headers);
    if (ret < 0) {
        chal_ctx.slot = -1;
        write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&chal_ctx, sizeof(chal_ctx));

        print_error("Bad file");
        return -2;
    }
    chal_ctx.group_id = temp_file_headers.group_id;

    print_debug("set group id");
    // Generate nonce
    uint32_t nonce = trng_get_u32();
    if (nonce == 0) {
        chal_ctx.slot = -1;
        write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&chal_ctx, sizeof(chal_ctx));

        print_error("RNG failed");
        return -3;
    }
    chal_ctx.nonce = nonce;

    print_debug("set nonce");
    // Generate key pair
    curve25519_key b_priv, a_pub;
    wc_curve25519_init(&b_priv);
    WC_RNG rng;
    wc_InitRng(&rng);

    ret = wc_curve25519_make_key(&rng, 32, &b_priv);
    if (ret != 0) {
        chal_ctx.slot = -1;
        write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&chal_ctx, sizeof(chal_ctx));

        print_error("Keygen failed");
        return -4;
    }
    uint32_t keysize = 32;
    wc_curve25519_export_public(&b_priv, chal_ctx.b_pub, &keysize);

    print_debug("set key");
    // Respond to initial request
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&chal_ctx, sizeof(chal_ctx));

    print_debug("sent challenge");
    read_packet(TRANSFER_INTERFACE, &cmd, &chal_ctx, &len_recv_msg);
    if (cmd != RECEIVE_MSG) {
        print_error("Opcode mismatch");
        return -5;
    }
    if (chal_ctx.slot != recv_req->slot || chal_ctx.group_id != temp_file_headers.group_id || chal_ctx.nonce != nonce) {
        print_error("Mismatch in received data.");
        return -6;
    }

    print_debug("received challenge response");
    // Verify challenge signature
    key32_t c_pub;
    ret = get_c_pub(&c_pub, chal_ctx.group_id);
    ret = verify_msg((uint8_t *)&chal_ctx, sizeof(chal_ctx) - 64,
                    chal_ctx.signature, c_pub);
    print_hex_debug(&chal_ctx, sizeof(chal_ctx));
    if (ret < 0) {
        print_hex_debug(&ret, sizeof(ret));
        print_error("Invalid signature received");
        return -7;
    }

    print_debug("verified signature");
    // Derive shared secret
    ret = wc_curve25519_import_public(chal_ctx.a_pub, 32, &a_pub);
    if (ret < 0) {
        print_error("Failed to import public key");
        return -8;
    }

    key32_t shared_key;
    uint32_t shared_size = 32;
    ret = wc_curve25519_shared_secret(&b_priv, &a_pub, shared_key, &shared_size);
    if (ret != 0 || shared_size != 32) {
        print_hex_debug(&ret, sizeof(ret));
        print_error("Shared key failed");
        return -9;
    }

    print_debug("derived shared key");
    print_hex_debug(&shared_key, shared_size);

    // Read file into response, encrypt response
    receive_response_t *recv_resp = malloc(sizeof(receive_response_t));
    if (recv_resp == NULL) {
        print_error("Insufficient memory for receive response");
        return -10;
    }

    for (int i = 0; i < AES_IV_SIZE / 4; i++) {
        uint32_t rand = trng_get_u32();
        if (rand == 0) {
            print_error("TRNG failed");
            free(recv_resp);
            return -11;
        }
        memcpy(&recv_resp->iv[i * 4], &rand, 4);
    }

    metadata = get_file_metadata(recv_req->slot);
    if (metadata == NULL) {
        print_error("Getting metadata failed");
        free(recv_resp);
        return -12;
    }

    memcpy(&recv_resp->uuid, &metadata->uuid, UUID_SIZE);

    if (read_file(recv_req->slot, &recv_resp->file) < 0) {
        print_error("Failed to read file");
        free(recv_resp);
        return -13;
    }

    print_debug("Read file");
    ret = encrypt_sym(recv_resp->uuid, UUID_SIZE + sizeof(file_t), shared_key,
                      recv_resp->iv, recv_resp->auth_tag, NULL, 0,
                      recv_resp->uuid);
    if (ret < 0) {
        print_error("Failed to encrypt response");
        free(recv_resp);
        return -14;
    }

    print_debug("Encrypted file packet");
    // Send response
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, recv_resp, sizeof(*recv_resp));

    print_debug("Sent file packet");

    free(recv_resp);
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
    int ret;

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
            ret = handle_receive((receive_request_t *)uart_buf);
            if (ret < 0)
                return ret;
            break;
        default:
            print_error("Bad message type");
            return -1;
    }

    // blank success message
    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}

