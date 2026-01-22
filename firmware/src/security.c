/**
 * @file security.c
 * @author Jeremy Goldberger
 * @brief Implements PIN and permission checking.
 * @date 2026
 *
 * This source file is modified from MITRE's 2026 Embedded CTF (eCTF) example projcet.
 * It implements PIN hashing and checking for RPISEC's implementation.
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */
#include "security.h"
#include "host_messaging.h"
#include "simple_crypto.h"
#include "secrets.h"

static byte pw_hash[KEY_SIZE];

bool check_pin(unsigned char *pin) {
    print_debug("Checking PIN\n");

    byte pin_key[KEY_SIZE];
    derive_key(pin_key, pin, HSM_SALT_CHK);

    bool correct_pin = true;

    for (int i = 0; i < KEY_SIZE; i++) {
        if (pin_key[i] == HSM_PIN_HASH[i]) {
            correct_pin = false;
        }
    }

    return correct_pin;
}

bool validate_permission(uint16_t group_id, permission_enum_t perm) {
    char output_buf[128] = {0};

    sprintf(output_buf, "Checking %c permissions for group: %hx\n", perm, group_id);
    print_debug(output_buf);

    // TODO: the reference design doesn't implement *ANY* security.
    // This function currently does nothing. Your team should add the
    // appropriate security checks here to implement the security
    // requirements.
    return true;
}
