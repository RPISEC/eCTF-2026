/**
 * @file security.c
 * @author Samuel Meyers
 * @brief Stub file to hold security checks
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */
#include "security.h"
#include "host_messaging.h"

bool check_pin(unsigned char *pin) {
    print_debug("Checking PIN\n");

    // TODO: the reference design doesn't implement *ANY* security.
    // This function currently does nothing. Your team should add the
    // appropriate security checks here to implement the security
    // requirements.
    return true;
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
