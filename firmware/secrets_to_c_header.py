"""
Author: Samuel Meyers
Date: 2026
Modified By: Jaden

This source file is part of an example system for MITRE's 2026 Embedded CTF
(eCTF). This code is being provided only for educational purposes for the 2026 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2026 The MITRE Corporation
"""

import argparse
import hashlib
import json
import os
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_NUM_GROUPS = 8
PERM_R = 0x01
PERM_W = 0x02
PERM_C = 0x04

KEY32_LEN = 32
PIN_SALT_LEN = 16
KS_IV_LEN = 12
KS_TAG_LEN = 16
WALLET_ITERS = 10

CLEAR_STORAGE_LEN = (MAX_NUM_GROUPS * 2) + MAX_NUM_GROUPS + (MAX_NUM_GROUPS * KEY32_LEN) + (MAX_NUM_GROUPS * KEY32_LEN)
KEYSTORE_LEN = (MAX_NUM_GROUPS * KEY32_LEN) * 3
KS_CT_LEN = KEYSTORE_LEN
WALLET_FLASH_LEN = CLEAR_STORAGE_LEN + PIN_SALT_LEN + KS_IV_LEN + KS_CT_LEN + KS_TAG_LEN


def _parse_permissions(perm_string):
    if not perm_string:
        raise ValueError("PERMISSIONS must be provided.")
    entries = perm_string.split(":")
    if len(entries) > MAX_NUM_GROUPS:
        raise ValueError(f"Too many permissions entries (max {MAX_NUM_GROUPS}).")

    parsed = []
    for entry in entries:
        if entry.count("=") != 1:
            raise ValueError(f"Invalid permission entry '{entry}'.")
        group_str, perms = entry.split("=")
        if not re.fullmatch(r"[0-9a-fA-F]{4}", group_str):
            raise ValueError(f"Invalid group id '{group_str}'.")
        if len(perms) != 3:
            raise ValueError(f"Invalid permissions '{perms}'.")

        mask = 0
        if perms[0] == "R":
            mask |= PERM_R
        elif perms[0] != "-":
            raise ValueError(f"Invalid read flag in '{perms}'.")
        if perms[1] == "W":
            mask |= PERM_W
        elif perms[1] != "-":
            raise ValueError(f"Invalid write flag in '{perms}'.")
        if perms[2] == "C":
            mask |= PERM_C
        elif perms[2] != "-":
            raise ValueError(f"Invalid receive flag in '{perms}'.")

        group_id = int(group_str, 16)
        parsed.append(
            {
                "group_id": group_id,
                "group_key": f"{group_id:04x}",
                "perms": mask,
            }
        )

    return parsed


def _load_payload(secrets_blob):
    payload = json.loads(secrets_blob.decode())
    if payload.get("format") != "ectf26-global-secrets":
        raise ValueError("Invalid secrets format.")
    groups = payload.get("groups")
    if not isinstance(groups, dict):
        raise ValueError("Secrets file missing groups.")
    return groups


def _decode_required(entry, field_name, group_key):
    if field_name not in entry:
        raise ValueError(f"Missing {field_name} for group {group_key}")
    value = bytes.fromhex(entry[field_name])
    if len(value) != KEY32_LEN:
        raise ValueError(f"{field_name} must be {KEY32_LEN} bytes for group {group_key}")
    return value


def _build_clear_storage(permission_entries, groups_payload):
    group_ids = [0] * MAX_NUM_GROUPS
    perms = [0] * MAX_NUM_GROUPS
    w_pub = [bytes(KEY32_LEN) for _ in range(MAX_NUM_GROUPS)]
    c_pub = [bytes(KEY32_LEN) for _ in range(MAX_NUM_GROUPS)]

    for idx, entry in enumerate(permission_entries):
        group_key = entry["group_key"]
        group_data = groups_payload.get(group_key)
        if group_data is None:
            raise ValueError(f"Missing group {group_key} in secrets file")

        group_ids[idx] = entry["group_id"]
        perms[idx] = entry["perms"]
        w_pub[idx] = _decode_required(group_data, "w_pub", group_key)
        c_pub[idx] = _decode_required(group_data, "c_pub", group_key)

    clear_bytes = bytearray()
    # clear_storage layout:
    # [group_id[MAX_NUM_GROUPS]:u16 LE][perms[MAX_NUM_GROUPS]:u8][w_pub][c_pub]
    for group_id in group_ids:
        clear_bytes.extend(group_id.to_bytes(2, "little"))
    clear_bytes.extend(bytes(perms))
    for key in w_pub:
        clear_bytes.extend(key)
    for key in c_pub:
        clear_bytes.extend(key)

    if len(clear_bytes) != CLEAR_STORAGE_LEN:
        raise ValueError("Clear storage length mismatch.")
    return bytes(clear_bytes)


def _build_keystore(permission_entries, groups_payload):
    k_storage = [bytes(KEY32_LEN) for _ in range(MAX_NUM_GROUPS)]
    w_priv = [bytes(KEY32_LEN) for _ in range(MAX_NUM_GROUPS)]
    c_priv = [bytes(KEY32_LEN) for _ in range(MAX_NUM_GROUPS)]

    for idx, entry in enumerate(permission_entries):
        group_key = entry["group_key"]
        group_data = groups_payload.get(group_key)
        if group_data is None:
            raise ValueError(f"Missing group {group_key} in secrets file")

        perms = entry["perms"]
        if perms & (PERM_R | PERM_W):
            k_storage[idx] = _decode_required(group_data, "k_storage", group_key)
        if perms & PERM_W:
            w_priv[idx] = _decode_required(group_data, "w_priv", group_key)
        if perms & PERM_C:
            c_priv[idx] = _decode_required(group_data, "c_priv", group_key)

    keystore = bytearray()
    for key in k_storage:
        keystore.extend(key)
    for key in w_priv:
        keystore.extend(key)
    for key in c_priv:
        keystore.extend(key)

    if len(keystore) != KEYSTORE_LEN:
        raise ValueError("Keystore length mismatch.")
    return bytes(keystore)


def _write_c_array(f, name, data, columns=12):
    f.write(f"static const uint8_t {name}[{len(data)}] = {{\n")
    for offset in range(0, len(data), columns):
        chunk = ", ".join(f"0x{b:02x}" for b in data[offset:offset + columns])
        f.write(f"    {chunk},\n")
    f.write("};\n")


def secrets_to_c_header(path, hsm_pin, permissions, secrets_blob):
    if not re.fullmatch(r"[0-9a-f]{6}", hsm_pin):
        raise ValueError("HSM_PIN must be 6 lowercase hex characters.")

    permission_entries = _parse_permissions(permissions)
    groups_payload = _load_payload(secrets_blob)

    clear_storage = _build_clear_storage(permission_entries, groups_payload)
    keystore = _build_keystore(permission_entries, groups_payload)

    pin_salt = os.urandom(PIN_SALT_LEN)
    ks_iv = os.urandom(KS_IV_LEN)
    pin_bytes = hsm_pin.encode("ascii")
    pin_hash = hashlib.pbkdf2_hmac("sha256", pin_bytes, pin_salt, WALLET_ITERS, dklen=KEY32_LEN)

    aesgcm = AESGCM(pin_hash)
    ct_with_tag = aesgcm.encrypt(ks_iv, keystore, clear_storage)
    ks_ct = ct_with_tag[:-KS_TAG_LEN]
    ks_tag = ct_with_tag[-KS_TAG_LEN:]

    round_trip = aesgcm.decrypt(ks_iv, ct_with_tag, clear_storage)
    if round_trip != keystore:
        raise ValueError("Wallet round-trip check failed.")

    wallet_flash = clear_storage + pin_salt + ks_iv + ks_ct + ks_tag
    if len(wallet_flash) != WALLET_FLASH_LEN:
        raise ValueError("Wallet flash length mismatch.")

    with open(os.path.join(path, "secrets.h"), "w") as f:
        f.write("#ifndef __SECRETS__\n")
        f.write("#define __SECRETS__\n")
        f.write("#include <stdint.h>\n")
        f.write(f"#define MAX_NUM_GROUPS {MAX_NUM_GROUPS}\n")
        f.write(f"#define PROVISIONED_NUM_GROUPS {len(permission_entries)}\n")
        f.write(f"#define PIN_SALT_LEN {PIN_SALT_LEN}\n")
        f.write(f"#define KS_IV_LEN {KS_IV_LEN}\n")
        f.write(f"#define KS_TAG_LEN {KS_TAG_LEN}\n")
        f.write(f"#define WALLET_ITERS {WALLET_ITERS}\n")
        f.write(f"#define CLEAR_STORAGE_LEN {CLEAR_STORAGE_LEN}\n")
        f.write(f"#define KEYSTORE_LEN {KEYSTORE_LEN}\n")
        f.write(f"#define KS_CT_LEN {KS_CT_LEN}\n")
        f.write(f"#define WALLET_FLASH_LEN {WALLET_FLASH_LEN}\n\n")
        _write_c_array(f, "wallet_flash", wallet_flash)
        f.write("\n#endif  // __SECRETS__\n")
        f.write("\n")


def _parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("secrets", type=argparse.FileType("rb"), help="Path to secrets file")
    parser.add_argument("hsm_pin", nargs="?", type=str, help="User PIN for the HSM")
    parser.add_argument("permissions", nargs="?", type=str, help="List of permissions (e.g. 1234=R--:4321=RWC)")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    pin_value = os.environ.get("HSM_PIN", args.hsm_pin)
    perms_value = os.environ.get("PERMISSIONS", args.permissions)
    if not pin_value or not perms_value:
        raise ValueError("HSM_PIN and PERMISSIONS are required.")
    secrets_to_c_header("./inc/", pin_value, perms_value, args.secrets.read())
