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

import os
import re
import json
import argparse
import hashlib
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_WALLET_GROUPS = 8
K_TRANSIT_LEN = 32
K_STORAGE_LEN = 32
ED25519_PRIV_LEN = 32
ED25519_PUB_LEN = 32
PIN_SALT_LEN = 16
PIN_CHECK_LEN = 16
WALLET_SALT_LEN = 16
WALLET_NONCE_LEN = 12
WALLET_TAG_LEN = 16
PIN_CHECK_ITERS = 100000
WALLET_KDF_ITERS = 100000
WALLET_AAD = b"WALLETv1"
WALLET_ENTRY_LEN = 2 + 1 + 1 + K_TRANSIT_LEN + K_STORAGE_LEN + ED25519_PRIV_LEN + ED25519_PUB_LEN


@dataclass
class Permission:
    """Represents a permission for one group
    """
    group_id: int=None
    read: bool=False
    write: bool=False
    receive: bool=False

    @classmethod
    def deserialize(cls, perms: str):
        """Create a Permission object from a string

        :param perm: A string representing a permission. The permission shall be a pair
            of group ID and permissions separated by an equal sign (e.g.,
            "<group_id>=<permission>"). The group ID shall be a 16-bit hexadecimal
            number padded with 0s to be a total of 4 characters with no preceding '0x'
            (e.g., 4b1d). The permission shall be a 3-character string where present
            permissions are represented by their opcode and absent permissions are
            represented by a '-' (e.g., "RWC", "RW-", "--C").
        """
        group_id, perm_string = perms.split('=')

        perm_obj = cls(
            int(group_id, 16),
            read = perm_string[0] == 'R',
            write = perm_string[1] == 'W',
            receive = perm_string[2] == 'C',
        )
        return perm_obj

    def serialize(self):
        ret = f'{self.group_id:04x}='
        for perm, shorthand in {'read': 'R', 'write': 'W', 'receive': 'C'}.items():
            ret += shorthand if getattr(self, perm) else "-"
        return ret

class PermissionList(list):
    """Represents a set of permissions that an HSM can be built with.
    """
    def __init__(self, *args):
        for item in args:
            if isinstance(item, Permission):
                self.append(item)

    @classmethod
    def deserialize(cls, perms: str):
        """Create a list of permission objects from a string
        representation

        :param perm: A string representing the permission set. The string shall be a
            colon-separated list of permissions (e.g., "<perm1>:<perm2>:<perm3>").

        :returns: An instance of `PermissionList`
        """
        ret = cls()
        permissions_strings = perms.split(":")
        for entry in permissions_strings:
            perm_obj = Permission.deserialize(entry)
            ret.append(perm_obj)
        return ret

    def serialize(self):
        return ':'.join(perm.serialize() for perm in self)


def _load_payload(secrets_blob):
    return json.loads(secrets_blob.decode())


def _decode_hex_field(entry, field_name, expected_len):
    hex_value = entry.get(field_name)
    if not hex_value:
        return bytes(expected_len)
    value = bytes.fromhex(hex_value)
    if len(value) != expected_len:
        raise ValueError(f"{field_name} must be {expected_len} bytes")
    return value


def _write_c_array(f, name, data, columns=12):
    f.write(f"static const uint8_t {name}[{len(data)}] = {{\n")
    for offset in range(0, len(data), columns):
        chunk = ", ".join(f"0x{b:02x}" for b in data[offset:offset + columns])
        f.write(f"    {chunk},\n")
    f.write("};\n\n")


def secrets_to_c_header(
    permissions: PermissionList, path: str, hsm_pin: str, secrets: bytes
):

    if len(permissions) > MAX_WALLET_GROUPS:
        raise ValueError(f"Too many permissions entries (max {MAX_WALLET_GROUPS}).")

    payload = _load_payload(secrets)
    groups_payload = payload.get("groups", {})

    # Wallet layout per entry:
    # [u16 group_id][u8 perms][u8 reserved][k_transit][k_storage][ed25519_priv][ed25519_pub]
    wallet_plain = bytearray()
    for perm in permissions:
        group_key = f"{perm.group_id:04x}"
        entry = groups_payload.get(group_key, {})
        perms_byte = (1 if perm.read else 0) | (2 if perm.write else 0) | (4 if perm.receive else 0)
        wallet_plain.extend(perm.group_id.to_bytes(2, "little"))
        wallet_plain.append(perms_byte)
        wallet_plain.append(0x00)

        if perm.receive:
            k_transit = _decode_hex_field(entry, "k_transit", K_TRANSIT_LEN)
            ed_pub = _decode_hex_field(entry, "ed25519_pub", ED25519_PUB_LEN)
        else:
            k_transit = bytes(K_TRANSIT_LEN)
            ed_pub = bytes(ED25519_PUB_LEN)

        if perm.read or perm.write:
            k_storage = _decode_hex_field(entry, "k_storage", K_STORAGE_LEN)
        else:
            k_storage = bytes(K_STORAGE_LEN)

        if perm.write:
            ed_priv = _decode_hex_field(entry, "ed25519_priv", ED25519_PRIV_LEN)
        else:
            ed_priv = bytes(ED25519_PRIV_LEN)

        wallet_plain.extend(k_transit)
        wallet_plain.extend(k_storage)
        wallet_plain.extend(ed_priv)
        wallet_plain.extend(ed_pub)

    while len(wallet_plain) < WALLET_ENTRY_LEN * MAX_WALLET_GROUPS:
        wallet_plain.extend(bytes(WALLET_ENTRY_LEN))

    pin_bytes = hsm_pin.encode("ascii")
    pin_salt = os.urandom(PIN_SALT_LEN)
    pin_check = hashlib.pbkdf2_hmac(
        "sha256",
        pin_bytes,
        pin_salt,
        PIN_CHECK_ITERS,
        dklen=PIN_CHECK_LEN,
    )

    wallet_salt = os.urandom(WALLET_SALT_LEN)
    wallet_nonce = os.urandom(WALLET_NONCE_LEN)
    wallet_key = hashlib.pbkdf2_hmac(
        "sha256",
        pin_bytes,
        wallet_salt,
        WALLET_KDF_ITERS,
        dklen=32,
    )
    aesgcm = AESGCM(wallet_key)
    wallet_ct_with_tag = aesgcm.encrypt(wallet_nonce, bytes(wallet_plain), WALLET_AAD)
    wallet_ct = wallet_ct_with_tag[:-WALLET_TAG_LEN]
    wallet_tag = wallet_ct_with_tag[-WALLET_TAG_LEN:]

    # Self-test the wrapping path to avoid emitting an unrecoverable wallet.
    wallet_round_trip = aesgcm.decrypt(wallet_nonce, wallet_ct_with_tag, WALLET_AAD)
    if wallet_round_trip != bytes(wallet_plain):
        raise ValueError("Wallet round-trip check failed.")

    with open(os.path.join(path, "secrets.h"), 'w') as f:
        f.write("#ifndef __SECRETS_H__\n")
        f.write("#define __SECRETS_H__\n\n")
        f.write('#include "security.h"\n\n')
        f.write(f"#define PIN_SALT_LEN {PIN_SALT_LEN}\n")
        f.write(f"#define PIN_CHECK_LEN {PIN_CHECK_LEN}\n")
        f.write(f"#define PIN_CHECK_ITERS {PIN_CHECK_ITERS}\n")
        f.write(f"#define WALLET_SALT_LEN {WALLET_SALT_LEN}\n")
        f.write(f"#define WALLET_NONCE_LEN {WALLET_NONCE_LEN}\n")
        f.write(f"#define WALLET_TAG_LEN {WALLET_TAG_LEN}\n")
        f.write(f"#define WALLET_ENTRY_LEN {WALLET_ENTRY_LEN}\n")
        f.write(f"#define WALLET_GROUPS {MAX_WALLET_GROUPS}\n")
        f.write(f"#define WALLET_CT_LEN {len(wallet_ct)}\n")
        f.write(f"#define WALLET_KDF_ITERS {WALLET_KDF_ITERS}\n")
        f.write(f"#define WALLET_AAD_LEN {len(WALLET_AAD)}\n\n")
        f.write(f"#define WALLET_AAD \"{WALLET_AAD.decode('ascii')}\"\n\n")
        _write_c_array(f, "pin_salt", pin_salt)
        _write_c_array(f, "pin_check", pin_check)
        _write_c_array(f, "wallet_salt", wallet_salt)
        _write_c_array(f, "wallet_nonce", wallet_nonce)
        _write_c_array(f, "wallet_ct", wallet_ct)
        _write_c_array(f, "wallet_tag", wallet_tag)
        f.write("const static group_permission_t global_permissions[MAX_PERMS] = {\n")
        for i, perm in enumerate(permissions):
            f.write(
                (f"\t{{{hex(perm.group_id)}, {str(perm.read).lower()}, "
                 f"{str(perm.write).lower()}, {str(perm.receive).lower()}}},\n")
            )
        f.write("};\n")
        f.write("\n#endif  // __SECRETS_H__\n")

if __name__ == '__main__':
    def parse_args():
        parser = argparse.ArgumentParser()

        parser.add_argument("secrets", type=argparse.FileType("rb"), help="Path to secrets file")
        parser.add_argument("hsm_pin", nargs="?", type=str, help="User PIN for the HSM")
        parser.add_argument("permissions", nargs="?", type=str, help="List of colon-separated permissions. E.g., \"1234=R--:4321=RWC\"")

        return parser.parse_args()

    args = parse_args()
    pin_value = os.environ.get("HSM_PIN", args.hsm_pin)
    perms_value = os.environ.get("PERMISSIONS", args.permissions)
    if not pin_value or not perms_value:
        raise ValueError("HSM_PIN and PERMISSIONS are required.")
    if not re.fullmatch(r"[0-9a-f]{6}", pin_value):
        raise ValueError("HSM_PIN must be 6 lowercase hex characters.")
    perms = PermissionList.deserialize(perms_value)
    secrets_to_c_header(perms, './inc/', pin_value, args.secrets.read())
