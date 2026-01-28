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
import json
import argparse
import hashlib
from dataclasses import dataclass

PBKDF2_ITERATIONS = 100000


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


def _load_global_secret(secrets_blob):
    payload = json.loads(secrets_blob.decode())
    secret_hex = payload.get("global_secret")
    if not secret_hex:
        raise ValueError("Secrets file missing global_secret")
    return bytes.fromhex(secret_hex)


def _load_magic_token(secrets_blob):
    payload = json.loads(secrets_blob.decode())
    token_hex = payload.get("magic_token")
    if not token_hex:
        raise ValueError("Secrets file missing magic_token")
    return bytes.fromhex(token_hex)


def _write_c_array(f, name, data, columns=12):
    f.write(f"static const uint8_t {name}[{len(data)}] = {{\n")
    for offset in range(0, len(data), columns):
        chunk = ", ".join(f"0x{b:02x}" for b in data[offset:offset + columns])
        f.write(f"    {chunk},\n")
    f.write("};\n\n")


def secrets_to_c_header(
    permissions: PermissionList, path: str, hsm_pin: str, secrets: bytes
):

    # Wrap deployment-wide secret material with a per-board mask derived from the PIN.
    global_secret = _load_global_secret(secrets)
    magic_token = _load_magic_token(secrets)
    if len(global_secret) != 32:
        raise ValueError("global_secret must be 32 bytes")
    if len(magic_token) != 16:
        raise ValueError("magic_token must be 16 bytes")

    blob = global_secret + magic_token
    salt = os.urandom(16)
    pin_bytes = hsm_pin.encode("utf-8")
    mask = hashlib.pbkdf2_hmac(
        "sha256",
        pin_bytes,
        salt,
        PBKDF2_ITERATIONS,
        dklen=len(blob),
    )
    wrapped_blob = bytes(b ^ m for b, m in zip(blob, mask))

    with open(os.path.join(path, "secrets.h"), 'w') as f:
        f.write("#ifndef __SECRETS_H__\n")
        f.write("#define __SECRETS_H__\n\n")
        f.write('#include "security.h"\n\n')
        f.write("#define PBKDF2_ITERATIONS 100000\n\n")
        _write_c_array(f, "secrets_salt", salt)
        _write_c_array(f, "wrapped_blob", wrapped_blob)
        _write_c_array(f, "expected_magic", magic_token)
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
        parser.add_argument("hsm_pin", type=str, help="User PIN for the HSM")
        parser.add_argument("permissions", type=str, help="List of colon-separated permissions. E.g., \"1234=R--:4321=RWC\"")

        return parser.parse_args()

    args = parse_args()
    perms = PermissionList.deserialize(args.permissions)
    secrets_to_c_header(perms, './inc/', args.hsm_pin, args.secrets.read())
