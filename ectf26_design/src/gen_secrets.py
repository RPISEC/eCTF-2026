"""
Author: Ben Janis
Date: 2026
Modified By: Jaden

This source file is part of an example system for MITRE's 2026 Embedded CTF
(eCTF). This code is being provided only for educational purposes for the 2026 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2026 The MITRE Corporation
"""

import argparse
import json
import secrets
from pathlib import Path

from loguru import logger
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def gen_secrets(groups: list[int]) -> bytes:
    """Generate the contents secrets file

    This will be passed to the Encoder, ectf26_design.gen_secrets,
    and the build process of the firmware

    NOTE: you should NOT write to secrets files within this function.
    All generated secrets must be contained in the returned bytes
    object.

    :param groups: List of permission groups that will be valid in this
        deployment.

    :returns: Contents of the secrets file
    """
    # Deployment-wide secrets for all groups. This file never ships on a device.
    secrets_data = {
        "format": "ectf26-global-secrets",
        "groups": {},
    }

    for group_id in groups:
        c_private = ec.generate_private_key(ec.SECP256R1())
        c_public = c_private.public_key()
        w_private = ec.generate_private_key(ec.SECP256R1())
        w_public = w_private.public_key()
        k_storage = secrets.token_bytes(32)

        c_priv_raw = c_private.private_numbers().private_value.to_bytes(32, "big")
        c_pub_raw = c_public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )
        w_priv_raw = w_private.private_numbers().private_value.to_bytes(32, "big")
        w_pub_raw = w_public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )

        if len(k_storage) != 32:
            raise ValueError("k_storage must be 32 bytes")
        if len(c_priv_raw) != 32 or len(w_priv_raw) != 32:
            raise ValueError("*_priv ECC keys must be 32 bytes")
        if len(c_pub_raw) != 33 or len(w_pub_raw) != 33:
            raise ValueError("*_pub ECC keys must be 33 bytes")

        secrets_data["groups"][f"{group_id:04x}"] = {
            "k_storage": k_storage.hex(),
            "c_priv": c_priv_raw.hex(),
            "c_pub": c_pub_raw.hex(),
            "w_priv": w_priv_raw.hex(),
            "w_pub": w_pub_raw.hex(),
        }

    # NOTE: if you choose to use JSON for your file type, you will not
    # be able to store binary data, and must either use a different file
    # type or encode the binary data to hex, base64, or another type of
    # ASCII-only encoding
    return json.dumps(secrets_data).encode()


def parse_args():
    """Define and parse the command line arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "groups",
        nargs="+",
        type=lambda x: int(x, 0),
        help="Supported group IDs",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets

    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    secrets_blob = gen_secrets(args.groups)

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets_blob)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()
