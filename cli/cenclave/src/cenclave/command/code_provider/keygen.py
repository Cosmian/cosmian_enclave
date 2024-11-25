"""cenclave.command.code_provider.keygen module."""

import base64
from pathlib import Path

from cenclave_lib_crypto.x25519 import x25519_keygen
from cenclave_lib_crypto.xsalsa20_poly1305 import random_key

from cenclave.log import LOGGER as LOG


def add_subparser(subparsers):
    """Define the subcommand."""
    parser = subparsers.add_parser(
        "keygen", help="key generation for symmetric or asymmetric cryptography"
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "--symmetric",
        action="store_true",
        help="generate a symmetric key for XSalsa20-Poly1305",
    )

    group.add_argument(
        "--asymmetric",
        action="store_true",
        help="generate an asymmetric keypair on Curve25519",
    )

    parser.add_argument(
        "--output",
        type=Path,
        metavar="FILE",
        help="path to write the generated key(s)",
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite if output file exists",
    )

    parser.set_defaults(func=run)


def run(args) -> None:
    """Run the subcommand."""
    output_path: Path = Path(args.output).resolve()

    if output_path.exists() and not args.force:
        raise FileExistsError(f"{output_path} already exists")

    if args.symmetric:
        output_path.write_bytes(random_key())
        LOG.info("Symmetric key wrote to %s", output_path)
    else:  # args.asymmetric
        pk, sk = x25519_keygen()
        LOG.info("Public key: %s", pk.hex())
        LOG.info("Public key (Base64): %s", base64.b64encode(pk).decode("utf-8"))

        output_path.write_bytes(pk + sk)
        LOG.info("Keypair wrote to %s", output_path)
