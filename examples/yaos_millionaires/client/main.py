"""Simple Python client for Yao's Millionaires with Cosmian Enclave.

```console
$ pip install requests intel-sgx-ra cenclave-lib-crypto
$ python main.py --help
usage: Client for Yao's Millionaires in Cosmian Enclave

positional arguments:
  url             URL of the remote enclave

options:
  -h, --help      show this help message and exit
  --reset         Remove participant's data from the computation
  --verify        Verify the enclave by doing the remote attestation
  --list          List participant's public key
  --push NUMBER   Push your wealth as number for the computation
  --result        Get result of the computation
  --keypair PATH  Path of the public/private keypair
  --debug         Debug information to stdout
```

"""

import argparse
import base64
import logging
import struct
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import requests
from cenclave_lib_crypto.seal_box import seal, unseal
from intel_sgx_ra.maa.attest import verify_quote
from intel_sgx_ra.quote import Quote
from intel_sgx_ra.ratls import get_server_certificate, ratls_verify_from_url, url_parse


def reset(session: requests.Session, url: str) -> None:
    response: requests.Response = session.delete(url)

    if response.status_code != 200:
        raise Exception(f"Bad response: {response.status_code}")


def push(
    session: requests.Session,
    url: str,
    pk: bytes,
    n: Union[int, float],
    enclave_pk: Optional[bytes] = None,
) -> None:
    encoded_n: bytes = struct.pack("<d", float(n))

    if enclave_pk is not None:
        encrypted_n: bytes = seal(encoded_n, enclave_pk)
        data = {
            "encrypted": True,
            "n": base64.b64encode(encrypted_n).decode("utf-8"),
        }
    else:
        data = {"encrypted": False, "n": base64.b64encode(encoded_n).decode("utf-8")}

    response: requests.Response = session.post(
        url=url,
        json={
            "pk": base64.b64encode(pk).decode("utf-8"),
            "data": data,
        },
    )

    if response.status_code != 200:
        raise Exception(f"Bad response: {response.status_code}")


def participants(session: requests.Session, url: str) -> Dict[str, List[str]]:
    response: requests.Response = session.get(f"{url}/participants")

    if response.status_code != 200:
        raise Exception(f"Bad response: {response.status_code}")

    return response.json()


def richest(session: requests.Session, url: str, pk: bytes, sk: bytes) -> str:
    pk_b64: str = base64.b64encode(pk).decode("utf-8")

    response: requests.Response = session.post(
        url=f"{url}/richest",
        json={"recipient_pk": pk_b64},
    )

    if response.status_code != 200:
        raise Exception(f"Bad response: {response.status_code}")

    content: Dict[str, Any] = response.json()

    encrypted_content: bytes = base64.b64decode(content["max"])

    logging.debug("Encrypted content for %s: %s", pk_b64, encrypted_content.hex())

    pk_winner: bytes = unseal(encrypted_content, sk)

    return base64.b64encode(pk_winner).decode("utf-8")


def verify(url: str) -> tuple[Path, bytes, bytes]:
    hostname, port = url_parse(url)

    quote: Quote = ratls_verify_from_url(url)
    ratls_cert_path: Path = Path(tempfile.gettempdir()) / "ratls.pem"
    ratls_cert = get_server_certificate((hostname, port))
    ratls_cert_path.write_bytes(ratls_cert.encode("utf-8"))

    maa_result: Dict[str, Any] = verify_quote(quote)

    logging.debug("Microsoft Azure Attestation response: %s", maa_result)

    mr_enclave: bytes = bytes.fromhex(maa_result["x-ms-sgx-mrenclave"])
    enclave_pk: bytes = quote.report_body.report_data[32:]

    return ratls_cert_path, mr_enclave, enclave_pk


def cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        usage="Client for Yao's Millionaires in Cosmian Enclave"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--reset",
        action="store_true",
        help="Remove participant's data from the computation",
    )
    group.add_argument(
        "--verify",
        action="store_true",
        help="Verify the enclave by doing the remote attestation",
    )
    group.add_argument(
        "--list", action="store_true", help="List participant's public key"
    )
    group.add_argument(
        "--push",
        type=float,
        metavar="NUMBER",
        help="Push your wealth as number for the computation",
    )
    group.add_argument(
        "--result", action="store_true", help="Get result of the computation"
    )
    parser.add_argument(
        "--keypair",
        type=Path,
        metavar="PATH",
        help="Path of the public/private keypair",
    )
    parser.add_argument(
        "--debug", action="store_true", help="Debug information to stdout"
    )
    parser.add_argument("url", help="URL of the remote enclave")

    return parser.parse_args()


def main() -> int:
    args: argparse.Namespace = cli_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    url: str = args.url

    session: requests.Session = requests.Session()

    ratls_cert_path, mr_enclave, enclave_pk = verify(url)

    session.verify = f"{ratls_cert_path}"

    if args.reset:
        reset(session, url)
        logging.info("Reset success")

    if args.verify:
        logging.info(
            "Verification successful, MRENCLAVE: %s",
            mr_enclave.hex(),
        )
    if args.list:
        logging.info(participants(session, url))

    keypair: bytes = Path(args.keypair).read_bytes()

    pk, sk = keypair[:32], keypair[32:]

    if args.push:
        push(session, url, pk, float(args.push), enclave_pk)
        logging.info(
            "Pushed %s with public key %s",
            float(args.push),
            base64.b64encode(pk).decode("utf-8"),
        )

    if args.result:
        logging.info("The richest participant is %s", richest(session, url, pk, sk))

    return 0


if __name__ == "__main__":
    main()
