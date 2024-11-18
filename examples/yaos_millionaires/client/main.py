"""Simple Python client for Yao's Millionaires.

```console
$ pip install requests intel-sgx-ra
$ python main.py http://127.0.0.1:5000  # for local testing
```

"""

import base64
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Union

import requests
from cenclave_lib_crypto.seal_box import unseal
from intel_sgx_ra.maa.attest import verify_quote
from intel_sgx_ra.quote import Quote
from intel_sgx_ra.ratls import get_server_certificate, ratls_verify_from_url, url_parse


# Key generated with cenclave_lib_crypto.x2559.x25519_keygen()
PK1: bytes = bytes.fromhex(
    "938b3e0e60ebbdbbd4348ba6a0468685043d540e332c32e8bc2ca40b858ad209"
)
PK1_B64: str = "k4s+DmDrvbvUNIumoEaGhQQ9VA4zLDLovCykC4WK0gk="
SK1: bytes = bytes.fromhex(
    "7957ceed56d44a384cf523619a00b2c129514daf422c0b799105fb2caa23ef97"
)

PK2: bytes = bytes.fromhex(
    "ff8b983287fec6aefcf1b55e8c1efeff984e5b8dfa8d4de62df521bd6ec57d14"
)
PK2_B64: str = "/4uYMof+xq788bVejB7+/5hOW436jU3mLfUhvW7FfRQ="
SK2: bytes = bytes.fromhex(
    "05e5aa1c56ec3d6bf707893e6a038a825d80a2802fdb565fd8fecb840735a954"
)


def reset(session: requests.Session, url: str) -> None:
    response: requests.Response = session.delete(url)

    if response.status_code != 200:
        raise Exception(f"Bad response: {response.status_code}")


def push(session: requests.Session, url: str, pk: bytes, n: Union[int, float]) -> None:
    response: requests.Response = session.post(
        url=url,
        json={"pk": base64.b64encode(pk).decode("utf-8"), "n": float(n)},
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

    print(f"Encrypted content for {pk_b64}: {encrypted_content.hex()}")

    pk_winner: bytes = unseal(encrypted_content, sk)

    return base64.b64encode(pk_winner).decode("utf-8")


def main() -> int:
    url: str = sys.argv[1]
    hostname, port = url_parse(url)

    session: requests.Session = requests.Session()

    quote: Quote = ratls_verify_from_url(url)
    ratls_cert_path: Path = Path(tempfile.gettempdir()) / "ratls.pem"
    ratls_cert = get_server_certificate((hostname, port))
    ratls_cert_path.write_bytes(ratls_cert.encode("utf-8"))

    _: Dict[str, Any] = verify_quote(quote)

    session.verify = f"{ratls_cert_path}"

    p_1 = (PK1, 100_398)
    p_2 = (PK2, 100_399)

    reset(session, url)

    for pk, n in (p_1, p_2):
        push(session, url, pk, n)

    print(participants(session, url))

    p_1_result = richest(session, url, PK1, SK1)
    p_2_result = richest(session, url, PK2, SK2)

    assert p_1_result == p_2_result

    print(f"The richest participant is {p_1_result}")

    return 0


if __name__ == "__main__":
    main()
