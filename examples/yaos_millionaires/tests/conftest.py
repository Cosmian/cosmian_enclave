"""Conftest."""

import base64
import os
from pathlib import Path
from typing import Optional

import pytest
from intel_sgx_ra.ratls import get_server_certificate, url_parse


@pytest.fixture(scope="module")
def url() -> str:
    """Get the url of the web app."""
    return os.getenv("TEST_REMOTE_URL", "http://localhost:5000")


@pytest.fixture(scope="module")
def secret_json() -> Optional[Path]:
    """Get the secret.json path."""
    e = os.getenv("TEST_SECRET_JSON")
    return Path(e) if e else None


@pytest.fixture(scope="module")
def sealed_secret_json() -> Optional[Path]:
    """Get the sealed_secret.json path."""
    e = os.getenv("TEST_SEALED_SECRET_JSON")
    return Path(e) if e else None


@pytest.fixture(scope="module")
def workspace(tmp_path_factory) -> Path:
    """Get the path of the test work directory."""
    return tmp_path_factory.mktemp("workspace")


@pytest.fixture(scope="module")
def certificate(url, workspace) -> Optional[Path]:
    """Get the web app certificate."""
    if "https" not in url:
        return None  # Do not check

    if "localhost" in url:
        return None  # Do not check

    hostname, port = url_parse(url)

    cert_path: Path = workspace / "cert.pem"

    if cert_path.exists():
        return cert_path  # Use this specific bundle

    pem = get_server_certificate((hostname, port))
    cert_path.write_bytes(pem.encode("utf-8"))

    return cert_path


@pytest.fixture(scope="module")
def keypair1_path() -> bytes:
    """Path of the participant 1 keypair."""
    return Path(__file__).parent / "data" / "keypair1.bin"


@pytest.fixture(scope="module")
def keypair2_path() -> bytes:
    """Path of the participant 2 keypair."""
    return Path(__file__).parent / "data" / "keypair2.bin"


@pytest.fixture(scope="module")
def pk1(keypair1_path) -> bytes:
    """Bytes of the public key of the participant 1."""
    return keypair1_path.read_bytes()[:32]


@pytest.fixture(scope="module")
def pk1_b64(pk1) -> bytes:
    """Base64 encoded public key of the participant 1."""
    return base64.b64encode(pk1)


@pytest.fixture(scope="module")
def pk2(keypair2_path) -> bytes:
    """Bytes of the public key of the participant 2."""
    return keypair2_path.read_bytes()[:32]


@pytest.fixture(scope="module")
def pk2_b64(pk2) -> bytes:
    """Base64 encoded public key of the participant 2."""
    return base64.b64encode(pk2)


@pytest.fixture(scope="module")
def sk1(keypair1_path) -> bytes:
    """Bytes of the private key of the participant 1."""
    return keypair1_path.read_bytes()[32:]


@pytest.fixture(scope="module")
def sk2(keypair2_path) -> bytes:
    """Bytes of the private key of the participant 2."""
    return keypair2_path.read_bytes()[32:]
