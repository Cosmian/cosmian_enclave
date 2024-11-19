"""Conftest."""

import os
from pathlib import Path
from typing import Optional, Union

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
def pk1() -> bytes:
    """Bytes of the public key of the participant 1."""
    return bytes.fromhex(
        "938b3e0e60ebbdbbd4348ba6a0468685043d540e332c32e8bc2ca40b858ad209"
    )


@pytest.fixture(scope="module")
def pk1_b64() -> str:
    """Base64 encoded public key of the participant 1."""
    return "k4s+DmDrvbvUNIumoEaGhQQ9VA4zLDLovCykC4WK0gk="


@pytest.fixture(scope="module")
def pk2() -> bytes:
    """Bytes of the public key of the participant 2."""
    return bytes.fromhex(
        "ff8b983287fec6aefcf1b55e8c1efeff984e5b8dfa8d4de62df521bd6ec57d14"
    )


@pytest.fixture(scope="module")
def pk2_b64() -> str:
    """Base64 encoded public key of the participant 2."""
    return "/4uYMof+xq788bVejB7+/5hOW436jU3mLfUhvW7FfRQ="


@pytest.fixture(scope="module")
def sk1() -> bytes:
    """Bytes of the private key of the participant 1."""
    return bytes.fromhex(
        "7957ceed56d44a384cf523619a00b2c129514daf422c0b799105fb2caa23ef97"
    )


@pytest.fixture(scope="module")
def sk2() -> bytes:
    """Bytes of the private key of the participant 2."""
    return bytes.fromhex(
        "05e5aa1c56ec3d6bf707893e6a038a825d80a2802fdb565fd8fecb840735a954"
    )
