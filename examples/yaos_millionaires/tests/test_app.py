"""Unit test for our app."""

import base64
import struct

from cenclave_lib_crypto.seal_box import unseal, seal


def test_health(url, session):
    """Test healthcheck endpoint."""
    response = session.get(f"{url}/health", timeout=10)
    assert response.status_code == 200


def test_participants(url, session, pk1, pk1_b64, pk2, pk2_b64):
    """Test participants endpoint."""
    response = session.get(f"{url}/participants", timeout=10)

    assert response.status_code == 200

    result = response.json()

    expected_pk1_b64 = base64.b64encode(pk1)
    expected_pk2_b64 = base64.b64encode(pk2)

    assert expected_pk1_b64 == pk1_b64
    assert expected_pk2_b64 == pk2_b64

    assert pk1_b64.decode("utf-8") in result["participants"]
    assert pk2_b64.decode("utf-8") in result["participants"]


def test_richest(url, session, pk1_b64, sk1, pk2_b64, sk2, pk_enclave):
    # reset first
    response = session.delete(f"{url}", timeout=10)
    assert response.status_code == 200

    n: float = 97.0
    encoded_n: bytes = struct.pack("<d", float(n))
    encrypted_n: bytes = seal(encoded_n, pk_enclave)

    response = session.post(
        url,
        json={
            "pk": pk1_b64.decode("utf-8"),
            "data": {"n": base64.b64encode(encrypted_n).decode("utf-8")},
        },
        timeout=10,
    )

    assert response.status_code == 200

    n: float = 97.1
    encoded_n: bytes = struct.pack("<d", float(n))
    encrypted_n: bytes = seal(encoded_n, pk_enclave)

    response = session.post(
        url,
        json={
            "pk": pk2_b64.decode("utf-8"),
            "data": {"n": base64.b64encode(encrypted_n).decode("utf-8")},
        },
        timeout=10,
    )

    assert response.status_code == 200

    # test result with pk1
    response = session.post(
        url=f"{url}/richest", json={"recipient_pk": pk1_b64.decode("utf-8")}
    )

    assert response.status_code == 200

    content = response.json()

    assert "max" in content
    assert content["max"] is not None

    encrypted_content = base64.b64decode(content["max"])
    # decrypt with sk1
    pk_winner: bytes = unseal(encrypted_content, sk1)

    assert base64.b64encode(pk_winner) == pk2_b64

    # test result with pk2
    response = session.post(
        url=f"{url}/richest", json={"recipient_pk": pk2_b64.decode("utf-8")}
    )

    assert response.status_code == 200

    content = response.json()

    assert "max" in content
    assert content["max"] is not None

    encrypted_content = base64.b64decode(content["max"])
    # decrypt with sk2
    pk_winner: bytes = unseal(encrypted_content, sk2)

    assert base64.b64encode(pk_winner) == pk2_b64
