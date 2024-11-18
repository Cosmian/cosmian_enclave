"""Unit test for our app."""

import base64

import requests
from cenclave_lib_crypto.seal_box import unseal


def test_health(url, certificate):
    """Test healthcheck endpoint."""
    response = requests.get(f"{url}/health", timeout=10, verify=certificate)
    assert response.status_code == 200


def test_participants(url, certificate, pk1, pk1_b64, pk2, pk2_b64):
    """Test participants endpoint."""
    response = requests.get(
        f"{url}/participants",
        timeout=10,
        verify=certificate,
    )

    assert response.status_code == 200

    result = response.json()

    expected_pk1_b64 = base64.b64encode(pk1).decode("utf-8")
    expected_pk2_b64 = base64.b64encode(pk2).decode("utf-8")

    assert expected_pk1_b64 == pk1_b64
    assert expected_pk2_b64 == pk2_b64

    assert pk1_b64 in result["participants"]
    assert pk2_b64 in result["participants"]


def test_richest(url, certificate, pk1_b64, sk1, pk2_b64, sk2):
    response = requests.post(
        url,
        json={"pk": pk1_b64, "n": float(97)},
        timeout=10,
        verify=certificate,
    )

    assert response.status_code == 200

    response = requests.post(
        url,
        json={"pk": pk2_b64, "n": float(97.1)},
        timeout=10,
        verify=certificate,
    )

    assert response.status_code == 200

    # test result with pk1
    response = requests.post(
        url=f"{url}/richest",
        json={"recipient_pk": pk1_b64},
        verify=certificate,
    )

    assert response.status_code == 200

    content = response.json()

    assert "max" in content
    assert content["max"] is not None

    encrypted_content = base64.b64decode(content["max"])
    # decrypt with sk1
    pk_winner: bytes = unseal(encrypted_content, sk1)

    assert base64.b64encode(pk_winner).decode("utf-8") == pk2_b64

    # test result with pk2
    response = requests.post(
        url=f"{url}/richest",
        json={"recipient_pk": pk2_b64},
        verify=certificate,
    )

    assert response.status_code == 200

    content = response.json()

    assert "max" in content
    assert content["max"] is not None

    encrypted_content = base64.b64decode(content["max"])
    # decrypt with sk2
    pk_winner: bytes = unseal(encrypted_content, sk2)

    assert base64.b64encode(pk_winner).decode("utf-8") == pk2_b64
