"""Test model/args.py."""

from pathlib import Path

from cenclave.core.test_docker import TestDockerConfig


def test_volumes():
    """Test `volumes` function."""
    ref_conf = TestDockerConfig(
        port=5000,
        code="/tmp/code.tar",
        application="app:app",
        sealed_secrets=None,
        secrets=None,
    )

    assert ref_conf.volumes() == {
        "/tmp/code.tar": {
            "bind": "/app",
            "mode": "rw",
        }
    }

    ref_conf = TestDockerConfig(
        port=5000,
        code=Path("/tmp/code.tar"),
        application="app:app",
        sealed_secrets=Path("/tmp/sealed_secrets"),
        secrets=Path("/tmp/secrets.json"),
    )

    assert ref_conf.volumes() == {
        "/tmp/code.tar": {
            "bind": "/app",
            "mode": "rw",
        },
        "/tmp/secrets.json": {
            "bind": "/root/.cache/cenclave/secrets.json",
            "mode": "rw",
        },
        "/tmp/sealed_secrets": {
            "bind": "/root/.cache/cenclave/sealed_secrets.json",
            "mode": "rw",
        },
    }


def test_cmd():
    """Test `cmd` function."""
    ref_conf = TestDockerConfig(
        port=5000,
        code="/tmp/code.tar",
        application="app:app",
        sealed_secrets=None,
        secrets=None,
    )

    assert ref_conf.cmd() == [
        "--application",
        "app:app",
        "--debug",
    ]

    ref_conf = TestDockerConfig(
        port=5000,
        code=Path("/tmp/code.tar"),
        application="app:app",
        sealed_secrets=Path("/tmp/sealed_secrets"),
        secrets=Path("/tmp/secrets.json"),
    )

    assert ref_conf.cmd() == [
        "--application",
        "app:app",
        "--debug",
    ]


def test_ports():
    """Test `ports` function."""
    ref_conf = TestDockerConfig(
        port=5000,
        code="/tmp/code.tar",
        application="app:app",
        sealed_secrets=None,
        secrets=None,
    )

    assert ref_conf.ports() == {"5000/tcp": ("127.0.0.1", "5000")}

    ref_conf = TestDockerConfig(
        port=5000,
        code=Path("/tmp/code.tar"),
        application="app:app",
        sealed_secrets=Path("/tmp/sealed_secrets"),
        secrets=Path("/tmp/secrets.json"),
    )

    assert ref_conf.ports() == {"5000/tcp": ("127.0.0.1", "5000")}
