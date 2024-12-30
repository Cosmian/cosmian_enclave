"""Test model/args.py."""

from pathlib import Path

from cenclave.core.no_sgx_docker import NoSgxDockerConfig
from cenclave.core.sgx_docker import SgxDockerConfig


def test_from_sgx():
    """Test the `from_sgx` method."""
    ref_conf = NoSgxDockerConfig(
        subject="CN=localhost,O=Big Company,C=FR,L=Paris,ST=Ile-de-France",
        subject_alternative_name="localhost",
        expiration_date=1714058115,
        client_certificate=None,
        ssl_verify_mode=None,
        size=4096,
        app_id="63322f85-1ff8-4483-91ae-f18d7398d157",
        application="app:app",
    )

    conf = NoSgxDockerConfig.from_sgx(
        SgxDockerConfig(
            size=4096,
            host="localhost",
            port=7788,
            subject="CN=localhost,O=Big Company,C=FR,L=Paris,ST=Ile-de-France",
            subject_alternative_name="localhost",
            app_id="63322f85-1ff8-4483-91ae-f18d7398d157",
            expiration_date=1714058115,
            client_certificate=None,
            ssl_verify_mode=None,
            app_dir="/home/cosmian/workspace/sgx_operator/",
            application="app:app",
            healthcheck="/health",
            signer_key="/opt/cosmian-internal/cosmian-signer-key.pem",
        )
    )

    assert conf == ref_conf


def test_volumes():
    """Test `volumes` function."""
    ref_conf = NoSgxDockerConfig(
        subject="CN=localhost,O=Big Company,C=FR,L=Paris,ST=Ile-de-France",
        subject_alternative_name="localhost",
        expiration_date=1714058115,
        client_certificate=None,
        ssl_verify_mode=None,
        size=4096,
        app_id="63322f85-1ff8-4483-91ae-f18d7398d157",
        application="app:app",
    )

    assert ref_conf.volumes(Path("/tmp/")) == {
        "/tmp": {
            "bind": "/opt/input",
            "mode": "rw",
        }
    }


def test_cmd():
    """Test `cmd` function."""
    ref_conf = NoSgxDockerConfig(
        subject="CN=localhost,O=Big Company,C=FR,L=Paris,ST=Ile-de-France",
        subject_alternative_name="localhost",
        expiration_date=1714058115,
        client_certificate=None,
        ssl_verify_mode=None,
        size=4096,
        app_id="63322f85-1ff8-4483-91ae-f18d7398d157",
        application="app:app",
    )

    assert ref_conf.cmd() == [
        "--application",
        "app:app",
        "--size",
        "4096M",
        "--san",
        "localhost",
        "--id",
        "63322f85-1ff8-4483-91ae-f18d7398d157",
        "--subject",
        "CN=localhost,O=Big Company,C=FR,L=Paris,ST=Ile-de-France",
        "--expiration",
        "1714058115",
        "--dry-run",
    ]

    ref_conf = NoSgxDockerConfig(
        subject="CN=localhost,O=Big Company,C=FR,L=Paris,ST=Ile-de-France",
        subject_alternative_name="localhost",
        client_certificate=None,
        ssl_verify_mode=None,
        size=4096,
        app_id="63322f85-1ff8-4483-91ae-f18d7398d157",
        application="app:app",
    )

    assert ref_conf.cmd() == [
        "--application",
        "app:app",
        "--size",
        "4096M",
        "--san",
        "localhost",
        "--id",
        "63322f85-1ff8-4483-91ae-f18d7398d157",
        "--subject",
        "CN=localhost,O=Big Company,C=FR,L=Paris,ST=Ile-de-France",
        "--dry-run",
    ]
