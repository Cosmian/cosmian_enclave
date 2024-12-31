"""cenclave.core.sgx_docker module."""

from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Tuple
from uuid import UUID

from pydantic import BaseModel, validator


class SgxDockerConfig(BaseModel):
    """Definition of container running in SGX enclave."""

    size: int
    host: str
    port: int
    app_id: UUID
    subject: str
    subject_alternative_name: str
    expiration_date: int
    client_certificate: Optional[str]
    ssl_verify_mode: Optional[int]
    app_dir: Path
    application: str
    healthcheck: str
    signer_key: Path

    signer_key_mountpoint: ClassVar[str] = "/root/.config/gramine/enclave-key.pem"
    app_mountpoint: ClassVar[str] = "/opt/input"
    docker_label: ClassVar[str] = "cenclave"
    entrypoint: ClassVar[str] = "cenclave-run"

    # pylint: disable=no-self-argument
    @validator("ssl_verify_mode")
    def check_ssl_verify_mode(cls, v, values):
        """Validate ssl_verify_mode with client_certificate."""
        if "ssl_verify_mode" in values and not values["client_certificate"]:
            raise ValueError("no client_certificate with ssl_verify_mode")

        if v and v not in (1, 2):
            raise ValueError(
                "ssl_verify_mode must be 1 (CERT_OPTIONAL) or 2 (CERT_REQUIRED)"
            )

        return v

    def cmd(self) -> List[str]:
        """Serialize the docker command args."""
        args = [
            "--application",
            self.application,
            "--size",
            f"{self.size}M",
            "--san",
            self.subject_alternative_name,
            "--id",
            str(self.app_id),
            "--subject",
            self.subject,
            "--expiration",
            str(self.expiration_date),
        ]

        if client_certificate := self.client_certificate:
            if ssl_verify_mode := self.ssl_verify_mode:
                args.extend(
                    [
                        "--client-certificate",
                        client_certificate,
                        "--ssl-verify-mode",
                        str(ssl_verify_mode),
                    ]
                )

        return args

    def ports(self) -> Dict[str, Tuple[str, str]]:
        """Define the docker ports."""
        return {"443/tcp": (self.host, str(self.port))}

    def labels(self) -> Dict[str, str]:
        """Define the docker labels."""
        return {
            SgxDockerConfig.docker_label: "1",
            "healthcheck_endpoint": self.healthcheck,
        }

    def volumes(self) -> Dict[str, Dict[str, str]]:
        """Define the docker volumes."""
        return {
            f"{self.app_dir.resolve()}": {
                "bind": SgxDockerConfig.app_mountpoint,
                "mode": "rw",
            },
            "/var/run/aesmd": {"bind": "/var/run/aesmd", "mode": "rw"},
            f"{self.signer_key.resolve()}": {
                "bind": SgxDockerConfig.signer_key_mountpoint,
                "mode": "rw",
            },
        }

    @staticmethod
    def devices() -> List[str]:
        """Define the docker devices."""
        return [
            "/dev/sgx_enclave:/dev/sgx_enclave:rw",
            "/dev/sgx_provision:/dev/sgx_provision:rw",
            "/dev/sgx/enclave:/dev/sgx/enclave:rw",
            "/dev/sgx/provision:/dev/sgx/provision:rw",
        ]

    @staticmethod
    def load(docker_attrs: Dict[str, Any], docker_labels: Any):
        """Load the docker configuration from the container."""
        data_map: Dict[str, Any] = {}

        cmd = docker_attrs["Config"]["Cmd"]
        port = docker_attrs["HostConfig"]["PortBindings"]
        signer_key = next(
            filter(
                lambda mount: mount["Destination"]
                == SgxDockerConfig.signer_key_mountpoint,
                docker_attrs["Mounts"],
            )
        )
        app = next(
            filter(
                lambda mount: mount["Destination"] == SgxDockerConfig.app_mountpoint,
                docker_attrs["Mounts"],
            )
        )

        i = 0
        while i < len(cmd):
            key = cmd[i][2:]
            if i + 1 == len(cmd):
                data_map[key] = True
                i += 1
                break

            if cmd[i + 1].startswith("--"):
                data_map[key] = True
                i += 1
                continue

            data_map[key] = cmd[i + 1]
            i += 2

        return SgxDockerConfig(
            size=int(data_map["size"][:-1]),
            host=port["443/tcp"][0]["HostIp"],
            subject=data_map["subject"],
            subject_alternative_name=data_map["san"],
            app_id=UUID(data_map["id"]),
            expiration_date=int(data_map["expiration"]),
            client_certificate=data_map.get("client-certificate"),
            ssl_verify_mode=data_map.get("ssl-verify-mode"),
            app_dir=Path(app["Source"]),
            application=data_map["application"],
            port=int(port["443/tcp"][0]["HostPort"]),
            healthcheck=docker_labels["healthcheck_endpoint"],
            signer_key=Path(signer_key["Source"]),
        )
