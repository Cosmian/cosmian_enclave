"""cenclave.core.no_sgx_docker module."""

from pathlib import Path
from typing import ClassVar, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel

from cenclave.core.sgx_docker import SgxDockerConfig


class NoSgxDockerConfig(BaseModel):
    """Definition of container running on a non-sgx hardware."""

    subject: str
    subject_alternative_name: str
    expiration_date: Optional[int]
    client_certificate: Optional[str]
    ssl_verify_mode: Optional[int]
    size: int
    app_id: UUID
    application: str

    app_mountpoint: ClassVar[str] = "/opt/input"
    entrypoint: ClassVar[str] = "cenclave-run"

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
        ]

        if self.expiration_date:
            args.append("--expiration")
            args.append(str(self.expiration_date))

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

        args.append("--dry-run")

        return args

    def volumes(self, app_path: Path) -> Dict[str, Dict[str, str]]:
        """Define the docker volumes."""
        return {
            f"{app_path.resolve()}": {
                "bind": NoSgxDockerConfig.app_mountpoint,
                "mode": "rw",
            }
        }

    @staticmethod
    def from_sgx(docker_config: SgxDockerConfig):
        """Load from a SgxDockerConfig object."""
        return NoSgxDockerConfig(
            subject=docker_config.subject,
            subject_alternative_name=docker_config.subject_alternative_name,
            expiration_date=docker_config.expiration_date,
            client_certificate=docker_config.client_certificate,
            ssl_verify_mode=docker_config.ssl_verify_mode,
            size=docker_config.size,
            app_id=docker_config.app_id,
            application=docker_config.application,
        )
