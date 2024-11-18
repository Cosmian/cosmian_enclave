"""cenclave.core.conf module."""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import toml
from pydantic import BaseModel, constr, validator

from cenclave.error import BadApplicationInput

if TYPE_CHECKING:
    Str255 = str
    Str16 = str
    StrUnlimited = str
else:
    Str255 = constr(min_length=1, max_length=255, strip_whitespace=True)
    Str16 = constr(min_length=1, max_length=16, strip_whitespace=True)
    StrUnlimited = constr(min_length=1)


def absolute_from_conf_file(conf_file: Path, path: Path) -> Path:
    """Make the `path` absolute from `conf_file.parent`."""
    if not path.is_absolute():
        return (conf_file.parent / path).resolve()

    return path


class AppConfParsingOption(Enum):
    """Parsing option for AppConf."""

    All = 0
    SkipCloud = 1
    UseInsecureCloud = 2


class SSLConf(BaseModel):
    """Definition of the app owner certificate."""

    # The domain name of the app
    domain_name: Str255
    # The path to the ssl private key
    private_key: Path
    # The path to the ssl certificate chain
    certificate: Path

    @property
    def certificate_data(self) -> str:
        """Get the data from certificate file."""
        return self.certificate.read_text()

    @property
    def private_key_data(self) -> str:
        """Get the data from private_key file."""
        return self.private_key.read_text()


class AppConf(BaseModel):
    """Define the application configuration."""

    # Name of the enclave instance
    name: Str255
    # from python_flask_module import python_flask_variable_name
    python_application: Str255
    # Endpoint to use to check if the application is up and sane
    healthcheck_endpoint: Str255
    # The command to test the application
    tests_cmd: str
    # The package to install before testing the application
    tests_requirements: List[str]

    @validator("healthcheck_endpoint", pre=False)
    # pylint: disable=no-self-argument,unused-argument
    def check_healthcheck_endpoint(cls, v: str):
        """Validate that `healthcheck_endpoint` is an endpoint."""
        if v.startswith("/"):
            return v
        raise ValueError('healthcheck_endpoint should start with a "/"')

    # pylint: disable=unused-argument
    @staticmethod
    def load(
        path: Optional[Path],
        option: AppConfParsingOption = AppConfParsingOption.All,
    ):
        """Load the configuration from a toml file."""
        path = path.expanduser() if path else Path(os.getcwd()) / "config.toml"

        with open(path, encoding="utf8") as f:
            data_map = toml.load(f)
            app = AppConf(**data_map)

            return app

    def save(self, path: Path) -> None:
        """Save the configuration into a toml file."""
        with open(path, "w", encoding="utf8") as f:
            data_map: Dict[str, Any] = {
                "name": self.name,
                "python_application": self.python_application,
                "healthcheck_endpoint": self.healthcheck_endpoint,
                "tests_cmd": self.tests_cmd,
                "tests_requirements": self.tests_requirements,
            }

            toml.dump(data_map, f)

    @property
    def python_module(self):
        """Get the python module from python_application."""
        split_str = self.python_application.split(":")
        if len(split_str) != 2:
            raise BadApplicationInput(
                "`python_application` is malformed. Expected format: `module:variable`"
            )
        return split_str[0]

    @property
    def python_variable(self):
        """Get the python variable from python_application."""
        split_str = self.python_application.split(":")
        if len(split_str) != 2:
            raise BadApplicationInput(
                "`python_application` is malformed. Expected format: `module:variable`"
            )
        return split_str[1]
