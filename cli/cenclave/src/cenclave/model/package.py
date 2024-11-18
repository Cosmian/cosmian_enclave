"""cenclave.model.package module."""

import tarfile
from pathlib import Path

from pydantic import BaseModel

from cenclave.error import PackageMalformed

DEFAULT_CODE_DIR = "src"
DEFAULT_CONFIG_FILENAME = "config.toml"
DEFAULT_TEST_DIR = "tests"
DEFAULT_DOCKERFILE_FILENAME = "Dockerfile"
DEFAULT_SECRETS_FILENAME = "secrets.json"
DEFAULT_SEAL_SECRETS_FILENAME = "secrets_to_seal.json"

CODE_TAR_NAME = "app.tar"
DOCKER_IMAGE_TAR_NAME = "image.tar"
CONFIG_NAME = "config.toml"
TEST_TAR_NAME = "tests.tar"


class CodePackage(BaseModel):
    """Definition of a code package."""

    code_tar: Path
    image_tar: Path
    test_tar: Path
    config_path: Path

    def create(
        self,
        output_tar: Path,
    ):
        """Create the package containing the code and Docker image tarballs."""
        with tarfile.open(output_tar, "w:") as tar_file:
            tar_file.add(self.code_tar, CODE_TAR_NAME)
            tar_file.add(self.image_tar, DOCKER_IMAGE_TAR_NAME)
            tar_file.add(self.test_tar, TEST_TAR_NAME)
            tar_file.add(self.config_path, CONFIG_NAME)

    @staticmethod
    def extract(workspace: Path, package: Path):
        """Extract the code and image from the tarball."""
        with tarfile.open(package, "r") as f:
            f.extractall(path=workspace)

        code_tar_path = workspace / CODE_TAR_NAME
        image_tar_path = workspace / DOCKER_IMAGE_TAR_NAME
        code_config_path = workspace / CONFIG_NAME
        test_tar_path = workspace / TEST_TAR_NAME

        if not code_tar_path.exists():
            raise PackageMalformed(
                f"'{CODE_TAR_NAME}' was not found in the cenclave package"
            )

        if not image_tar_path.exists():
            raise PackageMalformed(
                f"'{DOCKER_IMAGE_TAR_NAME}' was not found in the cenclave package"
            )

        if not test_tar_path.exists():
            raise PackageMalformed(
                f"'{TEST_TAR_NAME}' was not found in the cenclave package"
            )

        if not code_config_path.exists():
            raise PackageMalformed(
                f"'{CONFIG_NAME}' was not found in the cenclave package"
            )

        return CodePackage(
            code_tar=code_tar_path,
            image_tar=image_tar_path,
            test_tar=test_tar_path,
            config_path=code_config_path,
        )
