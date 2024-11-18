"""cenclave.core.ignore_file module."""

from pathlib import Path


class IgnoreFile:
    """Class to deal with the .cenclaveignore file."""

    @staticmethod
    def parse(path: Path):
        """Parse the cenclaveignore from `path`."""
        ignore_file = path / ".cenclaveignore"
        return (
            {
                line
                for line in ignore_file.read_text().splitlines()
                # Ignore empty lines
                # Ignore lines being comments
                if line.strip() and not line.strip().startswith("#")
            }
            if ignore_file.exists()
            else {}
        )
