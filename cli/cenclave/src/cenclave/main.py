"""cenclave.main module."""

import argparse
import os
import traceback
from warnings import filterwarnings  # noqa: E402

filterwarnings("ignore")  # noqa: E402

# pylint: disable=wrong-import-position
import cenclave
from cenclave.command.code_provider import (
    decrypt,
    encrypt,
    localtest,
    package,
    scaffold,
    seal,
    unseal,
    verify,
)
from cenclave.command.sgx_operator import (
    evidence,
    list_all,
    logs,
    restart,
    run,
    spawn,
    status,
    stop,
    test,
)
from cenclave.log import LOGGER as LOG
from cenclave.log import setup_logging


# pylint: disable=too-many-statements
def main() -> int:
    """Entrypoint of the CLI."""
    parser = argparse.ArgumentParser(
        description="Cosmian Enclave CLI" f" - {cenclave.__version__}"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"{cenclave.__version__}",
        help="version of %(prog)s CLI",
    )

    subparsers = parser.add_subparsers(title="commands")

    encrypt.add_subparser(subparsers)
    decrypt.add_subparser(subparsers)
    evidence.add_subparser(subparsers)
    scaffold.add_subparser(subparsers)
    list_all.add_subparser(subparsers)
    logs.add_subparser(subparsers)
    package.add_subparser(subparsers)
    restart.add_subparser(subparsers)
    run.add_subparser(subparsers)
    status.add_subparser(subparsers)
    seal.add_subparser(subparsers)
    unseal.add_subparser(subparsers)
    spawn.add_subparser(subparsers)
    stop.add_subparser(subparsers)
    test.add_subparser(subparsers)
    localtest.add_subparser(subparsers)
    verify.add_subparser(subparsers)

    args = parser.parse_args()

    setup_logging(False)

    try:
        func = args.func
    except AttributeError:
        parser.error("too few arguments")
        return 1

    try:
        func(args)
        return 0
    # pylint: disable=broad-except
    except Exception as e:
        if os.getenv("BACKTRACE") == "full":
            traceback.print_exc()

        LOG.error(e)
        return 1


if __name__ == "__main__":
    main()
