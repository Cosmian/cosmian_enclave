"""cenclave.command.code_provider.scaffold module."""

from cenclave.common.helpers import scaffold
from cenclave.log import LOGGER as LOG


def add_subparser(subparsers):
    """Define the subcommand."""
    parser = subparsers.add_parser(
        "scaffold", help="create a new boilerplate web application"
    )

    parser.add_argument(
        "app_name",
        type=str,
        help="name of the Python web application",
    )

    parser.set_defaults(func=run)


def run(args) -> None:
    """Run the subcommand."""
    conf_file = scaffold(args.app_name)

    LOG.info(  # type: ignore
        "An example app has been generated in the directory: %s/", args.app_name
    )
    LOG.warning("You can configure your web application in: %s", conf_file)
