"""cenclave.command.sgx_operator.logs module."""

from cenclave.command.helpers import get_app_container, get_client_docker
from cenclave.log import LOGGER as LOG


def add_subparser(subparsers):
    """Define the subcommand."""
    parser = subparsers.add_parser("logs", help="print container logs")

    parser.add_argument(
        "name",
        type=str,
        help="the name of the container",
    )

    parser.add_argument(
        "-f",
        "--follow",
        action="store_true",
        help="follow log output",
    )

    parser.set_defaults(func=run)


def run(args) -> None:
    """Run the subcommand."""
    client = get_client_docker()
    container = get_app_container(client, args.name)

    if args.follow:
        LOG.info("skipping...")
        for line in container.logs(tail=10, stream=True):
            LOG.info(line.decode("utf-8").strip())
    else:
        LOG.info(container.logs().decode("utf-8"))
