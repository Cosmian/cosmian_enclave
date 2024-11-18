"""cenclave.log module."""

import logging
import sys

LOGGER = logging.getLogger("cenclave")

LOGGING_SUCCESS = 25
LOGGING_ADVICE = 26


def setup_logging(debug: bool = False):
    """Configure basic logging."""
    format_msg = "%(message)s"

    # Define a specific format for stdout handler
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.DEBUG if debug else logging.INFO)

    logging.basicConfig(format=format_msg, handlers=[stdout_handler])
    LOGGER.setLevel(logging.DEBUG if debug else logging.INFO)

    # Add a success level to the default logger (then we can write LOG.success("msg"))
    logging.addLevelName(LOGGING_SUCCESS, "SUCCESS")
    # pylint: disable=protected-access
    setattr(
        LOGGER,
        "success",
        lambda message, *args: LOGGER._log(LOGGING_SUCCESS, message, args),
    )

    # Add an advice level to the default logger (then we can write LOG.advice("msg"))
    logging.addLevelName(LOGGING_ADVICE, "ADVICE")
    # pylint: disable=protected-access
    setattr(
        LOGGER,
        "advice",
        lambda message, *args: LOGGER._log(LOGGING_ADVICE, message, args),
    )
