"""cenclave.core.clock_tick module."""

import time

from cenclave.error import Timeout


class ClockTick:
    """Class to monitor the spent time."""

    def __init__(self, period: int, timeout: int, message: str):
        """Initialize the clock."""
        self.elapsed = 0
        self.timeout = timeout
        self.period = period
        self.message = message

    def tick(self) -> bool:
        """Start ticking."""
        if self.elapsed > self.timeout:
            raise Timeout(self.message)

        time.sleep(self.period)
        self.elapsed += self.period

        return True
