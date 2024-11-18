"""cenclave module."""

import os

__version__ = "1.0.0a1"

# PCCS to retrieve collaterals
PCCS_URL = os.getenv("PCCS_URL", default="https://pccs.cosmian.com")

# URL of Cosmian Enclave's documentation
DOC_URL = "https://docs.cosmian.com/compute/cosmian_enclave/overview/"
