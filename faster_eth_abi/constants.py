import os
from typing import (
    Final,
)

TT256: Final = 2**256
TT256M1: Final = 2**256 - 1
TT255: Final = 2**255

ETH_ABI_NOVALIDATE: Final = bool(os.environ.get("ETH_ABI_NOVALIDATE"))
"""
Set the `ETH_ABI_NOVALIDATE` environment variable to any value to skip
validation of input arguments while encoding. Decoding is not impacted.

This will enable much faster encoding in cases where the developer has
ensured the inputs will always be valid.
"""
