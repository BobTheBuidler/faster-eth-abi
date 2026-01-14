from importlib.metadata import (
    version as __version,
)
from typing import (
    Final,
)

from faster_eth_abi.abi import (
    decode,
    encode,
    is_encodable,
    is_encodable_type,
)

__all__ = ["decode", "encode", "is_encodable", "is_encodable_type"]

__version__: Final = __version("faster-eth-abi")
