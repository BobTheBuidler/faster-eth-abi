from importlib.metadata import (
    PackageNotFoundError,
    version as __version,
)

from faster_eth_abi.abi import (
    decode,
    encode,
    is_encodable,
    is_encodable_type,
)

try:
    __version__ = __version("faster-eth-abi")
except PackageNotFoundError:  # pragma: no cover - fallback for source checkouts
    __version__ = "0+unknown"
