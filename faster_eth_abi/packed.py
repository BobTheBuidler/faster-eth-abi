"""Helpers for packed ABI encoding.

Defines functions and registry for packed encoding and encodability checks.
"""
from typing import (
    Final,
)

from .codec import (
    ABIEncoder,
)
from .registry import (
    registry_packed,
)

default_encoder_packed: Final = ABIEncoder(registry_packed)

encode_packed: Final = default_encoder_packed.encode
is_encodable_packed: Final = default_encoder_packed.is_encodable
