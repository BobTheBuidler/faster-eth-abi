import decimal
from .decoding import (
    BaseArrayDecoder as BaseArrayDecoder,
    ByteStringDecoder as ByteStringDecoder,
    DynamicArrayDecoder as DynamicArrayDecoder,
    FixedByteSizeDecoder as FixedByteSizeDecoder,
    HeadTailDecoder as HeadTailDecoder,
    SignedFixedDecoder as SignedFixedDecoder,
    SignedIntegerDecoder as SignedIntegerDecoder,
    SizedArrayDecoder as SizedArrayDecoder,
    TupleDecoder as TupleDecoder,
    UnsignedFixedDecoder as UnsignedFixedDecoder,
)
from _typeshed import Incomplete
from faster_eth_abi.exceptions import (
    InsufficientDataBytes as InsufficientDataBytes,
    InvalidPointer as InvalidPointer,
    NonEmptyPaddingBytes as NonEmptyPaddingBytes,
)
from faster_eth_abi.io import (
    BytesIO as BytesIO,
    ContextFramesBytesIO as ContextFramesBytesIO,
)
from faster_eth_abi.typing import T as T
from faster_eth_abi.utils.localcontext import DECIMAL_CONTEXT as DECIMAL_CONTEXT
from faster_eth_abi.utils.numeric import ceil32 as ceil32
from typing import Final

Decimal: Final[Incomplete]

def decode_uint_256(stream: ContextFramesBytesIO) -> int:
    """
    A faster version of :func:`~decoding.decode_uint_256` in decoding.py.

    It recreates the logic from the UnsignedIntegerDecoder, but we can
    skip a lot because we know the value of many vars.
    """

def get_value_byte_size(decoder: FixedByteSizeDecoder) -> int: ...
def decode_head_tail(self, stream: ContextFramesBytesIO) -> T: ...
def decode_tuple(self, stream: ContextFramesBytesIO) -> tuple[T, ...]: ...
def validate_pointers_tuple(self, stream: ContextFramesBytesIO) -> None:
    """
    Verify that all pointers point to a valid location in the stream.
    """

def validate_pointers_array(
    self, stream: ContextFramesBytesIO, array_size: int
) -> None:
    """
    Verify that all pointers point to a valid location in the stream.
    """

def decode_sized_array(self, stream: ContextFramesBytesIO) -> tuple[T, ...]: ...
def decode_dynamic_array(self, stream: ContextFramesBytesIO) -> tuple[T, ...]: ...
def read_fixed_byte_size_data_from_stream(self, stream: BytesIO) -> bytes: ...
def split_data_and_padding_fixed_byte_size(
    self, raw_data: bytes
) -> tuple[bytes, bytes]: ...
def validate_padding_bytes_fixed_byte_size(
    self, value: T, padding_bytes: bytes
) -> None: ...
def get_expected_padding_bytes(self, chunk: bytes) -> bytes: ...
def validate_padding_bytes_signed_integer(
    self, value: int, padding_bytes: bytes
) -> None: ...
def decoder_fn_boolean(data: bytes) -> bool: ...
def decode_unsigned_fixed(self, data: bytes) -> decimal.Decimal: ...
def decode_signed_fixed(self, data: bytes) -> decimal.Decimal: ...
def read_bytestring_from_stream(self, stream: ContextFramesBytesIO) -> bytes: ...
