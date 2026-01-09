import abc
import decimal
from _typeshed import Incomplete
from eth_typing import HexAddress
from faster_eth_abi._decoding import (
    decode_dynamic_array as decode_dynamic_array,
    decode_head_tail as decode_head_tail,
    decode_signed_fixed as decode_signed_fixed,
    decode_sized_array as decode_sized_array,
    decode_string as decode_string,
    decode_tuple as decode_tuple,
    decode_unsigned_fixed as decode_unsigned_fixed,
    decoder_fn_boolean as decoder_fn_boolean,
    get_value_byte_size as get_value_byte_size,
    read_bytestring_from_stream as read_bytestring_from_stream,
    read_fixed_byte_size_data_from_stream as read_fixed_byte_size_data_from_stream,
    split_data_and_padding_fixed_byte_size as split_data_and_padding_fixed_byte_size,
    validate_padding_bytes_fixed_byte_size as validate_padding_bytes_fixed_byte_size,
    validate_padding_bytes_signed_integer as validate_padding_bytes_signed_integer,
    validate_pointers_array as validate_pointers_array,
)
from faster_eth_abi.base import BaseCoder as BaseCoder
from faster_eth_abi.exceptions import NonEmptyPaddingBytes as NonEmptyPaddingBytes
from faster_eth_abi.from_type_str import (
    parse_tuple_type_str as parse_tuple_type_str,
    parse_type_str as parse_type_str,
)
from faster_eth_abi.io import ContextFramesBytesIO as ContextFramesBytesIO
from faster_eth_abi.typing import T as T
from faster_eth_abi.utils.numeric import TEN as TEN
from functools import cached_property as cached_property
from typing import Any, Callable, Final, Generic, TypeVar, final

TByteStr = TypeVar("TByteStr", bytes, str)

class BaseDecoder(BaseCoder, Generic[T], metaclass=abc.ABCMeta):
    """
    Base class for all decoder classes.  Subclass this if you want to define a
    custom decoder class.  Subclasses must also implement
    :any:`BaseCoder.from_type_str`.
    """

    strict: bool
    @abc.abstractmethod
    def decode(self, stream: ContextFramesBytesIO) -> T:
        """
        Decodes the given stream of bytes into a python value.  Should raise
        :any:`exceptions.DecodingError` if a python value cannot be decoded
        from the given byte stream.
        """

    def __call__(self, stream: ContextFramesBytesIO) -> T: ...

class HeadTailDecoder(BaseDecoder[T]):
    """
    Decoder for a dynamic element of a dynamic container (a dynamic array, or a sized
    array or tuple that contains dynamic elements). A dynamic element consists of a
    pointer, aka offset, which is located in the head section of the encoded container,
    and the actual value, which is located in the tail section of the encoding.
    """

    is_dynamic: bool
    tail_decoder: Final[Incomplete]
    def __init__(
        self,
        tail_decoder: (
            HeadTailDecoder[T]
            | SizedArrayDecoder[T]
            | DynamicArrayDecoder[T]
            | ByteStringDecoder[T]
        ),
    ) -> None: ...
    def decode(self, stream: ContextFramesBytesIO) -> T: ...
    __call__ = decode

class TupleDecoder(BaseDecoder[tuple[T, ...]]):
    decoders: tuple[BaseDecoder[T], ...]
    is_dynamic: Incomplete
    len_of_head: Incomplete
    def __init__(self, decoders: tuple[BaseDecoder[T], ...]) -> None: ...
    def validate(self) -> None: ...
    @final
    def validate_pointers(self, stream: ContextFramesBytesIO) -> None: ...
    def decode(self, stream: ContextFramesBytesIO) -> tuple[T, ...]: ...
    __call__ = decode
    @parse_tuple_type_str
    def from_type_str(cls, abi_type, registry): ...

class SingleDecoder(BaseDecoder[T]):
    decoder_fn: Incomplete
    def validate(self) -> None: ...
    def validate_padding_bytes(self, value: Any, padding_bytes: bytes) -> None: ...
    def decode(self, stream: ContextFramesBytesIO) -> T: ...
    __call__ = decode
    def read_data_from_stream(self, stream: ContextFramesBytesIO) -> bytes: ...
    def split_data_and_padding(self, raw_data: bytes) -> tuple[bytes, bytes]: ...

class BaseArrayDecoder(BaseDecoder[tuple[T, ...]]):
    item_decoder: BaseDecoder
    def __init__(self, **kwargs: Any) -> None: ...
    def decode(self, stream: ContextFramesBytesIO) -> tuple[T, ...]: ...
    def validate(self) -> None: ...
    def from_type_str(cls, abi_type, registry): ...
    def validate_pointers(self, stream: ContextFramesBytesIO, array_size: int) -> None:
        """
        Verify that all pointers point to a valid location in the stream.
        """

class SizedArrayDecoder(BaseArrayDecoder[T]):
    array_size: int
    is_dynamic: Incomplete
    def __init__(self, **kwargs: Any) -> None: ...
    def decode(self, stream: ContextFramesBytesIO) -> tuple[T, ...]: ...
    __call__ = decode

class DynamicArrayDecoder(BaseArrayDecoder[T]):
    is_dynamic: bool
    def decode(self, stream: ContextFramesBytesIO) -> tuple[T, ...]: ...
    __call__ = decode

class FixedByteSizeDecoder(SingleDecoder[T]):
    decoder_fn: Callable[[bytes], T]
    value_bit_size: int
    data_byte_size: int
    is_big_endian: bool
    validate_padding_bytes: Incomplete
    def __init__(self, **kwargs: Any) -> None: ...
    def validate(self) -> None: ...
    def read_data_from_stream(self, stream: ContextFramesBytesIO) -> bytes: ...
    def split_data_and_padding(self, raw_data: bytes) -> tuple[bytes, bytes]: ...

class Fixed32ByteSizeDecoder(FixedByteSizeDecoder[T]):
    data_byte_size: int

class BooleanDecoder(Fixed32ByteSizeDecoder[bool]):
    value_bit_size: int
    is_big_endian: bool
    decoder_fn: Incomplete
    def from_type_str(cls, abi_type, registry): ...

class AddressDecoder(Fixed32ByteSizeDecoder[HexAddress]):
    value_bit_size: Incomplete
    is_big_endian: bool
    decoder_fn: Incomplete
    def from_type_str(cls, abi_type, registry): ...

class UnsignedIntegerDecoder(Fixed32ByteSizeDecoder[int]):
    decoder_fn: staticmethod[[bytes], int]
    is_big_endian: bool
    def from_type_str(cls, abi_type, registry): ...

decode_uint_256: Incomplete

class UnsignedIntegerDecoderCached(UnsignedIntegerDecoder):
    decoder_fn: Callable[[bytes], int]
    maxsize: Final[int | None]
    def __init__(self, maxsize: int | None = None, **kwargs: Any) -> None: ...

class SignedIntegerDecoder(Fixed32ByteSizeDecoder[int]):
    is_big_endian: bool
    def __init__(self, **kwargs: Any) -> None: ...
    @cached_property
    def neg_threshold(self) -> int: ...
    @cached_property
    def neg_offset(self) -> int: ...
    def decoder_fn(self, data: bytes) -> int: ...
    def validate_padding_bytes(self, value: Any, padding_bytes: bytes) -> None: ...
    def from_type_str(cls, abi_type, registry): ...

class SignedIntegerDecoderCached(SignedIntegerDecoder):
    decoder_fn: Callable[[bytes], int]
    maxsize: Final[int | None]
    def __init__(self, maxsize: int | None = None, **kwargs: Any) -> None: ...

class BytesDecoder(Fixed32ByteSizeDecoder[bytes]):
    is_big_endian: bool
    @staticmethod
    def decoder_fn(data: bytes) -> bytes: ...
    def from_type_str(cls, abi_type, registry): ...

class BaseFixedDecoder(Fixed32ByteSizeDecoder[decimal.Decimal]):
    frac_places: int
    is_big_endian: bool
    @cached_property
    def denominator(self) -> decimal.Decimal: ...
    def validate(self) -> None: ...

class UnsignedFixedDecoder(BaseFixedDecoder):
    def decoder_fn(self, data: bytes) -> decimal.Decimal: ...
    def from_type_str(cls, abi_type, registry): ...

class SignedFixedDecoder(BaseFixedDecoder):
    @cached_property
    def neg_threshold(self) -> int: ...
    @cached_property
    def neg_offset(self) -> int: ...
    @cached_property
    def expected_padding_pos(self) -> bytes: ...
    @cached_property
    def expected_padding_neg(self) -> bytes: ...
    def decoder_fn(self, data: bytes) -> decimal.Decimal: ...
    def validate_padding_bytes(self, value: Any, padding_bytes: bytes) -> None: ...
    def from_type_str(cls, abi_type, registry): ...

class ByteStringDecoder(SingleDecoder[TByteStr]):
    is_dynamic: bool
    @staticmethod
    def decoder_fn(data: bytes) -> bytes: ...
    @final
    def read_data_from_stream(self, stream: ContextFramesBytesIO) -> bytes: ...
    def validate_padding_bytes(self, value: Any, padding_bytes: bytes) -> None: ...
    def from_type_str(cls, abi_type, registry): ...

class StringDecoder(ByteStringDecoder[str]):
    bytes_errors: Final[Incomplete]
    def __init__(self, handle_string_errors: str = "strict") -> None: ...
    def from_type_str(cls, abi_type, registry): ...
    def decode(self, stream: ContextFramesBytesIO) -> str: ...
    __call__ = decode
    @staticmethod
    def decoder_fn(data: bytes, handle_string_errors: str = "strict") -> str: ...
