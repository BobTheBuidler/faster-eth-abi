import abc
from _typeshed import Incomplete
from decimal import Decimal
from eth_typing.abi import TypeStr as TypeStr
from faster_eth_abi._encoding import (
    encode_bytestring as encode_bytestring,
    encode_elements as encode_elements,
    encode_elements_dynamic as encode_elements_dynamic,
    encode_fixed_bigendian as encode_fixed_bigendian,
    encode_fixed_smallendian as encode_fixed_smallendian,
    encode_signed as encode_signed,
    encode_signed_fixed as encode_signed_fixed,
    encode_text as encode_text,
    encode_tuple as encode_tuple,
    encode_tuple_all_dynamic as encode_tuple_all_dynamic,
    encode_tuple_no_dynamic as encode_tuple_no_dynamic,
    encode_tuple_no_dynamic_funcs as encode_tuple_no_dynamic_funcs,
    encode_unsigned_fixed as encode_unsigned_fixed,
    int_to_big_endian as int_to_big_endian,
    validate_array as validate_array,
    validate_fixed as validate_fixed,
    validate_packed_array as validate_packed_array,
    validate_sized_array as validate_sized_array,
    validate_tuple as validate_tuple,
)
from faster_eth_abi.base import BaseCoder as BaseCoder
from faster_eth_abi.exceptions import (
    EncodingTypeError as EncodingTypeError,
    IllegalValue as IllegalValue,
    ValueOutOfBounds as ValueOutOfBounds,
)
from faster_eth_abi.from_type_str import (
    parse_tuple_type_str as parse_tuple_type_str,
    parse_type_str as parse_type_str,
)
from faster_eth_abi.registry import ABIRegistry as ABIRegistry
from faster_eth_abi.utils.numeric import (
    TEN as TEN,
    compute_signed_fixed_bounds as compute_signed_fixed_bounds,
    compute_signed_integer_bounds as compute_signed_integer_bounds,
    compute_unsigned_fixed_bounds as compute_unsigned_fixed_bounds,
    compute_unsigned_integer_bounds as compute_unsigned_integer_bounds,
)
from faster_eth_abi.utils.string import abbr as abbr
from functools import cached_property as cached_property
from numbers import Number
from typing import Any, Callable, ClassVar, Final, NoReturn, Sequence, final
from typing_extensions import Self, TypeGuard

class BaseEncoder(BaseCoder, metaclass=abc.ABCMeta):
    """
    Base class for all encoder classes.  Subclass this if you want to define a
    custom encoder class.  Subclasses must also implement
    :any:`BaseCoder.from_type_str`.
    """

    @abc.abstractmethod
    def encode(self, value: Any) -> bytes:
        """
        Encodes the given value as a sequence of bytes.  Should raise
        :any:`exceptions.EncodingError` if ``value`` cannot be encoded.
        """

    @abc.abstractmethod
    def validate_value(self, value: Any) -> None:
        """
        Checks whether or not the given value can be encoded by this encoder.
        If the given value cannot be encoded, must raise
        :any:`exceptions.EncodingError`.
        """

    @classmethod
    def invalidate_value(
        cls, value: Any, exc: type[Exception] = ..., msg: str | None = None
    ) -> NoReturn:
        """
        Throws a standard exception for when a value is not encodable by an
        encoder.
        """

    def __call__(self, value: Any) -> bytes: ...

class TupleEncoder(BaseEncoder):
    encoders: tuple[BaseEncoder, ...]
    is_dynamic: Incomplete
    validators: Final[Callable[[Any], None]]
    def __init__(self, encoders: tuple[BaseEncoder, ...], **kwargs: Any) -> None: ...
    def validate(self) -> None: ...
    @final
    def validate_value(self, value: Sequence[Any]) -> None: ...
    def encode(self, values: Sequence[Any]) -> bytes: ...
    def __call__(self, values: Sequence[Any]) -> bytes: ...
    @parse_tuple_type_str
    def from_type_str(cls, abi_type: TypeStr, registry: ABIRegistry) -> Self: ...

class FixedSizeEncoder(BaseEncoder):
    value_bit_size: int
    data_byte_size: int
    encode_fn: Callable[..., Any]
    type_check_fn: Callable[..., bool]
    is_big_endian: bool
    def validate(self) -> None: ...
    def validate_value(self, value: Any) -> None: ...
    def encode(self, value: Any) -> bytes: ...
    __call__ = encode

class Fixed32ByteSizeEncoder(FixedSizeEncoder):
    data_byte_size: int
    def encode(self, value: Any) -> bytes: ...
    __call__ = encode

class BooleanEncoder(Fixed32ByteSizeEncoder):
    value_bit_size: int
    is_big_endian: bool
    @classmethod
    def validate_value(cls, value: Any) -> None: ...
    @classmethod
    def encode_fn(cls, value: bool) -> bytes: ...
    def from_type_str(cls, abi_type: TypeStr, registry: ABIRegistry) -> Self: ...

class PackedBooleanEncoder(BooleanEncoder):
    data_byte_size: int

class NumberEncoder(Fixed32ByteSizeEncoder):
    is_big_endian: bool
    bounds_fn: Callable[[int], tuple[Number, Number]]
    illegal_value_fn: Callable[[Any], bool]
    type_check_fn: Callable[[Any], bool]
    @cached_property
    def bounds(self) -> tuple[Number, Number]: ...
    @cached_property
    def lower_bound(self) -> Number: ...
    @cached_property
    def upper_bound(self) -> Number: ...
    def validate(self) -> None: ...
    def validate_value(self, value: Any) -> None: ...

class UnsignedIntegerEncoder(NumberEncoder):
    encode_fn: Incomplete
    bounds_fn: Incomplete
    type_check_fn: Incomplete
    def from_type_str(cls, abi_type: TypeStr, registry: ABIRegistry) -> Self: ...

class UnsignedIntegerEncoderCached(UnsignedIntegerEncoder):
    encode: Final[Callable[[int], bytes]]
    maxsize: Final[int | None]
    def __init__(self, maxsize: int | None = None, **kwargs: Any) -> None: ...

encode_uint_256: Incomplete

class PackedUnsignedIntegerEncoder(UnsignedIntegerEncoder):
    def from_type_str(cls, abi_type: TypeStr, registry: ABIRegistry) -> Self: ...

class PackedUnsignedIntegerEncoderCached(PackedUnsignedIntegerEncoder):
    encode: Final[Callable[[int], bytes]]
    maxsize: Final[int | None]
    def __init__(self, maxsize: int | None = None, **kwargs: Any) -> None: ...

class SignedIntegerEncoder(NumberEncoder):
    bounds_fn: Incomplete
    type_check_fn: Incomplete
    @cached_property
    def modulus(self) -> int: ...
    def encode_fn(self, value: int) -> bytes: ...
    def encode(self, value: int) -> bytes: ...
    __call__ = encode
    def from_type_str(cls, abi_type: TypeStr, registry: ABIRegistry) -> Self: ...

class SignedIntegerEncoderCached(SignedIntegerEncoder):
    encode: Final[Callable[[int], bytes]]
    maxsize: Final[int | None]
    def __init__(self, maxsize: int | None = None, **kwargs: Any) -> None: ...

class PackedSignedIntegerEncoder(SignedIntegerEncoder):
    def from_type_str(cls, abi_type: TypeStr, registry: ABIRegistry) -> Self: ...

class PackedSignedIntegerEncoderCached(PackedSignedIntegerEncoder):
    encode: Final[Callable[[int], bytes]]
    maxsize: Final[int | None]
    def __init__(self, maxsize: int | None = None, **kwargs: Any) -> None: ...

class BaseFixedEncoder(NumberEncoder):
    frac_places: int
    @staticmethod
    def type_check_fn(value: Any) -> TypeGuard[Number]: ...
    @staticmethod
    def illegal_value_fn(value: Number) -> bool: ...
    @cached_property
    def denominator(self) -> Decimal: ...
    @cached_property
    def precision(self) -> Decimal: ...
    def validate_value(self, value: Any) -> None: ...
    def validate(self) -> None: ...

class UnsignedFixedEncoder(BaseFixedEncoder):
    def bounds_fn(self, value_bit_size): ...
    def encode_fn(self, value: Decimal) -> bytes: ...
    def from_type_str(cls, abi_type: TypeStr, registry: ABIRegistry) -> Self: ...

class PackedUnsignedFixedEncoder(UnsignedFixedEncoder):
    def from_type_str(cls, abi_type: TypeStr, registry: ABIRegistry) -> Self: ...

class SignedFixedEncoder(BaseFixedEncoder):
    def bounds_fn(self, value_bit_size): ...
    @cached_property
    def modulus(self) -> int: ...
    def encode_fn(self, value: Decimal) -> bytes: ...
    def encode(self, value: Decimal) -> bytes: ...
    __call__ = encode
    def from_type_str(cls, abi_type: TypeStr, registry: ABIRegistry) -> Self: ...

class PackedSignedFixedEncoder(SignedFixedEncoder):
    def from_type_str(cls, abi_type: TypeStr, registry: ABIRegistry) -> Self: ...

class AddressEncoder(Fixed32ByteSizeEncoder):
    value_bit_size: Incomplete
    encode_fn: Incomplete
    is_big_endian: bool
    @classmethod
    def validate_value(cls, value: Any) -> None: ...
    def validate(self) -> None: ...
    def from_type_str(cls, abi_type: TypeStr, registry: ABIRegistry) -> Self: ...

class PackedAddressEncoder(AddressEncoder):
    data_byte_size: int

class BytesEncoder(Fixed32ByteSizeEncoder):
    is_big_endian: bool
    def encode(self, value: Any) -> bytes: ...
    __call__ = encode
    @cached_property
    def value_byte_size(self) -> int: ...
    def validate_value(self, value: Any) -> None: ...
    @staticmethod
    def encode_fn(value: bytes) -> bytes: ...
    def from_type_str(cls, abi_type: TypeStr, registry: ABIRegistry) -> Self: ...

class PackedBytesEncoder(BytesEncoder):
    def from_type_str(cls, abi_type: TypeStr, registry: ABIRegistry) -> Self: ...

class ByteStringEncoder(BaseEncoder):
    is_dynamic: bool
    @classmethod
    def validate_value(cls, value: Any) -> None: ...
    @classmethod
    def encode(cls, value: bytes) -> bytes: ...
    __call__: ClassVar[Callable[[type[Self], bytes], bytes]]
    def from_type_str(cls, abi_type: TypeStr, registry: ABIRegistry) -> Self: ...

class PackedByteStringEncoder(ByteStringEncoder):
    is_dynamic: bool
    @classmethod
    def encode(cls, value: bytes) -> bytes: ...
    __call__ = encode

class TextStringEncoder(BaseEncoder):
    is_dynamic: bool
    @classmethod
    def validate_value(cls, value: Any) -> None: ...
    @classmethod
    def encode(cls, value: str) -> bytes: ...
    __call__: ClassVar[Callable[[type[Self], str], bytes]]
    def from_type_str(cls, abi_type: TypeStr, registry: ABIRegistry) -> Self: ...

class PackedTextStringEncoder(TextStringEncoder):
    is_dynamic: bool
    @classmethod
    def encode(cls, value: str) -> bytes: ...
    __call__ = encode

class BaseArrayEncoder(BaseEncoder, metaclass=abc.ABCMeta):
    item_encoder: BaseEncoder
    def validate(self) -> None: ...
    def validate_value(self, value: Any) -> None: ...
    def encode_elements(self, value: Sequence[Any]) -> bytes: ...
    def from_type_str(cls, abi_type: TypeStr, registry: ABIRegistry) -> Self: ...

class PackedArrayEncoder(BaseArrayEncoder):
    array_size: int | None
    def validate_value(self, value: Any) -> None: ...
    def encode(self, value: Sequence[Any]) -> bytes: ...
    __call__ = encode
    def from_type_str(cls, abi_type: TypeStr, registry: ABIRegistry) -> Self: ...

class SizedArrayEncoder(BaseArrayEncoder):
    array_size: int
    is_dynamic: Incomplete
    def __init__(self, **kwargs: Any) -> None: ...
    def validate(self) -> None: ...
    def validate_value(self, value: Any) -> None: ...
    def encode(self, value: Sequence[Any]) -> bytes: ...
    __call__ = encode

class DynamicArrayEncoder(BaseArrayEncoder):
    is_dynamic: bool
    def encode(self, value: Sequence[Any]) -> bytes: ...
