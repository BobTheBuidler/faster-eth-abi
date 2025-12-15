"""Private helpers for encoding logic, intended for C compilation.

This file exists because the original encoding.py is not ready to be fully compiled to C.
This module contains functions and logic that we do wish to compile.
"""
import codecs
import decimal
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Final,
    List,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
)

from faster_eth_utils import (
    is_list_like,
)

from faster_eth_abi.exceptions import (
    IllegalValue,
    ValueOutOfBounds,
)
from faster_eth_abi.utils.localcontext import (
    DECIMAL_CONTEXT,
)
from faster_eth_abi.utils.numeric import (
    ceil32,
)
from faster_eth_abi.utils.padding import (
    zpad_right,
)

if TYPE_CHECKING:
    from faster_eth_abi.encoding import (
        BaseArrayEncoder,
        BaseEncoder,
        BaseFixedEncoder,
        PackedArrayEncoder,
        SizedArrayEncoder,
        SignedFixedEncoder,
        TupleEncoder,
        UnsignedFixedEncoder,
    )


T = TypeVar("T")

__encode: Final = codecs.encode


# TupleEncoder
def validate_tuple(self: "TupleEncoder", value: Sequence[Any]) -> None:
    # TODO: maybe try functools.singledispatch here

    validators = self.validators
    expected_length = len(validators)
        
    # we can make more optimized C code by splitting this block by `value` type
    if isinstance(value, list):
        if len(lst := value) != expected_length:
            self.invalidate_value(
                lst,
                exc=ValueOutOfBounds,
                msg=f"value has {len(lst)} items when {expected_length} were expected",
            )
    
        for item, validator in zip(value, validators):
            validator(item)

    elif isinstance(value, tuple):
        if len(tup := value) != expected_length:
            self.invalidate_value(
                tup,
                exc=ValueOutOfBounds,
                msg=f"value has {len(tup)} items when {expected_length} were expected",
            )
    
        for item, validator in zip(value, validators):
            validator(item)

    elif is_list_like(value):
        if len(value) != expected_length:
            self.invalidate_value(
                value,
                exc=ValueOutOfBounds,
                msg=f"value has {len(value)} items when {expected_length} were expected",
            )
    
        for item, validator in zip(value, validators):
            validator(item)

    else:
        self.invalidate_value(
            value,
            msg="must be list-like object such as array or tuple",
        )


def encode_tuple(self: "TupleEncoder", values: Sequence[Any]) -> bytes:
    validate_tuple(self, values)
    head_length = 0
    raw_head_chunks: List[Optional[bytes]] = []
    tail_chunks: List[bytes] = []
    
    # we can make more optimized C code by splitting this block by `values` type
    if isinstance(values, tuple):
        for value, encoder, is_dynamic in zip(values, self.encoders, self._is_dynamic):
            if is_dynamic:
                raw_head_chunks.append(None)
                head_length += 32
                tail_chunks.append(encoder(value))
            else:
                chunk = encoder(value)
                raw_head_chunks.append(chunk)
                head_length += len(chunk)
                tail_chunks.append(b"")
    elif isinstance(values, list):
        for value, encoder, is_dynamic in zip(values, self.encoders, self._is_dynamic):
            if is_dynamic:
                raw_head_chunks.append(None)
                head_length += 32
                tail_chunks.append(encoder(value))
            else:
                chunk = encoder(value)
                raw_head_chunks.append(chunk)
                head_length += len(chunk)
                tail_chunks.append(b"")
    else:
        for value, encoder, is_dynamic in zip(values, self.encoders, self._is_dynamic):
            if is_dynamic:
                raw_head_chunks.append(None)
                head_length += 32
                tail_chunks.append(encoder(value))
            else:
                chunk = encoder(value)
                raw_head_chunks.append(chunk)
                head_length += len(chunk)
                tail_chunks.append(b"")

    tail_offsets = [0]
    total_offset = 0
    for item in tail_chunks[:-1]:
        total_offset += len(item)
        tail_offsets.append(total_offset)

    head_chunks = tuple(
        encode_uint_256(head_length + offset) if chunk is None else chunk
        for chunk, offset in zip(raw_head_chunks, tail_offsets)
    )

    return b"".join(head_chunks) + b"".join(tail_chunks)


def encode_tuple_all_dynamic(self: "TupleEncoder", values: Sequence[Any]) -> bytes:
    validate_tuple(self, values)
    encoders = self.encoders

    # we can make more optimized C code by splitting this line by `values` type
    if isinstance(values, tuple):
        tail_chunks = [encoder(value) for encoder, value in zip(encoders, values)]
    elif isinstance(values, list):
        tail_chunks = [encoder(value) for encoder, value in zip(encoders, values)]
    else:
        tail_chunks = [encoder(value) for encoder, value in zip(encoders, values)]

    total_offset = 0
    head_length = 32 * len(encoders)
    head_chunks = [encode_uint_256(head_length)]
    for item in tail_chunks[:-1]:
        total_offset += len(item)
        head_chunks.append(encode_uint_256(head_length + total_offset))

    return b"".join(head_chunks) + b"".join(tail_chunks)


def encode_tuple_no_dynamic(self: "TupleEncoder", values: Sequence[Any]) -> bytes:
    validate_tuple(self, values)
    encoders = self.encoders
    
    # we can make more optimized C code by splitting this line by `values` type
    if isinstance(values, tuple):
        return b"".join(encoders[i](values[i]) for i in range(len(encoders)))
    elif isinstance(values, list):
        return b"".join(encoders[i](values[i]) for i in range(len(encoders)))
    else:
        return b"".join(encoders[i](values[i]) for i in range(len(encoders)))


def encode_tuple_no_dynamic1(self: "TupleEncoder", values: Sequence[Any]) -> bytes:
    validate_tuple(self, values)
    encoders: Tuple["BaseEncoder"] = self.encoders
    
    # we can make more optimized C code by splitting this line by `values` type
    if isinstance(values, tuple):
        return encoders[0](values[0])
    elif isinstance(values, list):
        return encoders[0](values[0])
    else:
        return encoders[0](values[0])


def encode_tuple_no_dynamic2(self: "TupleEncoder", values: Sequence[Any]) -> bytes:
    validate_tuple(self, values)
    encoders = self.encoders
    # encoders: Tuple["BaseEncoder", "BaseEncoder"] = self.encoders
    
    # we can make more optimized C code by splitting this line by `values` type
    if isinstance(values, tuple):
        return encoders[0]((tup := values)[0]) + encoders[1](tup[1])
    elif isinstance(values, list):
        return encoders[0]((lst := values)[0]) + encoders[1](lst[1])
    else:
        return encoders[0](values[0]) + encoders[1](values[1])


def encode_tuple_no_dynamic3(self: "TupleEncoder", values: Sequence[Any]) -> bytes:
    validate_tuple(self, values)
    encoders = self.encoders
    # encoders: Tuple["BaseEncoder", "BaseEncoder", "BaseEncoder"] = self.encoders
    
    # we can make more optimized C code by splitting this line by `values` type
    if isinstance(values, tuple):
        return b"".join(encoders[i](values[i]) for i in range(3))
    elif isinstance(values, list):
        return b"".join(encoders[i](values[i]) for i in range(3))
    else:
        return b"".join(encoders[i](values[i]) for i in range(3))


def encode_tuple_no_dynamic4(self: "TupleEncoder", values: Sequence[Any]) -> bytes:
    validate_tuple(self, values)
    encoders = self.encoders
    # encoders: Tuple["BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder"] = self.encoders
    
    # we can make more optimized C code by splitting this line by `values` type
    if isinstance(values, tuple):
        return b"".join(encoders[i](values[i]) for i in range(4))
    elif isinstance(values, list):
        return b"".join(encoders[i](values[i]) for i in range(4))
    else:
        return b"".join(encoders[i](values[i]) for i in range(4))


def encode_tuple_no_dynamic5(self: "TupleEncoder", values: Sequence[Any]) -> bytes:
    validate_tuple(self, values)
    encoders = self.encoders
    # encoders: Tuple["BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder"] = self.encoders
    
    # we can make more optimized C code by splitting this line by `values` type
    if isinstance(values, tuple):
        return b"".join(encoders[i](values[i]) for i in range(5))
    elif isinstance(values, list):
        return b"".join(encoders[i](values[i]) for i in range(5))
    else:
        return b"".join(encoders[i](values[i]) for i in range(5))


def encode_tuple_no_dynamic6(self: "TupleEncoder", values: Sequence[Any]) -> bytes:
    validate_tuple(self, values)
    encoders = self.encoders
    # encoders: Tuple["BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder"] = self.encoders
    
    # we can make more optimized C code by splitting this line by `values` type
    if isinstance(values, tuple):
        return b"".join(encoders[i](values[i]) for i in range(6))
    elif isinstance(values, list):
        return b"".join(encoders[i](values[i]) for i in range(6))
    else:
        return b"".join(encoders[i](values[i]) for i in range(6))


def encode_tuple_no_dynamic7(self: "TupleEncoder", values: Sequence[Any]) -> bytes:
    validate_tuple(self, values)
    encoders = self.encoders
    # encoders: Tuple["BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder"] = self.encoders
    
    # we can make more optimized C code by splitting this line by `values` type
    if isinstance(values, tuple):
        return b"".join(encoders[i](values[i]) for i in range(7))
    elif isinstance(values, list):
        return b"".join(encoders[i](values[i]) for i in range(7))
    else:
        return b"".join(encoders[i](values[i]) for i in range(7))


def encode_tuple_no_dynamic8(self: "TupleEncoder", values: Sequence[Any]) -> bytes:
    validate_tuple(self, values)
    encoders = self.encoders
    # encoders: Tuple["BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder"] = self.encoders
    
    # we can make more optimized C code by splitting this line by `values` type
    if isinstance(values, tuple):
        return b"".join(encoders[i](values[i]) for i in range(8))
    elif isinstance(values, list):
        return b"".join(encoders[i](values[i]) for i in range(8))
    else:
        return b"".join(encoders[i](values[i]) for i in range(8))


def encode_tuple_no_dynamic9(self: "TupleEncoder", values: Sequence[Any]) -> bytes:
    validate_tuple(self, values)
    encoders = self.encoders
    # encoders: Tuple["BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder"] = self.encoders
    
    # we can make more optimized C code by splitting this line by `values` type
    if isinstance(values, tuple):
        return b"".join(encoders[i](values[i]) for i in range(9))
    elif isinstance(values, list):
        return b"".join(encoders[i](values[i]) for i in range(9))
    else:
        return b"".join(encoders[i](values[i]) for i in range(9))


def encode_tuple_no_dynamic10(self: "TupleEncoder", values: Sequence[Any]) -> bytes:
    validate_tuple(self, values)
    encoders = self.encoders
    # encoders: Tuple["BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder", "BaseEncoder"] = self.encoders
    
    # we can make more optimized C code by splitting this line by `values` type
    if isinstance(values, tuple):
        return b"".join(encoders[i](values[i]) for i in range(10))
    elif isinstance(values, list):
        return b"".join(encoders[i](values[i]) for i in range(10))
    else:
        return b"".join(encoders[i](values[i]) for i in range(10))


encode_tuple_no_dynamic_funcs: Dict[
    int, Callable[["TupleEncoder", Sequence[Any]], bytes]
] = {
    1: encode_tuple_no_dynamic1,
    2: encode_tuple_no_dynamic2,
    3: encode_tuple_no_dynamic3,
    4: encode_tuple_no_dynamic4,
    5: encode_tuple_no_dynamic5,
    6: encode_tuple_no_dynamic6,
    7: encode_tuple_no_dynamic7,
    8: encode_tuple_no_dynamic8,
    9: encode_tuple_no_dynamic9,
    10: encode_tuple_no_dynamic10,
}


# BaseFixedEncoder
def validate_fixed(self: "BaseFixedEncoder", value: decimal.Decimal) -> None:
    with DECIMAL_CONTEXT:
        residue = value % self.precision

    if residue > 0:
        self.invalidate_value(
            value,
            exc=IllegalValue,
            msg=f"residue {residue!r} outside allowed fractional precision of "
            f"{self.frac_places}",
        )


def encode_fixed(
    value: Any,
    encode_fn: Callable[[Any], bytes],
    is_big_endian: bool,
    data_byte_size: int,
) -> bytes:
    base_encoded_value = encode_fn(value)
    if is_big_endian:
        return base_encoded_value.rjust(data_byte_size, b"\x00")
    else:
        return base_encoded_value.ljust(data_byte_size, b"\x00")


# UnsignedFixedEncoder

def encode_unsigned_fixed(self: "UnsignedFixedEncoder", value: decimal.Decimal) -> bytes:
    with DECIMAL_CONTEXT:
        scaled_value = value * self.denominator
        integer_value = int(scaled_value)

    return int_to_big_endian(integer_value)


# SignedFixedEncoder

def encode_signed_fixed(self: "SignedFixedEncoder", value: decimal.Decimal) -> bytes:
    with DECIMAL_CONTEXT:
        scaled_value = value * self.denominator
        integer_value = int(scaled_value)

    unsigned_integer_value = integer_value % self.modulus

    return int_to_big_endian(unsigned_integer_value)


def encode_signed(
    value: T,
    encode_fn: Callable[[T], bytes],
    data_byte_size: int,
) -> bytes:
    base_encoded_value = encode_fn(value)
    if value >= 0:
        return base_encoded_value.rjust(data_byte_size, b"\x00")
    else:
        return base_encoded_value.rjust(data_byte_size, b"\xff")


def encode_bytestring(value: bytes) -> bytes:
    value_length = len(value)
    encoded_size = encode_uint_256(value_length)
    padded_value = zpad_right(value, ceil32(value_length))
    return encoded_size + padded_value


def encode_text(value: str) -> bytes:
    value_as_bytes = __encode(value, "utf8")
    value_length = len(value_as_bytes)

    encoded_size = encode_uint_256(value_length)
    padded_value = zpad_right(value_as_bytes, ceil32(value_length))

    return encoded_size + padded_value


def validate_array(array_encoder: "BaseArrayEncoder", value: Sequence[Any]) -> None:
    # sourcery skip: merge-duplicate-blocks
    # TODO: specialize this func so we can call validate_item at the C level
    
    validate_item = array_encoder.item_encoder.validate_value
    
    # fast path for lists
    if isinstance(value, list):
        for item in value:
            validate_item(item)
    
    # fast path for tuples
    elif isinstance(value, tuple):
        for item in value:
            validate_item(item)

    # slow path for generic sequences
    elif is_list_like(value):
        for item in value:
            validate_item(item)

    # failure path
    else:
        array_encoder.invalidate_value(
            value,
            msg="must be list-like such as array or tuple",
        )

    
def encode_elements(item_encoder: "BaseEncoder", value: Sequence[Any]) -> bytes:
    tail_chunks = tuple(item_encoder(i) for i in value)

    items_are_dynamic: bool = getattr(item_encoder, "is_dynamic", False)
    if not items_are_dynamic or len(value) == 0:
        return b"".join(tail_chunks)

    head_length = 32 * len(value)
    tail_offsets = [0]
    total_offset = 0
    for item in tail_chunks[:-1]:
        total_offset += len(item)
        tail_offsets.append(total_offset)

    head_chunks = tuple(
        encode_uint_256(head_length + offset) for offset in tail_offsets
    )
    return b"".join(head_chunks) + b"".join(tail_chunks)


def validate_packed_array(array_encoder: "PackedArrayEncoder", value: Sequence[Any]) -> None:
    validate_array(array_encoder, value)
    array_size = array_encoder.array_size
    if array_size is not None and len(value) != array_size:
        array_encoder.invalidate_value(
            value,
            exc=ValueOutOfBounds,
            msg=f"value has {len(value)} items when {array_size} were expected",
        )


def validate_sized_array(array_encoder: "SizedArrayEncoder", value: Sequence[Any]) -> None:
    validate_array(array_encoder, value)
    if len(value) != array_encoder.array_size:
        array_encoder.invalidate_value(
            value,
            exc=ValueOutOfBounds,
            msg=f"value has {len(value)} items when {array_encoder.array_size} were "
            "expected",
        )


def encode_elements_dynamic(item_encoder: "BaseEncoder", value: Sequence[Any]) -> bytes:
    encoded_size = encode_uint_256(len(value))
    encoded_elements = encode_elements(item_encoder, value)
    return encoded_size + encoded_elements


def encode_uint_256(i: int) -> bytes:
    # An optimized version of the `encode_uint_256` in `encoding.py` which
    # does not perform any validation. We should not have any issues here
    # unless you're encoding really really massive iterables.
    big_endian = int_to_big_endian(i)
    return big_endian.rjust(32, b"\x00")


def int_to_big_endian(value: int) -> bytes:
    # vendored from eth-utils so it can compile nicely into faster-eth-abi's binary
    return value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
