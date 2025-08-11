from itertools import (
    accumulate,
)
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    List,
    Optional,
    Sequence,
)

if TYPE_CHECKING:
    from faster_eth_abi.encoding import (
        BaseEncoder,
        UnsignedIntegerEncoder,
    )


def encode_tuple(
    values: Sequence[Any],
    encoders: Sequence["BaseEncoder"],
    # this is only here to prevent circ import issues and will be removed
    encode_uint_256: "UnsignedIntegerEncoder",
) -> bytes:
    raw_head_chunks: List[Optional[bytes]] = []
    tail_chunks: List[bytes] = []
    for value, encoder in zip(values, encoders):
        if getattr(encoder, "is_dynamic", False):
            raw_head_chunks.append(None)
            tail_chunks.append(encoder(value))
        else:
            raw_head_chunks.append(encoder(value))
            tail_chunks.append(b"")

    head_length = sum(32 if item is None else len(item) for item in raw_head_chunks)
    tail_offsets = (0, *accumulate(len(item) for item in tail_chunks[:-1]))
    head_chunks = tuple(
        encode_uint_256(head_length + offset) if chunk is None else chunk
        for chunk, offset in zip(raw_head_chunks, tail_offsets)
    )

    return b"".join(head_chunks) + b"".join(tail_chunks)


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


def encode_signed(
    value: int,
    encode_fn: Callable[[int], bytes],
    data_byte_size: int,
) -> bytes:
    base_encoded_value = encode_fn(value)
    if value >= 0:
        return base_encoded_value.rjust(data_byte_size, b"\x00")
    else:
        return base_encoded_value.rjust(data_byte_size, b"\xff")
