"""Internal codec helpers for encoding and decoding sequences of values using the head-tail mechanism.

Provides encode_c and decode_c functions for binary serialization and deserialization of values
according to ABI type specifications.
"""

from typing import (
    TYPE_CHECKING,
    Any,
    Iterable,
    Tuple,
)

from eth_typing import (
    Decodable,
    TypeStr,
)

from faster_eth_abi.utils.validation import (
    validate_bytes_param,
)

if TYPE_CHECKING:
    from faster_eth_abi.codec import (
        ABIDecoder,
        ABIEncoder,
    )


def encode_c(
    self: "ABIEncoder",
    types: Iterable[TypeStr],
    args: Iterable[Any],
) -> bytes:
    """
    Encodes the python values in ``args`` as a sequence of binary values of
    the ABI types in ``types`` via the head-tail mechanism.

    :param types: A list or tuple of string representations of the ABI types
        that will be used for encoding e.g.  ``('uint256', 'bytes[]',
        '(int,int)')``
    :param args: A list or tuple of python values to be encoded.

    :returns: The head-tail encoded binary representation of the python
        values in ``args`` as values of the ABI types in ``types``.
    """
    if isinstance(args, list):
        args_kind = "list"
    elif isinstance(args, tuple):
        args_kind = "tuple"
    else:
        raise TypeError(
            f"The `args` value type must be one of list or tuple. Got {type(args)}"
        )

    encoder = self._registry.get_tuple_encoder(*types)
    encoder._set_fast_path(args, args_kind)

    return encoder.encode(args)


def decode_c(
    self: "ABIDecoder",
    types: Iterable[TypeStr],
    data: Decodable,
    strict: bool = True,
) -> Tuple[Any, ...]:
    """
    Decodes the binary value ``data`` as a sequence of values of the ABI types
    in ``types`` via the head-tail mechanism into a tuple of equivalent python
    values.

    :param types: A list or tuple of string representations of the ABI types that
        will be used for decoding e.g. ``('uint256', 'bytes[]', '(int,int)')``
    :param data: The binary value to be decoded.
    :param strict: If ``False``, dynamic-type decoders will ignore validations such
        as making sure the data is padded to a multiple of 32 bytes or checking that
        padding bytes are zero / empty. ``False`` is how the Solidity ABI decoder
        currently works. However, ``True`` is the default for the faster-eth-abi
        library.

    :returns: A tuple of equivalent python values for the ABI values
        represented in ``data``.
    """
    validate_bytes_param(data, "data")

    decoder = self._registry.get_tuple_decoder(*types, strict=strict)
    stream = self.stream_class(data)

    return decoder(stream)
