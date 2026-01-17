from eth_typing import Decodable as Decodable, TypeStr as TypeStr
from faster_eth_abi.codec import ABIDecoder as ABIDecoder, ABIEncoder as ABIEncoder
from faster_eth_abi.utils.validation import validate_bytes_param as validate_bytes_param
from typing import Any, Iterable

def encode_c(self, types: Iterable[TypeStr], args: Iterable[Any]) -> bytes:
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

def decode_c(
    self, types: Iterable[TypeStr], data: Decodable, strict: bool = True
) -> tuple[Any, ...]:
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
