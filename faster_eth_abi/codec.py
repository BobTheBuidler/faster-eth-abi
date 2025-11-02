# mypy: disable-error-code="overload-overlap"
"""
API for ABI encoding and decoding.

Defines the main encoder and decoder classes, providing methods for binary serialization
and deserialization of values according to ABI type specifications.
"""

from typing import (
    Any,
    Iterable,
    Tuple,
    Union,
    overload,
)

from eth_typing import (
    HexAddress,
)
from eth_typing.abi import (
    Decodable,
    TypeStr,
)

from faster_eth_abi._codec import (
    decode_c,
    encode_c,
)
from faster_eth_abi.decoding import (
    ContextFramesBytesIO,
)
from faster_eth_abi.exceptions import (
    EncodingError,
    MultipleEntriesFound,
)
from faster_eth_abi.registry import (
    ABIRegistry,
)
from faster_eth_abi.typing import (
    AddressTypeStr,
    BoolTypeStr,
    BytesTypeStr,
    IntTypeStr,
    StringTypeStr,
    UintTypeStr,
)

DecodesToIntTypeStr = Union[UintTypeStr, IntTypeStr]


class BaseABICoder:
    """
    Base class for porcelain coding APIs.  These are classes which wrap
    instances of :class:`~faster_eth_abi.registry.ABIRegistry` to provide last-mile
    coding functionality.
    """

    def __init__(self, registry: ABIRegistry):
        """
        Constructor.

        :param registry: The registry providing the encoders to be used when
            encoding values.
        """
        self._registry = registry


class ABIEncoder(BaseABICoder):
    """
    Wraps a registry to provide last-mile encoding functionality.
    """

    def encode(self, types: Iterable[TypeStr], args: Iterable[Any]) -> bytes:
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
        return encode_c(self, types, args)

    def is_encodable(self, typ: TypeStr, arg: Any) -> bool:
        """
        Determines if the python value ``arg`` is encodable as a value of the
        ABI type ``typ``.

        :param typ: A string representation for the ABI type against which the
            python value ``arg`` will be checked e.g. ``'uint256'``,
            ``'bytes[]'``, ``'(int,int)'``, etc.
        :param arg: The python value whose encodability should be checked.

        :returns: ``True`` if ``arg`` is encodable as a value of the ABI type
            ``typ``.  Otherwise, ``False``.
        """
        try:
            encoder = self._registry.get_encoder(typ)
        except MultipleEntriesFound:
            raise
        except Exception:
            return False

        validate = getattr(encoder, "validate_value", encoder)
        try:
            validate(arg)
        except EncodingError:
            return False

        return True

    def is_encodable_type(self, typ: TypeStr) -> bool:
        """
        Returns ``True`` if values for the ABI type ``typ`` can be encoded by
        this codec.

        :param typ: A string representation for the ABI type that will be
            checked for encodability e.g. ``'uint256'``, ``'bytes[]'``,
            ``'(int,int)'``, etc.

        :returns: ``True`` if values for ``typ`` can be encoded by this codec.
            Otherwise, ``False``.
        """
        return self._registry.has_encoder(typ)


class ABIDecoder(BaseABICoder):
    """
    Wraps a registry to provide last-mile decoding functionality.
    """

    stream_class = ContextFramesBytesIO

    # raw tuple types, same type

    # len == 1

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any]:
        ...

    # len == 2

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, Any]:
        ...

    # len == 3
    # okay get ready for some ugly overloads
    # We will probably not implement lengths > 3

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, AddressTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, HexAddress, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, AddressTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, HexAddress, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, AddressTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, HexAddress, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, AddressTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, HexAddress, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, AddressTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, HexAddress, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, AddressTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, HexAddress, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, BytesTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, bytes, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, BytesTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, bytes, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, BytesTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, bytes, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, BytesTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, bytes, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, BytesTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, bytes, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, BytesTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, bytes, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, StringTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, str, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, StringTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, str, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, StringTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, str, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, StringTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, str, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, StringTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, str, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, StringTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, str, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, DecodesToIntTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, int, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, DecodesToIntTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, int, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, DecodesToIntTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, int, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, DecodesToIntTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, int, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, DecodesToIntTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, int, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, DecodesToIntTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, int, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, BoolTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, bool, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, BoolTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, bool, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, BoolTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, bool, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, BoolTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, bool, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, BoolTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, bool, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, BoolTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, bool, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, TypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, Any, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, TypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, Any, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, TypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, Any, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, TypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, Any, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, TypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, Any, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[AddressTypeStr, TypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, Any, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, AddressTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, HexAddress, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, AddressTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, HexAddress, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, AddressTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, HexAddress, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, AddressTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, HexAddress, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, AddressTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, HexAddress, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, AddressTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, HexAddress, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, BytesTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, bytes, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, BytesTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, bytes, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, BytesTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, bytes, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, BytesTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, bytes, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, BytesTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, bytes, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, BytesTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, bytes, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, StringTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, str, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, StringTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, str, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, StringTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, str, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, StringTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, str, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, StringTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, str, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, StringTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, str, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, DecodesToIntTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, int, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, DecodesToIntTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, int, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, DecodesToIntTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, int, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, DecodesToIntTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, int, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, DecodesToIntTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, int, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, DecodesToIntTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, int, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, BoolTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, bool, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, BoolTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, bool, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, BoolTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, bool, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, BoolTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, bool, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, BoolTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, bool, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, BoolTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, bool, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, TypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, Any, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, TypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, Any, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, TypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, Any, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, TypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, Any, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, TypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, Any, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, TypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, Any, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, AddressTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, HexAddress, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, AddressTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, HexAddress, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, AddressTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, HexAddress, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, AddressTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, HexAddress, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, AddressTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, HexAddress, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, AddressTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, HexAddress, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, BytesTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, bytes, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, BytesTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, bytes, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, BytesTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, bytes, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, BytesTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, bytes, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, BytesTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, bytes, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, BytesTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, bytes, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, StringTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, str, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, StringTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, str, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, StringTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, str, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, StringTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, str, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, StringTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, str, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, StringTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, str, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, DecodesToIntTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, int, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, DecodesToIntTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, int, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, DecodesToIntTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, int, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, DecodesToIntTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, int, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, DecodesToIntTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, int, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, DecodesToIntTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, int, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, BoolTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, bool, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, BoolTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, bool, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, BoolTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, bool, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, BoolTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, bool, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, BoolTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, bool, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, BoolTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, bool, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, TypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, Any, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, TypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, Any, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, TypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, Any, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, TypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, Any, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, TypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, Any, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, TypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, Any, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, AddressTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, HexAddress, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, AddressTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, HexAddress, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, AddressTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, HexAddress, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, AddressTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, HexAddress, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, AddressTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, HexAddress, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, AddressTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, HexAddress, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, BytesTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bytes, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, BytesTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bytes, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, BytesTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bytes, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, BytesTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bytes, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, BytesTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bytes, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, BytesTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bytes, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, StringTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, str, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, StringTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, str, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, StringTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, str, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, StringTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, str, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, StringTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, str, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, StringTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, str, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, DecodesToIntTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, int, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, DecodesToIntTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, int, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, DecodesToIntTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, int, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, DecodesToIntTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, int, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, DecodesToIntTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, int, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, DecodesToIntTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, int, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, BoolTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bool, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, BoolTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bool, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, BoolTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bool, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, BoolTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bool, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, BoolTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bool, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, BoolTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bool, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, TypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, Any, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, TypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, Any, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, TypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, Any, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, TypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, Any, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, TypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, Any, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodesToIntTypeStr, TypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, Any, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, AddressTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, HexAddress, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, AddressTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, HexAddress, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, AddressTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, HexAddress, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, AddressTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, HexAddress, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, AddressTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, HexAddress, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, AddressTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, HexAddress, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, BytesTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, bytes, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, BytesTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, bytes, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, BytesTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, bytes, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, BytesTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, bytes, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, BytesTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, bytes, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, BytesTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, bytes, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, StringTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, str, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, StringTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, str, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, StringTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, str, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, StringTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, str, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, StringTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, str, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, StringTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, str, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, DecodesToIntTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, int, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, DecodesToIntTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, int, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, DecodesToIntTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, int, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, DecodesToIntTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, int, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, DecodesToIntTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, int, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, DecodesToIntTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, int, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, BoolTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, bool, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, BoolTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, bool, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, BoolTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, bool, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, BoolTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, bool, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, BoolTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, bool, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, BoolTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, bool, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, TypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, Any, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, TypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, Any, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, TypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, Any, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, TypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, Any, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, TypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, Any, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, TypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, Any, Any]:
        ...

    # --- Fallbacks for len == 3 ---

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, AddressTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, HexAddress, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, AddressTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, HexAddress, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, AddressTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, HexAddress, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, AddressTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, HexAddress, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, AddressTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, HexAddress, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, AddressTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, HexAddress, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, BytesTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, bytes, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, BytesTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, bytes, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, BytesTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, bytes, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, BytesTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, bytes, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, BytesTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, bytes, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, BytesTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, bytes, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, StringTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, str, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, StringTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, str, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, StringTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, str, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, StringTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, str, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, StringTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, str, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, StringTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, str, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, DecodesToIntTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, int, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, DecodesToIntTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, int, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, DecodesToIntTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, int, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, DecodesToIntTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, int, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, DecodesToIntTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, int, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, DecodesToIntTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, int, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, BoolTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, bool, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, BoolTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, bool, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, BoolTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, bool, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, BoolTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, bool, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, BoolTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, bool, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, BoolTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, bool, Any]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, TypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, Any, HexAddress]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, TypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, Any, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, TypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, Any, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, TypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, Any, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, TypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, Any, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[TypeStr, TypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, Any, Any]:
        ...

    # non-tuple types input

    @overload
    def decode(
        self,
        types: Iterable[AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[HexAddress, ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, ...]:
        ...

    # fallback to union types, still better than Any

    @overload
    def decode(
        self,
        types: Iterable[Union[AddressTypeStr, BytesTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[HexAddress, bytes], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[AddressTypeStr, StringTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[HexAddress, str], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[AddressTypeStr, DecodesToIntTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[HexAddress, int], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[AddressTypeStr, BoolTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[HexAddress, bool], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[BytesTypeStr, StringTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[bytes, str], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[BytesTypeStr, DecodesToIntTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[bytes, int], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[BytesTypeStr, BoolTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[bytes, bool], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[StringTypeStr, DecodesToIntTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[str, int], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[StringTypeStr, BoolTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[str, bool], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[DecodesToIntTypeStr, BoolTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[int, bool], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[AddressTypeStr, BytesTypeStr, StringTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[HexAddress, bytes, str], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[AddressTypeStr, BytesTypeStr, DecodesToIntTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[HexAddress, bytes, int], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[AddressTypeStr, BytesTypeStr, BoolTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[HexAddress, bytes, bool], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[AddressTypeStr, StringTypeStr, DecodesToIntTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[HexAddress, str, int], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[AddressTypeStr, StringTypeStr, BoolTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[HexAddress, str, bool], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[AddressTypeStr, DecodesToIntTypeStr, BoolTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[HexAddress, int, bool], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[BytesTypeStr, StringTypeStr, DecodesToIntTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[bytes, str, int], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[BytesTypeStr, StringTypeStr, BoolTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[bytes, str, bool], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[BytesTypeStr, DecodesToIntTypeStr, BoolTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[bytes, int, bool], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[StringTypeStr, DecodesToIntTypeStr, BoolTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[str, int, bool], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[
            Union[AddressTypeStr, BytesTypeStr, StringTypeStr, DecodesToIntTypeStr]
        ],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[HexAddress, bytes, str, int], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[
            Union[AddressTypeStr, BytesTypeStr, StringTypeStr, BoolTypeStr]
        ],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[HexAddress, bytes, str, bool], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[
            Union[AddressTypeStr, BytesTypeStr, DecodesToIntTypeStr, BoolTypeStr]
        ],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[HexAddress, bytes, int, bool], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[
            Union[AddressTypeStr, StringTypeStr, DecodesToIntTypeStr, BoolTypeStr]
        ],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[AddressTypeStr, str, int, bool], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[
            Union[BytesTypeStr, StringTypeStr, DecodesToIntTypeStr, BoolTypeStr]
        ],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[bytes, str, int, bool], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[
            Union[
                AddressTypeStr,
                BytesTypeStr,
                StringTypeStr,
                DecodesToIntTypeStr,
                BoolTypeStr,
            ]
        ],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[HexAddress, bytes, str, int, bool], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Any, ...]:
        ...

    def decode(
        self,
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
        return decode_c(self, types, data, strict)


class ABICodec(ABIEncoder, ABIDecoder):
    pass
