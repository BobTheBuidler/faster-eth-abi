from eth_typing import HexAddress as HexAddress
from eth_typing.abi import Decodable as Decodable, TypeStr as TypeStr
from faster_eth_abi._codec import decode_c as decode_c, encode_c as encode_c
from faster_eth_abi.decoding import ContextFramesBytesIO as ContextFramesBytesIO
from faster_eth_abi.exceptions import (
    EncodingError as EncodingError,
    MultipleEntriesFound as MultipleEntriesFound,
)
from faster_eth_abi.registry import ABIRegistry as ABIRegistry
from faster_eth_abi.typing import (
    AddressTypeStr as AddressTypeStr,
    BoolTypeStr as BoolTypeStr,
    BytesTypeStr as BytesTypeStr,
    IntTypeStr as IntTypeStr,
    StringTypeStr as StringTypeStr,
    UintTypeStr as UintTypeStr,
)
from typing import Any, Iterable, overload

DecodesToIntTypeStr = UintTypeStr | IntTypeStr

class BaseABICoder:
    """
    Base class for porcelain coding APIs.  These are classes which wrap
    instances of :class:`~faster_eth_abi.registry.ABIRegistry` to provide last-mile
    coding functionality.
    """

    def __init__(self, registry: ABIRegistry) -> None:
        """
        Constructor.

        :param registry: The registry providing the encoders to be used when
            encoding values.
        """

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

class ABIDecoder(BaseABICoder):
    """
    Wraps a registry to provide last-mile decoding functionality.
    """

    stream_class = ContextFramesBytesIO
    @overload
    def decode(
        self, types: tuple[AddressTypeStr], data: Decodable, strict: bool = True
    ) -> tuple[HexAddress]: ...
    @overload
    def decode(
        self, types: tuple[BytesTypeStr], data: Decodable, strict: bool = True
    ) -> tuple[bytes]: ...
    @overload
    def decode(
        self, types: tuple[StringTypeStr], data: Decodable, strict: bool = True
    ) -> tuple[str]: ...
    @overload
    def decode(
        self, types: tuple[DecodesToIntTypeStr], data: Decodable, strict: bool = True
    ) -> tuple[int]: ...
    @overload
    def decode(
        self, types: tuple[BoolTypeStr], data: Decodable, strict: bool = True
    ) -> tuple[bool]: ...
    @overload
    def decode(
        self, types: tuple[TypeStr], data: Decodable, strict: bool = True
    ) -> tuple[Any]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, str]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, int]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, str]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, int]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, bool]: ...
    @overload
    def decode(
        self, types: tuple[BytesTypeStr, TypeStr], data: Decodable, strict: bool = True
    ) -> tuple[bytes, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, str]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, int]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, bool]: ...
    @overload
    def decode(
        self, types: tuple[StringTypeStr, TypeStr], data: Decodable, strict: bool = True
    ) -> tuple[str, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, str]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, int]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, str]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, int]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, bool]: ...
    @overload
    def decode(
        self, types: tuple[BoolTypeStr, TypeStr], data: Decodable, strict: bool = True
    ) -> tuple[bool, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, HexAddress]: ...
    @overload
    def decode(
        self, types: tuple[TypeStr, BytesTypeStr], data: Decodable, strict: bool = True
    ) -> tuple[Any, bytes]: ...
    @overload
    def decode(
        self, types: tuple[TypeStr, StringTypeStr], data: Decodable, strict: bool = True
    ) -> tuple[Any, str]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, int]: ...
    @overload
    def decode(
        self, types: tuple[TypeStr, BoolTypeStr], data: Decodable, strict: bool = True
    ) -> tuple[Any, bool]: ...
    @overload
    def decode(
        self, types: tuple[TypeStr, TypeStr], data: Decodable, strict: bool = True
    ) -> tuple[Any, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, AddressTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, HexAddress, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, AddressTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, HexAddress, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, AddressTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, HexAddress, str]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, AddressTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, HexAddress, int]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, AddressTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, HexAddress, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, AddressTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, HexAddress, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, BytesTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, bytes, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, BytesTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, bytes, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, BytesTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, bytes, str]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, BytesTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, bytes, int]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, BytesTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, bytes, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, BytesTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, bytes, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, StringTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, str, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, StringTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, str, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, StringTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, str, str]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, StringTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, str, int]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, StringTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, str, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, StringTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, str, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, DecodesToIntTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, int, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, DecodesToIntTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, int, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, DecodesToIntTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, int, str]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, DecodesToIntTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, int, int]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, DecodesToIntTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, int, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, DecodesToIntTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, int, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, BoolTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, bool, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, BoolTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, bool, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, BoolTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, bool, str]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, BoolTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, bool, int]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, BoolTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, bool, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, BoolTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, bool, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, TypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, Any, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, TypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, Any, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, TypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, Any, str]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, TypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, Any, int]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, TypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, Any, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[AddressTypeStr, TypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress, Any, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, AddressTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, HexAddress, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, AddressTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, HexAddress, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, AddressTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, HexAddress, str]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, AddressTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, HexAddress, int]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, AddressTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, HexAddress, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, AddressTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, HexAddress, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, BytesTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, bytes, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, BytesTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, bytes, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, BytesTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, bytes, str]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, BytesTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, bytes, int]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, BytesTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, bytes, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, BytesTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, bytes, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, StringTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, str, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, StringTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, str, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, StringTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, str, str]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, StringTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, str, int]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, StringTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, str, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, StringTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, str, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, DecodesToIntTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, int, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, DecodesToIntTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, int, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, DecodesToIntTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, int, str]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, DecodesToIntTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, int, int]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, DecodesToIntTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, int, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, DecodesToIntTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, int, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, BoolTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, bool, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, BoolTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, bool, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, BoolTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, bool, str]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, BoolTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, bool, int]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, BoolTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, bool, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, BoolTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, bool, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, TypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, Any, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, TypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, Any, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, TypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, Any, str]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, TypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, Any, int]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, TypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, Any, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[BytesTypeStr, TypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes, Any, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, AddressTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, HexAddress, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, AddressTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, HexAddress, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, AddressTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, HexAddress, str]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, AddressTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, HexAddress, int]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, AddressTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, HexAddress, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, AddressTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, HexAddress, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, BytesTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, bytes, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, BytesTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, bytes, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, BytesTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, bytes, str]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, BytesTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, bytes, int]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, BytesTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, bytes, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, BytesTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, bytes, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, StringTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, str, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, StringTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, str, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, StringTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, str, str]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, StringTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, str, int]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, StringTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, str, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, StringTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, str, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, DecodesToIntTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, int, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, DecodesToIntTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, int, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, DecodesToIntTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, int, str]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, DecodesToIntTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, int, int]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, DecodesToIntTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, int, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, DecodesToIntTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, int, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, BoolTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, bool, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, BoolTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, bool, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, BoolTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, bool, str]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, BoolTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, bool, int]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, BoolTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, bool, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, BoolTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, bool, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, TypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, Any, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, TypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, Any, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, TypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, Any, str]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, TypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, Any, int]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, TypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, Any, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[StringTypeStr, TypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str, Any, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, AddressTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, HexAddress, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, AddressTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, HexAddress, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, AddressTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, HexAddress, str]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, AddressTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, HexAddress, int]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, AddressTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, HexAddress, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, AddressTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, HexAddress, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, BytesTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, bytes, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, BytesTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, bytes, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, BytesTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, bytes, str]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, BytesTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, bytes, int]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, BytesTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, bytes, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, BytesTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, bytes, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, StringTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, str, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, StringTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, str, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, StringTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, str, str]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, StringTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, str, int]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, StringTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, str, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, StringTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, str, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, DecodesToIntTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, int, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, DecodesToIntTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, int, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, DecodesToIntTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, int, str]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, DecodesToIntTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, int, int]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, DecodesToIntTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, int, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, DecodesToIntTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, int, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, BoolTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, bool, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, BoolTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, bool, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, BoolTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, bool, str]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, BoolTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, bool, int]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, BoolTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, bool, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, BoolTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, bool, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, TypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, Any, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, TypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, Any, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, TypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, Any, str]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, TypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, Any, int]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, TypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, Any, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[DecodesToIntTypeStr, TypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int, Any, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, AddressTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, HexAddress, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, AddressTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, HexAddress, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, AddressTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, HexAddress, str]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, AddressTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, HexAddress, int]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, AddressTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, HexAddress, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, AddressTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, HexAddress, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, BytesTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, bytes, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, BytesTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, bytes, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, BytesTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, bytes, str]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, BytesTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, bytes, int]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, BytesTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, bytes, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, BytesTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, bytes, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, StringTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, str, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, StringTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, str, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, StringTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, str, str]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, StringTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, str, int]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, StringTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, str, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, StringTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, str, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, DecodesToIntTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, int, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, DecodesToIntTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, int, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, DecodesToIntTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, int, str]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, DecodesToIntTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, int, int]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, DecodesToIntTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, int, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, DecodesToIntTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, int, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, BoolTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, bool, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, BoolTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, bool, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, BoolTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, bool, str]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, BoolTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, bool, int]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, BoolTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, bool, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, BoolTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, bool, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, TypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, Any, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, TypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, Any, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, TypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, Any, str]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, TypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, Any, int]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, TypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, Any, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[BoolTypeStr, TypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bool, Any, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, AddressTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, HexAddress, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, AddressTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, HexAddress, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, AddressTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, HexAddress, str]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, AddressTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, HexAddress, int]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, AddressTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, HexAddress, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, AddressTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, HexAddress, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, BytesTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, bytes, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, BytesTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, bytes, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, BytesTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, bytes, str]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, BytesTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, bytes, int]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, BytesTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, bytes, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, BytesTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, bytes, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, StringTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, str, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, StringTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, str, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, StringTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, str, str]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, StringTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, str, int]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, StringTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, str, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, StringTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, str, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, DecodesToIntTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, int, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, DecodesToIntTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, int, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, DecodesToIntTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, int, str]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, DecodesToIntTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, int, int]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, DecodesToIntTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, int, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, DecodesToIntTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, int, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, BoolTypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, bool, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, BoolTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, bool, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, BoolTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, bool, str]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, BoolTypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, bool, int]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, BoolTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, bool, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, BoolTypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, bool, Any]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, TypeStr, AddressTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, Any, HexAddress]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, TypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, Any, bytes]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, TypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, Any, str]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, TypeStr, DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, Any, int]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, TypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, Any, bool]: ...
    @overload
    def decode(
        self,
        types: tuple[TypeStr, TypeStr, TypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[Any, Any, Any]: ...
    @overload
    def decode(
        self, types: Iterable[AddressTypeStr], data: Decodable, strict: bool = True
    ) -> tuple[HexAddress, ...]: ...
    @overload
    def decode(
        self, types: Iterable[BytesTypeStr], data: Decodable, strict: bool = True
    ) -> tuple[bytes, ...]: ...
    @overload
    def decode(
        self, types: Iterable[StringTypeStr], data: Decodable, strict: bool = True
    ) -> tuple[str, ...]: ...
    @overload
    def decode(
        self, types: Iterable[DecodesToIntTypeStr], data: Decodable, strict: bool = True
    ) -> tuple[int, ...]: ...
    @overload
    def decode(
        self, types: Iterable[BoolTypeStr], data: Decodable, strict: bool = True
    ) -> tuple[bool, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[AddressTypeStr | BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress | bytes, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[AddressTypeStr | StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress | str, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[AddressTypeStr | DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress | int, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[AddressTypeStr | BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress | bool, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[BytesTypeStr | StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes | str, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[BytesTypeStr | DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes | int, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[BytesTypeStr | BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes | bool, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[StringTypeStr | DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str | int, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[StringTypeStr | BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str | bool, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[DecodesToIntTypeStr | BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[int | bool, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[AddressTypeStr | BytesTypeStr | StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress | bytes | str, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[AddressTypeStr | BytesTypeStr | DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress | bytes | int, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[AddressTypeStr | BytesTypeStr | BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress | bytes | bool, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[AddressTypeStr | StringTypeStr | DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress | str | int, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[AddressTypeStr | StringTypeStr | BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress | str | bool, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[AddressTypeStr | DecodesToIntTypeStr | BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress | int | bool, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[BytesTypeStr | StringTypeStr | DecodesToIntTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes | str | int, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[BytesTypeStr | StringTypeStr | BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes | str | bool, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[BytesTypeStr | DecodesToIntTypeStr | BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes | int | bool, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[StringTypeStr | DecodesToIntTypeStr | BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[str | int | bool, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[
            AddressTypeStr | BytesTypeStr | StringTypeStr | DecodesToIntTypeStr
        ],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress | bytes | str | int, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[AddressTypeStr | BytesTypeStr | StringTypeStr | BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress | bytes | str | bool, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[
            AddressTypeStr | BytesTypeStr | DecodesToIntTypeStr | BoolTypeStr
        ],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress | bytes | int | bool, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[
            AddressTypeStr | StringTypeStr | DecodesToIntTypeStr | BoolTypeStr
        ],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[AddressTypeStr | str | int | bool, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[
            BytesTypeStr | StringTypeStr | DecodesToIntTypeStr | BoolTypeStr
        ],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[bytes | str | int | bool, ...]: ...
    @overload
    def decode(
        self,
        types: Iterable[
            AddressTypeStr
            | BytesTypeStr
            | StringTypeStr
            | DecodesToIntTypeStr
            | BoolTypeStr
        ],
        data: Decodable,
        strict: bool = True,
    ) -> tuple[HexAddress | bytes | str | int | bool, ...]: ...
    @overload
    def decode(
        self, types: Iterable[TypeStr], data: Decodable, strict: bool = True
    ) -> tuple[Any, ...]: ...

class ABICodec(ABIEncoder, ABIDecoder): ...
