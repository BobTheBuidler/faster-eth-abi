# mypy: disable-error-code="overload-overlap"
from typing import (
    Any,
    Iterable,
    Tuple,
    Union,
    overload,
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
    BoolTypeStr,
    BytesTypeStr,
    IntTypeStr,
    StringTypeStr,
    UintTypeStr,
)

DecodeToInt = Union[UintTypeStr, IntTypeStr]


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
        except:
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
        types: Tuple[DecodeToInt],
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

    # len == 2

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
        types: Tuple[BytesTypeStr, DecodeToInt],
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
        types: Tuple[StringTypeStr, DecodeToInt],
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
        types: Tuple[DecodeToInt, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodeToInt, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodeToInt, DecodeToInt],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodeToInt, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bool]:
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
        types: Tuple[BoolTypeStr, DecodeToInt],
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

    # len == 3
    # okay get ready for some ugly overloads
    # We will probably not implement lengths > 3

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
        types: Tuple[BytesTypeStr, BytesTypeStr, DecodeToInt],
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
        types: Tuple[BytesTypeStr, StringTypeStr, DecodeToInt],
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
        types: Tuple[BytesTypeStr, DecodeToInt, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, int, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, DecodeToInt, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, int, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, DecodeToInt, DecodeToInt],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, int, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BytesTypeStr, DecodeToInt, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bytes, int, bool]:
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
        types: Tuple[BytesTypeStr, BoolTypeStr, DecodeToInt],
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
        types: Tuple[StringTypeStr, BytesTypeStr, DecodeToInt],
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
        types: Tuple[StringTypeStr, StringTypeStr, DecodeToInt],
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
        types: Tuple[StringTypeStr, DecodeToInt, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, int, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, DecodeToInt, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, int, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, DecodeToInt, DecodeToInt],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, int, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[StringTypeStr, DecodeToInt, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[str, int, bool]:
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
        types: Tuple[StringTypeStr, BoolTypeStr, DecodeToInt],
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
        types: Tuple[DecodeToInt, BytesTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bytes, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodeToInt, BytesTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bytes, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodeToInt, BytesTypeStr, DecodeToInt],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bytes, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodeToInt, BytesTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bytes, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodeToInt, StringTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, str, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodeToInt, StringTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, str, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodeToInt, StringTypeStr, DecodeToInt],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, str, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodeToInt, StringTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, str, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodeToInt, DecodeToInt, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, int, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodeToInt, DecodeToInt, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, int, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodeToInt, DecodeToInt, DecodeToInt],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, int, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodeToInt, DecodeToInt, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, int, bool]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodeToInt, BoolTypeStr, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bool, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodeToInt, BoolTypeStr, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bool, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodeToInt, BoolTypeStr, DecodeToInt],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bool, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[DecodeToInt, BoolTypeStr, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[int, bool, bool]:
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
        types: Tuple[BoolTypeStr, BytesTypeStr, DecodeToInt],
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
        types: Tuple[BoolTypeStr, StringTypeStr, DecodeToInt],
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
        types: Tuple[BoolTypeStr, DecodeToInt, BytesTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, int, bytes]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, DecodeToInt, StringTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, int, str]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, DecodeToInt, DecodeToInt],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, int, int]:
        ...

    @overload
    def decode(
        self,
        types: Tuple[BoolTypeStr, DecodeToInt, BoolTypeStr],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[bool, int, bool]:
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
        types: Tuple[BoolTypeStr, BoolTypeStr, DecodeToInt],
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

    # non-tuple types input

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
        types: Iterable[DecodeToInt],
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
        types: Iterable[Union[BytesTypeStr, StringTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[bytes, str], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[BytesTypeStr, DecodeToInt]],
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
        types: Iterable[Union[StringTypeStr, DecodeToInt]],
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
        types: Iterable[Union[DecodeToInt, BoolTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[int, bool], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[BytesTypeStr, StringTypeStr, DecodeToInt]],
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
        types: Iterable[Union[BytesTypeStr, DecodeToInt, BoolTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[bytes, int, bool], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[StringTypeStr, DecodeToInt, BoolTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[str, int, bool], ...]:
        ...

    @overload
    def decode(
        self,
        types: Iterable[Union[BytesTypeStr, StringTypeStr, DecodeToInt, BoolTypeStr]],
        data: Decodable,
        strict: bool = True,
    ) -> Tuple[Union[bytes, str, int, bool], ...]:
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
