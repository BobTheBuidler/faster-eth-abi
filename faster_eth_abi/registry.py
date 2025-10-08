import functools
from copy import (
    copy,
)
from typing import (
    Any,
    Callable,
    Optional,
    Type,
    Union,
)

from eth_typing import (
    TypeStr,
)

from . import (
    decoding,
    encoding,
)
from ._registry import (
    BaseEquals,
    Copyable,
    Equals,
    PredicateMapping,
)
from .base import (
    BaseCoder,
)
from .exceptions import (
    MultipleEntriesFound,
    ParseError,
)
from .grammar import (
    TupleType,
    parse,
)
from .io import (
    ContextFramesBytesIO,
)


Lookup = Union[TypeStr, Callable[[TypeStr], bool]]

EncoderCallable = Callable[[Any], bytes]
DecoderCallable = Callable[[ContextFramesBytesIO], Any]

Encoder = Union[EncoderCallable, Type[encoding.BaseEncoder]]
Decoder = Union[DecoderCallable, Type[decoding.BaseDecoder]]


def has_arrlist(type_str: TypeStr) -> bool:
    """
    A predicate that matches a type string with an array dimension list.
    """
    try:
        abi_type = parse(type_str)
    except (ParseError, ValueError):
        return False

    return abi_type.arrlist is not None


def is_base_tuple(type_str: TypeStr) -> bool:
    """
    A predicate that matches a tuple type with no array dimension list.
    """
    try:
        abi_type = parse(type_str)
    except (ParseError, ValueError):
        return False

    return isinstance(abi_type, TupleType) and abi_type.arrlist is None


def _clear_encoder_cache(old_method: Callable[..., None]) -> Callable[..., None]:
    @functools.wraps(old_method)
    def new_method(self: "ABIRegistry", *args: Any, **kwargs: Any) -> None:
        self.get_encoder.cache_clear()
        self.get_tuple_encoder.cache_clear()
        return old_method(self, *args, **kwargs)

    return new_method


def _clear_decoder_cache(old_method: Callable[..., None]) -> Callable[..., None]:
    @functools.wraps(old_method)
    def new_method(self: "ABIRegistry", *args: Any, **kwargs: Any) -> None:
        self.get_decoder.cache_clear()
        self.get_tuple_decoder.cache_clear()
        return old_method(self, *args, **kwargs)

    return new_method


class BaseRegistry:
    @staticmethod
    def _register(mapping, lookup, value, label=None):
        if callable(lookup):
            mapping.add(lookup, value, label)
            return

        if isinstance(lookup, str):
            mapping.add(Equals(lookup), value, lookup)
            return

        raise TypeError(
            f"Lookup must be a callable or a value of type `str`: got {lookup!r}"
        )

    @staticmethod
    def _unregister(mapping, lookup_or_label):
        if callable(lookup_or_label):
            mapping.remove_by_equality(lookup_or_label)
            return

        if isinstance(lookup_or_label, str):
            mapping.remove_by_label(lookup_or_label)
            return

        raise TypeError(
            f"Lookup/label must be a callable or a value of type `str`: "
            f"got {lookup_or_label!r}"
        )

    @staticmethod
    def _get_registration(mapping, type_str):
        try:
            value = mapping.find(type_str)
        except ValueError as e:
            if "No matching" in e.args[0]:
                # If no matches found, attempt to parse in case lack of matches
                # was due to unparsability
                parse(type_str)

            raise

        return value


class ABIRegistry(Copyable, BaseRegistry):
    def __init__(self):
        self._encoders = PredicateMapping("encoder registry")
        self._decoders = PredicateMapping("decoder registry")
        self.get_encoder = functools.lru_cache(maxsize=None)(self._get_encoder_uncached)
        self.get_decoder = functools.lru_cache(maxsize=None)(self._get_decoder_uncached)
        self.get_tuple_encoder = functools.lru_cache(maxsize=None)(
            self._get_tuple_encoder_uncached
        )
        self.get_tuple_decoder = functools.lru_cache(maxsize=None)(
            self._get_tuple_decoder_uncached
        )

    def _get_registration(self, mapping, type_str):
        coder = super()._get_registration(mapping, type_str)

        if isinstance(coder, type) and issubclass(coder, BaseCoder):
            return coder.from_type_str(type_str, self)

        return coder

    @_clear_encoder_cache
    def register_encoder(
        self, lookup: Lookup, encoder: Encoder, label: Optional[str] = None
    ) -> None:
        """
        Registers the given ``encoder`` under the given ``lookup``.  A unique
        string label may be optionally provided that can be used to refer to
        the registration by name.  For more information about arguments, refer
        to :any:`register`.
        """
        self._register(self._encoders, lookup, encoder, label=label)

    @_clear_encoder_cache
    def unregister_encoder(self, lookup_or_label: Lookup) -> None:
        """
        Unregisters an encoder in the registry with the given lookup or label.
        If ``lookup_or_label`` is a string, the encoder with the label
        ``lookup_or_label`` will be unregistered.  If it is an function, the
        encoder with the lookup function ``lookup_or_label`` will be
        unregistered.
        """
        self._unregister(self._encoders, lookup_or_label)

    @_clear_decoder_cache
    def register_decoder(
        self, lookup: Lookup, decoder: Decoder, label: Optional[str] = None
    ) -> None:
        """
        Registers the given ``decoder`` under the given ``lookup``.  A unique
        string label may be optionally provided that can be used to refer to
        the registration by name.  For more information about arguments, refer
        to :any:`register`.
        """
        self._register(self._decoders, lookup, decoder, label=label)

    @_clear_decoder_cache
    def unregister_decoder(self, lookup_or_label: Lookup) -> None:
        """
        Unregisters a decoder in the registry with the given lookup or label.
        If ``lookup_or_label`` is a string, the decoder with the label
        ``lookup_or_label`` will be unregistered.  If it is an function, the
        decoder with the lookup function ``lookup_or_label`` will be
        unregistered.
        """
        self._unregister(self._decoders, lookup_or_label)

    def register(
        self,
        lookup: Lookup,
        encoder: Encoder,
        decoder: Decoder,
        label: Optional[str] = None,
    ) -> None:
        """
        Registers the given ``encoder`` and ``decoder`` under the given
        ``lookup``.  A unique string label may be optionally provided that can
        be used to refer to the registration by name.

        :param lookup: A type string or type string matcher function
            (predicate).  When the registry is queried with a type string
            ``query`` to determine which encoder or decoder to use, ``query``
            will be checked against every registration in the registry.  If a
            registration was created with a type string for ``lookup``, it will
            be considered a match if ``lookup == query``.  If a registration
            was created with a matcher function for ``lookup``, it will be
            considered a match if ``lookup(query) is True``.  If more than one
            registration is found to be a match, then an exception is raised.

        :param encoder: An encoder callable or class to use if ``lookup``
            matches a query.  If ``encoder`` is a callable, it must accept a
            python value and return a ``bytes`` value.  If ``encoder`` is a
            class, it must be a valid subclass of :any:`encoding.BaseEncoder`
            and must also implement the :any:`from_type_str` method on
            :any:`base.BaseCoder`.

        :param decoder: A decoder callable or class to use if ``lookup``
            matches a query.  If ``decoder`` is a callable, it must accept a
            stream-like object of bytes and return a python value.  If
            ``decoder`` is a class, it must be a valid subclass of
            :any:`decoding.BaseDecoder` and must also implement the
            :any:`from_type_str` method on :any:`base.BaseCoder`.

        :param label: An optional label that can be used to refer to this
            registration by name.  This label can be used to unregister an
            entry in the registry via the :any:`unregister` method and its
            variants.
        """
        self.register_encoder(lookup, encoder, label=label)
        self.register_decoder(lookup, decoder, label=label)

    def unregister(self, label: Optional[str]) -> None:
        """
        Unregisters the entries in the encoder and decoder registries which
        have the label ``label``.
        """
        self.unregister_encoder(label)
        self.unregister_decoder(label)

    def _get_encoder_uncached(self, type_str: TypeStr):  # type: ignore [no-untyped-def]
        return self._get_registration(self._encoders, type_str)

    def _get_tuple_encoder_uncached(
        self, 
        *type_strs: TypeStr,
    ) -> encoding.TupleEncoder:
        return encoding.TupleEncoder(
            encoders=tuple(self.get_encoder(type_str) for type_str in type_strs)
        )

    def has_encoder(self, type_str: TypeStr) -> bool:
        """
        Returns ``True`` if an encoder is found for the given type string
        ``type_str``.  Otherwise, returns ``False``.  Raises
        :class:`~faster_eth_abi.exceptions.MultipleEntriesFound` if multiple encoders
        are found.
        """
        try:
            self.get_encoder(type_str)
        except Exception as e:
            if isinstance(e, MultipleEntriesFound):
                raise e
            return False

        return True

    def _get_decoder_uncached(self, type_str: TypeStr, strict: bool = True):  # type: ignore [no-untyped-def]
        decoder = self._get_registration(self._decoders, type_str)

        if hasattr(decoder, "is_dynamic") and decoder.is_dynamic:
            # Set a transient flag each time a call is made to ``get_decoder()``.
            # Only dynamic decoders should be allowed these looser constraints. All
            # other decoders should keep the default value of ``True``.
            decoder.strict = strict

        return decoder

    def _get_tuple_decoder_uncached(
        self, 
        *type_strs: TypeStr, 
        strict: bool = True,
    ) -> decoding.TupleDecoder:
        return decoding.TupleDecoder(
            decoders=tuple(self.get_decoder(type_str, strict) for type_str in type_strs)
        )

    def copy(self):
        """
        Copies a registry such that new registrations can be made or existing
        registrations can be unregistered without affecting any instance from
        which a copy was obtained.  This is useful if an existing registry
        fulfills most of a user's needs but requires one or two modifications.
        In that case, a copy of that registry can be obtained and the necessary
        changes made without affecting the original registry.
        """
        cpy = type(self)()

        cpy._encoders = copy(self._encoders)
        cpy._decoders = copy(self._decoders)

        return cpy


registry = ABIRegistry()

registry.register(
    BaseEquals("uint"),
    encoding.UnsignedIntegerEncoder,
    decoding.UnsignedIntegerDecoder,
    label="uint",
)
registry.register(
    BaseEquals("int"),
    encoding.SignedIntegerEncoder,
    decoding.SignedIntegerDecoder,
    label="int",
)
registry.register(
    BaseEquals("address"),
    encoding.AddressEncoder,
    decoding.AddressDecoder,
    label="address",
)
registry.register(
    BaseEquals("bool"),
    encoding.BooleanEncoder,
    decoding.BooleanDecoder,
    label="bool",
)
registry.register(
    BaseEquals("ufixed"),
    encoding.UnsignedFixedEncoder,
    decoding.UnsignedFixedDecoder,
    label="ufixed",
)
registry.register(
    BaseEquals("fixed"),
    encoding.SignedFixedEncoder,
    decoding.SignedFixedDecoder,
    label="fixed",
)
registry.register(
    BaseEquals("bytes", with_sub=True),
    encoding.BytesEncoder,
    decoding.BytesDecoder,
    label="bytes<M>",
)
registry.register(
    BaseEquals("bytes", with_sub=False),
    encoding.ByteStringEncoder,
    decoding.ByteStringDecoder,
    label="bytes",
)
registry.register(
    BaseEquals("function"),
    encoding.BytesEncoder,
    decoding.BytesDecoder,
    label="function",
)
registry.register(
    BaseEquals("string"),
    encoding.TextStringEncoder,
    decoding.StringDecoder,
    label="string",
)
registry.register(
    has_arrlist,
    encoding.BaseArrayEncoder,
    decoding.BaseArrayDecoder,
    label="has_arrlist",
)
registry.register(
    is_base_tuple,
    encoding.TupleEncoder,
    decoding.TupleDecoder,
    label="is_base_tuple",
)

registry_packed = ABIRegistry()

registry_packed.register_encoder(
    BaseEquals("uint"),
    encoding.PackedUnsignedIntegerEncoder,
    label="uint",
)
registry_packed.register_encoder(
    BaseEquals("int"),
    encoding.PackedSignedIntegerEncoder,
    label="int",
)
registry_packed.register_encoder(
    BaseEquals("address"),
    encoding.PackedAddressEncoder,
    label="address",
)
registry_packed.register_encoder(
    BaseEquals("bool"),
    encoding.PackedBooleanEncoder,
    label="bool",
)
registry_packed.register_encoder(
    BaseEquals("ufixed"),
    encoding.PackedUnsignedFixedEncoder,
    label="ufixed",
)
registry_packed.register_encoder(
    BaseEquals("fixed"),
    encoding.PackedSignedFixedEncoder,
    label="fixed",
)
registry_packed.register_encoder(
    BaseEquals("bytes", with_sub=True),
    encoding.PackedBytesEncoder,
    label="bytes<M>",
)
registry_packed.register_encoder(
    BaseEquals("bytes", with_sub=False),
    encoding.PackedByteStringEncoder,
    label="bytes",
)
registry_packed.register_encoder(
    BaseEquals("function"),
    encoding.PackedBytesEncoder,
    label="function",
)
registry_packed.register_encoder(
    BaseEquals("string"),
    encoding.PackedTextStringEncoder,
    label="string",
)
registry_packed.register_encoder(
    has_arrlist,
    encoding.PackedArrayEncoder,
    label="has_arrlist",
)
registry_packed.register_encoder(
    is_base_tuple,
    encoding.TupleEncoder,
    label="is_base_tuple",
)
