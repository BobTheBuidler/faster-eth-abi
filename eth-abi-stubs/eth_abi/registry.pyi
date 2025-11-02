import abc
from . import (
    decoding as decoding,
    encoding as encoding,
    exceptions as exceptions,
    grammar as grammar,
)
from .base import BaseCoder as BaseCoder
from .exceptions import (
    MultipleEntriesFound as MultipleEntriesFound,
    NoEntriesFound as NoEntriesFound,
)
from .io import ContextFramesBytesIO as ContextFramesBytesIO
from _typeshed import Incomplete
from eth_typing import TypeStr
from typing import Any, Callable, Final, Generic, Iterator, TypeVar
from typing_extensions import ParamSpec, Self

T = TypeVar("T")
P = ParamSpec("P")
Lookup = TypeStr | Callable[[TypeStr], bool]
EncoderCallable = Callable[[Any], bytes]
DecoderCallable = Callable[[ContextFramesBytesIO], Any]
Encoder = EncoderCallable | type[encoding.BaseEncoder]
Decoder = DecoderCallable | type[decoding.BaseDecoder]

class Copyable(abc.ABC, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def copy(self) -> Self: ...
    def __copy__(self) -> Self: ...
    def __deepcopy__(self, *args: Any) -> Self: ...

class PredicateMapping(Copyable, Generic[T]):
    """
    Acts as a mapping from predicate functions to values.  Values are retrieved
    when their corresponding predicate matches a given input.  Predicates can
    also be labeled to facilitate removal from the mapping.
    """

    def __init__(self, name: str) -> None: ...
    def add(self, predicate: Lookup, value: T, label: str | None = None) -> None: ...
    def find(self, type_str: TypeStr) -> T: ...
    def remove_by_equality(self, predicate: Lookup) -> None: ...
    def remove_by_label(self, label: str) -> None: ...
    def remove(self, predicate_or_label: Lookup | str) -> None: ...
    def copy(self) -> Self: ...

class Predicate(Generic[T]):
    """
    Represents a predicate function to be used for type matching in
    ``ABIRegistry``.
    """

    def __init__(self) -> None: ...
    def __call__(self, arg: TypeStr) -> None: ...
    def __iter__(self) -> Iterator[T]: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: Predicate) -> bool: ...

class Equals(Predicate[str]):
    """
    A predicate that matches any input equal to `value`.
    """

    value: Final[Incomplete]
    def __init__(self, value: str) -> None: ...
    def __call__(self, other: TypeStr) -> bool: ...
    def __iter__(self) -> Iterator[str]: ...

class BaseEquals(Predicate[str | bool | None]):
    """
    A predicate that matches a basic type string with a base component equal to
    `value` and no array component.  If `with_sub` is `True`, the type string
    must have a sub component to match.  If `with_sub` is `False`, the type
    string must *not* have a sub component to match.  If `with_sub` is None,
    the type string's sub component is ignored.
    """

    base: Final[Incomplete]
    with_sub: Final[Incomplete]
    def __init__(self, base: TypeStr, *, with_sub: bool | None = None) -> None: ...
    def __call__(self, type_str: TypeStr) -> bool: ...
    def __iter__(self) -> Iterator[str | bool | None]: ...

def has_arrlist(type_str: TypeStr) -> bool:
    """
    A predicate that matches a type string with an array dimension list.
    """

def is_base_tuple(type_str: TypeStr) -> bool:
    """
    A predicate that matches a tuple type with no array dimension list.
    """

class BaseRegistry: ...

class ABIRegistry(Copyable, BaseRegistry):
    get_encoder: Incomplete
    get_decoder: Incomplete
    get_tuple_encoder: Incomplete
    get_tuple_decoder: Incomplete
    def __init__(self) -> None: ...
    @_clear_encoder_cache
    def register_encoder(
        self, lookup: Lookup, encoder: Encoder, label: str | None = None
    ) -> None:
        """
        Registers the given ``encoder`` under the given ``lookup``.  A unique
        string label may be optionally provided that can be used to refer to
        the registration by name.  For more information about arguments, refer
        to :any:`register`.
        """

    @_clear_encoder_cache
    def unregister_encoder(self, lookup_or_label: Lookup) -> None:
        """
        Unregisters an encoder in the registry with the given lookup or label.
        If ``lookup_or_label`` is a string, the encoder with the label
        ``lookup_or_label`` will be unregistered.  If it is an function, the
        encoder with the lookup function ``lookup_or_label`` will be
        unregistered.
        """

    @_clear_decoder_cache
    def register_decoder(
        self, lookup: Lookup, decoder: Decoder, label: str | None = None
    ) -> None:
        """
        Registers the given ``decoder`` under the given ``lookup``.  A unique
        string label may be optionally provided that can be used to refer to
        the registration by name.  For more information about arguments, refer
        to :any:`register`.
        """

    @_clear_decoder_cache
    def unregister_decoder(self, lookup_or_label: Lookup) -> None:
        """
        Unregisters a decoder in the registry with the given lookup or label.
        If ``lookup_or_label`` is a string, the decoder with the label
        ``lookup_or_label`` will be unregistered.  If it is an function, the
        decoder with the lookup function ``lookup_or_label`` will be
        unregistered.
        """

    def register(
        self,
        lookup: Lookup,
        encoder: Encoder,
        decoder: Decoder,
        label: str | None = None,
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

    def unregister(self, label: str | None) -> None:
        """
        Unregisters the entries in the encoder and decoder registries which
        have the label ``label``.
        """

    def has_encoder(self, type_str: TypeStr) -> bool:
        """
        Returns ``True`` if an encoder is found for the given type string
        ``type_str``.  Otherwise, returns ``False``.  Raises
        :class:`~faster_eth_abi.exceptions.MultipleEntriesFound` if multiple encoders
        are found.
        """

    def copy(self) -> Self:
        """
        Copies a registry such that new registrations can be made or existing
        registrations can be unregistered without affecting any instance from
        which a copy was obtained.  This is useful if an existing registry
        fulfills most of a user's needs but requires one or two modifications.
        In that case, a copy of that registry can be obtained and the necessary
        changes made without affecting the original registry.
        """

registry: Incomplete
is_int: Incomplete
is_int8: Incomplete
is_int16: Incomplete
is_uint: Incomplete
is_uint8: Incomplete
is_uint16: Incomplete
registry_packed: Incomplete
