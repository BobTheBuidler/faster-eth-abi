import re
from typing import (
    Any,
    Final,
    Literal,
    NewType,
    NoReturn,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    final,
)

from eth_typing.abi import (
    TypeStr,
)
from mypy_extensions import (
    mypyc_attr,
)
from parsimonious.nodes import (
    Node,
)
from typing_extensions import (
    Self,
)

from faster_eth_abi.exceptions import (
    ABITypeError,
)


TYPE_ALIASES: Final = {
    "int": "int256",
    "uint": "uint256",
    "fixed": "fixed128x18",
    "ufixed": "ufixed128x18",
    "function": "bytes24",
    "byte": "bytes1",
}

TYPE_ALIAS_RE: Final = re.compile(
    rf"\b({'|'.join(map(re.escape, TYPE_ALIASES.keys()))})\b"
)


IntSubtype = NewType("IntSubtype", int)
FixedSubtype = NewType("FixedSubtype", Tuple[int, int])
Subtype = Union[IntSubtype, FixedSubtype]
TSub = TypeVar("TSub", Subtype, Literal[None])


@mypyc_attr(allow_interpreted_subclasses=True)
class ABIType:
    """
    Base class for results of type string parsing operations.
    """

    __slots__ = ("arrlist", "node")

    def __init__(
        self, arrlist: Optional[Sequence[str]] = None, node: Optional[Node] = None
    ) -> None:
        self.arrlist: Final = arrlist
        """
        The list of array dimensions for a parsed type.  Equal to ``None`` if
        type string has no array dimensions.
        """

        self.node: Final = node
        """
        The parsimonious ``Node`` instance associated with this parsed type.
        Used to generate error messages for invalid types.
        """

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{type(self).__qualname__} {self.to_type_str()!r}>"

    def __eq__(self, other: Any) -> bool:
        # Two ABI types are equal if their string representations are equal
        return type(self) is type(other) and self.to_type_str() == other.to_type_str()

    def to_type_str(self) -> TypeStr:  # pragma: no cover
        """
        Returns the string representation of an ABI type.  This will be equal to
        the type string from which it was created.
        """
        raise NotImplementedError("Must implement `to_type_str`")

    @property
    def item_type(self) -> Self:
        """
        If this type is an array type, equal to an appropriate
        :class:`~faster_eth_abi.grammar.ABIType` instance for the array's items.
        """
        raise NotImplementedError("Must implement `item_type`")

    def validate(self) -> None:  # pragma: no cover
        """
        Validates the properties of an ABI type against the solidity ABI spec:

        https://solidity.readthedocs.io/en/develop/abi-spec.html

        Raises :class:`~faster_eth_abi.exceptions.ABITypeError` if validation fails.
        """
        raise NotImplementedError("Must implement `validate`")

    @final
    def invalidate(self, error_msg: str) -> NoReturn:
        # Invalidates an ABI type with the given error message.  Expects that a
        # parsimonious node was provided from the original parsing operation
        # that yielded this type.
        node = self.node

        raise ABITypeError(
            f"For '{node.text}' type at column {node.start + 1} "
            f"in '{node.full_text}': {error_msg}"
        )

    @final
    @property
    def is_array(self) -> bool:
        """
        Equal to ``True`` if a type is an array type (i.e. if it has an array
        dimension list).  Otherwise, equal to ``False``.
        """
        return self.arrlist is not None

    @property
    def is_dynamic(self) -> bool:
        """
        Equal to ``True`` if a type has a dynamically sized encoding.
        Otherwise, equal to ``False``.
        """
        raise NotImplementedError("Must implement `is_dynamic`")

    @final
    @property
    def _has_dynamic_arrlist(self) -> bool:
        return self.is_array and any(len(dim) == 0 for dim in self.arrlist)


TComp = TypeVar("TComp", bound=ABIType)


@mypyc_attr(allow_interpreted_subclasses=True)
class TupleType(ABIType):
    """
    Represents the result of parsing a tuple type string e.g. "(int,bool)".
    """

    __slots__ = ("components",)

    def __init__(
        self,
        components: Tuple[TComp, ...],
        arrlist: Optional[Sequence[str]] = None,
        *,
        node: Optional[Node] = None,
    ) -> None:
        super().__init__(arrlist, node)

        self.components: Final = components
        """
        A tuple of :class:`~faster_eth_abi.grammar.ABIType` instances for each of the
        tuple type's components.
        """

    def to_type_str(self) -> TypeStr:
        arrlist = self.arrlist

        if isinstance(arrlist, tuple):
            arrlist = "".join(map(repr, map(list, arrlist)))
        else:
            arrlist = ""

        return f"({','.join(c.to_type_str() for c in self.components)}){arrlist}"

    @property
    def item_type(self) -> Self:
        if not self.is_array:
            raise ValueError(
                f"Cannot determine item type for non-array type '{self.to_type_str()}'"
            )

        arrlist = self.arrlist[:-1] or None  # type: ignore [index]
        cls = type(self)
        if cls is TupleType:
            return TupleType(self.components, arrlist, node=self.node)  # type: ignore [return-value]
        else:
            return cls(self.components, arrlist, node=self.node)

    def validate(self) -> None:
        for c in self.components:
            c.validate()

    @property
    def is_dynamic(self) -> bool:
        if self._has_dynamic_arrlist:
            return True

        return any(c.is_dynamic for c in self.components)


@mypyc_attr(allow_interpreted_subclasses=True)
class BasicType(ABIType, Generic[TSub]):
    """
    Represents the result of parsing a basic type string e.g. "uint", "address",
    "ufixed128x19[][2]".
    """

    __slots__ = ("base", "sub")

    def __init__(
        self,
        base: str,
        sub: Optional[TSub] = None,
        arrlist: Optional[Sequence] = None,
        *,
        node: Optional[Node] = None,
    ) -> None:
        super().__init__(arrlist, node)

        self.base: Final = base
        """The base of a basic type e.g. "uint" for "uint256" etc."""

        self.sub: Final = sub
        """
        The sub type of a basic type e.g. ``256`` for "uint256" or ``(128, 18)``
        for "ufixed128x18" etc.  Equal to ``None`` if type string has no sub
        type.
        """

    def to_type_str(self) -> TypeStr:
        sub, arrlist = self.sub, self.arrlist

        if isinstance(sub, int):
            substr = str(sub)
        elif isinstance(sub, tuple):
            substr = "x".join(map(str, sub))
        else:
            substr = ""

        if isinstance(arrlist, tuple):
            return self.base + substr + "".join(map(repr, map(list, arrlist)))
        else:
            return self.base + substr

    @property
    def item_type(self) -> Self:
        if not self.is_array:
            raise ValueError(
                f"Cannot determine item type for non-array type '{self.to_type_str()}'"
            )

        cls = type(self)
        arrlist = self.arrlist[:-1] or None  # type: ignore [index]
        if cls is BasicType:
            return BasicType(self.base, self.sub, arrlist, node=self.node)  # type: ignore [return-value]
        else:
            return cls(self.base, self.sub, arrlist, node=self.node)

    @property
    def is_dynamic(self) -> bool:
        if self._has_dynamic_arrlist:
            return True

        base = self.base
        if base == "string":
            return True

        if base == "bytes" and self.sub is None:
            return True

        return False

    def validate(self) -> None:
        base, sub = self.base, self.sub

        # Check validity of string type
        if base == "string":
            if sub is not None:
                self.invalidate("string type cannot have suffix")

        # Check validity of bytes type
        elif base == "bytes":
            if not (sub is None or isinstance(sub, int)):
                self.invalidate(
                    "bytes type must have either no suffix or a numerical suffix"
                )

            if isinstance(sub, int) and sub > 32:
                self.invalidate("maximum 32 bytes for fixed-length bytes")

        # Check validity of integer type
        elif base in ("int", "uint"):
            if not isinstance(sub, int):
                self.invalidate("integer type must have numerical suffix")

            if sub < 8 or sub > 256:
                self.invalidate("integer size out of bounds (max 256 bits)")

            if sub % 8 != 0:
                self.invalidate("integer size must be multiple of 8")

        # Check validity of fixed type
        elif base in ("fixed", "ufixed"):
            if not isinstance(sub, tuple):
                self.invalidate(
                    "fixed type must have suffix of form <bits>x<exponent>, "
                    "e.g. 128x19",
                )

            bits, minus_e = sub

            if bits < 8 or bits > 256:
                self.invalidate("fixed size out of bounds (max 256 bits)")

            if bits % 8 != 0:
                self.invalidate("fixed size must be multiple of 8")

            if minus_e < 1 or minus_e > 80:
                self.invalidate(
                    f"fixed exponent size out of bounds, {minus_e} must be in 1-80"
                )

        # Check validity of hash type
        elif base == "hash":
            if not isinstance(sub, int):
                self.invalidate("hash type must have numerical suffix")

        # Check validity of address type
        elif base == "address":
            if sub is not None:
                self.invalidate("address cannot have suffix")


BytesType = BasicType[IntSubtype]
FixedType = BasicType[FixedSubtype]


def normalize(type_str: TypeStr) -> TypeStr:
    """
    Normalizes a type string into its canonical version e.g. the type string
    'int' becomes 'int256', etc.

    :param type_str: The type string to be normalized.
    :returns: The canonical version of the input type string.
    """
    return TYPE_ALIAS_RE.sub(__normalize, type_str)


def __normalize(match: "re.Match[str]") -> str:
    return TYPE_ALIASES[match.group(0)]
