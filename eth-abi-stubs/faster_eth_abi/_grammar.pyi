from _typeshed import Incomplete
from eth_typing.abi import TypeStr as TypeStr
from faster_eth_abi.exceptions import ABITypeError as ABITypeError
from parsimonious.nodes import Node as Node
from typing import Any, Final, Generic, Literal, NoReturn, Sequence, TypeVar, final
from typing_extensions import Self

TYPE_ALIASES: Final[Incomplete]
TYPE_ALIAS_RE: Final[Incomplete]
IntSubtype: Incomplete
FixedSubtype: Incomplete
Subtype = IntSubtype | FixedSubtype
TSub = TypeVar("TSub", IntSubtype, FixedSubtype, Literal[None])

class ABIType:
    """
    Base class for results of type string parsing operations.
    """

    arrlist: Final[Incomplete]
    node: Final[Incomplete]
    def __init__(
        self, arrlist: Sequence[str] | None = None, node: Node | None = None
    ) -> None: ...
    def __eq__(self, other: Any) -> bool: ...
    def to_type_str(self) -> TypeStr:
        """
        Returns the string representation of an ABI type.  This will be equal to
        the type string from which it was created.
        """

    @property
    def item_type(self) -> Self:
        """
        If this type is an array type, equal to an appropriate
        :class:`~faster_eth_abi.grammar.ABIType` instance for the array's items.
        """

    def validate(self) -> None:
        """
        Validates the properties of an ABI type against the solidity ABI spec:

        https://solidity.readthedocs.io/en/develop/abi-spec.html

        Raises :class:`~faster_eth_abi.exceptions.ABITypeError` if validation fails.
        """

    @final
    def invalidate(self, error_msg: str) -> NoReturn: ...
    @final
    @property
    def is_array(self) -> bool:
        """
        Equal to ``True`` if a type is an array type (i.e. if it has an array
        dimension list).  Otherwise, equal to ``False``.
        """

    @property
    def is_dynamic(self) -> bool:
        """
        Equal to ``True`` if a type has a dynamically sized encoding.
        Otherwise, equal to ``False``.
        """

TComp = TypeVar("TComp", bound=ABIType)

class TupleType(ABIType):
    """
    Represents the result of parsing a tuple type string e.g. "(int,bool)".
    """

    components: Final[Incomplete]
    def __init__(
        self,
        components: tuple[TComp, ...],
        arrlist: Sequence[str] | None = None,
        *,
        node: Node | None = None
    ) -> None: ...
    def to_type_str(self) -> TypeStr: ...
    @property
    def item_type(self) -> Self: ...
    def validate(self) -> None: ...
    @property
    def is_dynamic(self) -> bool: ...

class BasicType(ABIType, Generic[TSub]):
    """
    Represents the result of parsing a basic type string e.g. "uint", "address",
    "ufixed128x19[][2]".
    """

    base: Final[Incomplete]
    sub: Final[Incomplete]
    def __init__(
        self,
        base: str,
        sub: TSub | None = None,
        arrlist: Sequence | None = None,
        *,
        node: Node | None = None
    ) -> None: ...
    def to_type_str(self) -> TypeStr: ...
    @property
    def item_type(self) -> Self: ...
    @property
    def is_dynamic(self) -> bool: ...
    def validate(self) -> None: ...

BytesType = BasicType[IntSubtype]
FixedType = BasicType[FixedSubtype]

def normalize(type_str: TypeStr) -> TypeStr:
    """
    Normalizes a type string into its canonical version e.g. the type string
    'int' becomes 'int256', etc.

    :param type_str: The type string to be normalized.
    :returns: The canonical version of the input type string.
    """
