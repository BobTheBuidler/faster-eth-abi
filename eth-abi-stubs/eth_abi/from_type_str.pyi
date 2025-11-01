from ._grammar import (
    ABIType as ABIType,
    BasicType as BasicType,
    TupleType as TupleType,
    normalize as normalize,
)
from .base import BaseCoder as BaseCoder
from .grammar import parse as parse
from _typeshed import Incomplete
from typing import Callable, TypeVar

TType = TypeVar("TType", bound=type["BaseCoder"])
OldFromTypeStr: Incomplete
NewFromTypeStr: Incomplete

def parse_type_str(
    expected_base: str | None = None, with_arrlist: bool = False
) -> Callable[[OldFromTypeStr[TType]], "NewFromTypeStr[TType]"]:
    """
    Used by BaseCoder subclasses as a convenience for implementing the
    ``from_type_str`` method required by ``ABIRegistry``.  Useful if normalizing
    then parsing a type string with an (optional) expected base is required in
    that method.
    """

def parse_tuple_type_str(
    old_from_type_str: OldFromTypeStr[TType],
) -> NewFromTypeStr[TType]:
    """
    Used by BaseCoder subclasses as a convenience for implementing the
    ``from_type_str`` method required by ``ABIRegistry``.  Useful if normalizing
    then parsing a tuple type string is required in that method.
    """
