import parsimonious
from _typeshed import Incomplete
from faster_eth_abi._grammar import (
    ABIType as ABIType,
    BasicType as BasicType,
    TYPE_ALIASES as TYPE_ALIASES,
    TYPE_ALIAS_RE as TYPE_ALIAS_RE,
    TupleType as TupleType,
    normalize as normalize,
)
from typing import Final

__all__ = [
    "NodeVisitor",
    "ABIType",
    "TupleType",
    "BasicType",
    "grammar",
    "parse",
    "normalize",
    "visitor",
    "TYPE_ALIASES",
    "TYPE_ALIAS_RE",
]

grammar: Final[Incomplete]

class NodeVisitor(parsimonious.NodeVisitor):
    """
    Parsimonious node visitor which performs both parsing of type strings and
    post-processing of parse trees.  Parsing operations are cached.
    """

    parse: Final[Incomplete]
    def __init__(self) -> None: ...
    grammar = grammar
    def visit_non_zero_tuple(self, node, visited_children): ...
    def visit_tuple_type(self, node, visited_children): ...
    def visit_next_type(self, node, visited_children): ...
    def visit_basic_type(self, node, visited_children): ...
    def visit_two_size(self, node, visited_children): ...
    def visit_const_arr(self, node, visited_children): ...
    def visit_dynam_arr(self, node, visited_children): ...
    def visit_alphas(self, node, visited_children): ...
    def visit_digits(self, node, visited_children): ...
    def generic_visit(self, node, visited_children): ...

visitor: Final[Incomplete]
parse: Final[Incomplete]
