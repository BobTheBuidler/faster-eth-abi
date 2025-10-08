import functools
import re
from typing import (
    Any,
    Final,
    NoReturn,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    final,
)

from eth_typing import (
    TypeStr,
)
import parsimonious
from parsimonious import (
    expressions,
)
from parsimonious.nodes import (
    Node,
)
from typing_extensions import (
    Self,
)

from faster_eth_abi._grammar import (
    TYPE_ALIASES,
    TYPE_ALIAS_RE,
    ABIType,
    BasicType,
    TupleType,
)
from faster_eth_abi.exceptions import (
    ABITypeError,
    ParseError,
)

grammar: Final = parsimonious.Grammar(
    r"""
    type = tuple_type / basic_type

    tuple_type = components arrlist?
    components = non_zero_tuple

    non_zero_tuple = "(" type next_type* ")"
    next_type = "," type

    basic_type = base sub? arrlist?

    base = alphas

    sub = two_size / digits
    two_size = (digits "x" digits)

    arrlist = (const_arr / dynam_arr)+
    const_arr = "[" digits "]"
    dynam_arr = "[]"

    alphas = ~"[A-Za-z]+"
    digits = ~"[1-9][0-9]*"
    """
)


@final
class NodeVisitor(parsimonious.NodeVisitor):  # type: ignore [misc]
    """
    Parsimonious node visitor which performs both parsing of type strings and
    post-processing of parse trees.  Parsing operations are cached.
    """

    def __init__(self):
        self.parse = functools.lru_cache(maxsize=None)(self._parse_uncached)

    grammar = grammar

    def visit_non_zero_tuple(self, node, visited_children):
        # Ignore left and right parens
        _, first, rest, _ = visited_children

        return (first,) + rest

    def visit_tuple_type(self, node, visited_children):
        components, arrlist = visited_children

        return TupleType(components, arrlist, node=node)

    def visit_next_type(self, node, visited_children):
        # Ignore comma
        _, abi_type = visited_children

        return abi_type

    def visit_basic_type(self, node, visited_children):
        base, sub, arrlist = visited_children

        return BasicType(base, sub, arrlist, node=node)

    def visit_two_size(self, node, visited_children):
        # Ignore "x"
        first, _, second = visited_children

        return first, second

    def visit_const_arr(self, node, visited_children):
        # Ignore left and right brackets
        _, int_value, _ = visited_children

        return (int_value,)

    def visit_dynam_arr(self, node, visited_children):
        return ()

    def visit_alphas(self, node, visited_children):
        return node.text

    def visit_digits(self, node, visited_children):
        return int(node.text)

    def generic_visit(self, node, visited_children):
        expr = node.expr
        if isinstance(expr, expressions.OneOf):
            # Unwrap value chosen from alternatives
            return visited_children[0]

        if isinstance(expr, expressions.Quantifier) and expr.min == 0 and expr.max == 1:
            # Unwrap optional value or return `None`
            if len(visited_children) != 0:
                return visited_children[0]

            return None

        return tuple(visited_children)

    def _parse_uncached(self, type_str, **kwargs):
        """
        Parses a type string into an appropriate instance of
        :class:`~faster_eth_abi.grammar.ABIType`.  If a type string cannot be parsed,
        throws :class:`~faster_eth_abi.exceptions.ParseError`.

        :param type_str: The type string to be parsed.
        :returns: An instance of :class:`~faster_eth_abi.grammar.ABIType` containing
            information about the parsed type string.
        """
        if not isinstance(type_str, str):
            raise TypeError(f"Can only parse string values: got {type(type_str)}")

        try:
            return super().parse(type_str, **kwargs)
        except parsimonious.ParseError as e:
            # This is a good place to add some better messaging around the type string.
            # If this logic grows any bigger, we should abstract it to its own function.
            if "()" in type_str:
                # validate against zero-sized tuple types
                raise ValueError(
                    'Zero-sized tuple types "()" are not supported.'
                ) from None

            raise ParseError(e.text, e.pos, e.expr) from e


visitor: Final = NodeVisitor()


__all__ = ["NodeVisitor", "ABIType", "TupleType", "BasicType", "grammar", "visitor", "parse", "TYPE_ALIASES", "TYPE_ALIAS_RE"]

# TODO: try moving this to _grammar and importing it here and seeing if mypyc resolves that?
parse: Final = visitor.parse
