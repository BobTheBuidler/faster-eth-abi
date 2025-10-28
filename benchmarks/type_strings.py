"""Shared list of all ABI type strings used in benchmarks"""
import itertools

TYPE_STRINGS = [
    "uint256",
    "int8",
    "address",
    "bytes32",
    "string",
    "bool",
    "uint256[2]",
    "string[]",
    "(uint256,bool)",
    "(address,uint8)",
    "(string,bytes)",
    "(uint256[2],string)",
    "(uint8,(bool,string))",
    "((uint8,uint8),uint8)",
    "(uint8[2],(string,bool[2]))",
    "(uint256[],(string[],bool))",
    "((uint8[2],(string,bool)),bytes32)",
    "(uint8[2][2],(string[2],bool[2]))",
    "uint8[]",
    "bytes",
    "fixed128x18",
    "ufixed128x18",
]


TUPLE_TYPE_STRINGS = list(
    itertools.chain(
        TYPE_STRINGS,
        list(itertools.product(TYPE_STRINGS, repeat=2))[:25],
        list(itertools.product(TYPE_STRINGS, repeat=3))[:25],
        list(itertools.product(TYPE_STRINGS, repeat=4))[:25],
        list(itertools.product(TYPE_STRINGS, repeat=5))[:25],
        list(itertools.product(TYPE_STRINGS, repeat=6))[:25],
        list(itertools.product(TYPE_STRINGS, repeat=7))[:25],
        list(itertools.product(TYPE_STRINGS, repeat=8))[:25],
        list(itertools.product(TYPE_STRINGS, repeat=9))[:25],
        list(itertools.product(TYPE_STRINGS, repeat=10))[:25],
    )
)
