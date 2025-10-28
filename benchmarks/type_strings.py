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


def first_x_of_product(repeat: int, first_x: int):
    product = itertools.product(TYPE_STRINGS, repeat=repeat)
    for i in range(first_x):
        try:
            yield next(product)
        except StopIteration:
            return


TUPLE_TYPE_STRINGS = list(
    itertools.chain(*(first_x_of_product(i, 25) for i in range(1, 11)))
)
