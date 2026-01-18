from _typeshed import Incomplete
from eth_typing.abi import TypeStr as TypeStr
from faster_eth_abi._grammar import (
    ABIType as ABIType,
    Arrlist as Arrlist,
    BasicType as BasicType,
    TupleType as TupleType,
    normalize as normalize,
)
from faster_eth_abi.grammar import parse as parse
from faster_eth_abi.registry import (
    BaseEquals as BaseEquals,
    BaseRegistry as BaseRegistry,
    Lookup as Lookup,
    PredicateMapping as PredicateMapping,
    has_arrlist as has_arrlist,
    is_base_tuple as is_base_tuple,
)
from faster_eth_abi.utils.numeric import scale_places as scale_places
from hypothesis import strategies as st
from typing import Any, Final, TypeAlias

StrategyFactory: TypeAlias
StrategyRegistration: TypeAlias
StrategyMapping: TypeAlias = PredicateMapping[StrategyRegistration]

class StrategyRegistry(BaseRegistry):
    def __init__(self) -> None: ...
    def register_strategy(
        self,
        lookup: Lookup,
        registration: StrategyRegistration,
        label: str | None = None,
    ) -> None: ...
    def unregister_strategy(self, lookup_or_label: Lookup) -> None: ...
    def get_strategy(self, type_str: TypeStr) -> st.SearchStrategy:
        """
        Returns a hypothesis strategy for the given ABI type.

        :param type_str: The canonical string representation of the ABI type
            for which a hypothesis strategy should be returned.

        :returns: A hypothesis strategy for generating Python values that are
            encodable as values of the given ABI type.
        """

def get_uint_strategy(
    abi_type: BasicType[Any], registry: StrategyRegistry
) -> st.SearchStrategy: ...
def get_int_strategy(
    abi_type: BasicType[Any], registry: StrategyRegistry
) -> st.SearchStrategy: ...

address_strategy: Final[Incomplete]
bool_strategy: Final[Incomplete]

def get_ufixed_strategy(
    abi_type: BasicType[Any], registry: StrategyRegistry
) -> st.SearchStrategy: ...
def get_fixed_strategy(
    abi_type: BasicType[Any], registry: StrategyRegistry
) -> st.SearchStrategy: ...
def get_bytes_strategy(
    abi_type: BasicType[Any], registry: StrategyRegistry
) -> st.SearchStrategy: ...

bytes_strategy: Final[Incomplete]
string_strategy: Final[Incomplete]

def get_array_strategy(
    abi_type: ABIType, registry: StrategyRegistry
) -> st.SearchStrategy: ...
def get_tuple_strategy(
    abi_type: TupleType, registry: StrategyRegistry
) -> st.SearchStrategy: ...

strategy_registry: Final[Incomplete]
get_abi_strategy: Final[Incomplete]
