import pytest

import eth_abi.registry
from pytest_codspeed import (
    BenchmarkFixture,
)

from benchmarks.batch import (
    batch,
)
from benchmarks.type_strings import (
    TYPE_STRINGS,
)
import faster_eth_abi.registry

ITERATIONS = 50_000


@pytest.mark.benchmark(group="RegistryGetEncoder")
@pytest.mark.parametrize("type_str", TYPE_STRINGS)
def test_ABIRegistry_get_encoder(benchmark: BenchmarkFixture, type_str):
    benchmark(batch, ITERATIONS, eth_abi.registry.registry.get_encoder, type_str)


@pytest.mark.benchmark(group="RegistryGetEncoder")
@pytest.mark.parametrize("type_str", TYPE_STRINGS)
def test_faster_ABIRegistry_get_encoder(benchmark: BenchmarkFixture, type_str):
    benchmark(batch, ITERATIONS, faster_eth_abi.registry.registry.get_encoder, type_str)


@pytest.mark.benchmark(group="RegistryGetDecoder")
@pytest.mark.parametrize("type_str", TYPE_STRINGS)
def test_ABIRegistry_get_decoder(benchmark: BenchmarkFixture, type_str):
    benchmark(batch, ITERATIONS, eth_abi.registry.registry.get_decoder, type_str)


@pytest.mark.benchmark(group="RegistryGetDecoder")
@pytest.mark.parametrize("type_str", TYPE_STRINGS)
def test_faster_ABIRegistry_get_decoder(benchmark: BenchmarkFixture, type_str):
    benchmark(batch, ITERATIONS, faster_eth_abi.registry.registry.get_decoder, type_str)


@pytest.mark.benchmark(group="PredicateMappingFind")
@pytest.mark.parametrize("type_strs", [TYPE_STRINGS])  # TODO extend me
@pytest.mark.parametrize("type_str", TYPE_STRINGS)
def test_PredicateMapping_find(benchmark: BenchmarkFixture, type_strs, type_str):
    mapping = eth_abi.registry.PredicateMapping("test")
    for t in type_strs:
        mapping.add(lambda s, t=t: s == t, t)
    benchmark(batch, ITERATIONS, mapping.find, type_str)


@pytest.mark.benchmark(group="PredicateMappingFind")
@pytest.mark.parametrize("type_strs", [TYPE_STRINGS])  # TODO extend me
@pytest.mark.parametrize("type_str", TYPE_STRINGS)
def test_faster_PredicateMapping_find(benchmark: BenchmarkFixture, type_strs, type_str):
    mapping = faster_eth_abi.registry.PredicateMapping("test")
    for t in type_strs:
        mapping.add(lambda s, t=t: s == t, t)
    benchmark(batch, ITERATIONS, mapping.find, type_str)


@pytest.mark.benchmark(group="PredicateMappingAddRemove")
def test_PredicateMapping_add_remove(benchmark: BenchmarkFixture):
    mapping = eth_abi.registry.PredicateMapping("test")

    def add_remove():
        for t in TYPE_STRINGS:
            pred = lambda s, t=t: s == t
            mapping.add(pred, t)
            mapping.remove(pred)

    benchmark(batch, 100, add_remove)


@pytest.mark.benchmark(group="PredicateMappingAddRemove")
def test_faster_PredicateMapping_add_remove(benchmark: BenchmarkFixture):
    mapping = faster_eth_abi.registry.PredicateMapping("test")

    def add_remove():
        for t in TYPE_STRINGS:
            pred = lambda s, t=t: s == t
            mapping.add(pred, t)
            mapping.remove(pred)

    benchmark(batch, 100, add_remove)


@pytest.mark.benchmark(group="HasArrlist")
@pytest.mark.parametrize("type_str", TYPE_STRINGS)
def test_has_arrlist(benchmark: BenchmarkFixture, type_str):
    benchmark(batch, ITERATIONS, eth_abi.registry.has_arrlist, type_str)


@pytest.mark.benchmark(group="HasArrlist")
@pytest.mark.parametrize("type_str", TYPE_STRINGS)
def test_faster_has_arrlist(benchmark: BenchmarkFixture, type_str):
    benchmark(batch, ITERATIONS, faster_eth_abi.registry.has_arrlist, type_str)


@pytest.mark.benchmark(group="IsBaseTuple")
@pytest.mark.parametrize("type_str", TYPE_STRINGS)
def test_is_base_tuple(benchmark: BenchmarkFixture, type_str):
    benchmark(batch, ITERATIONS, eth_abi.registry.is_base_tuple, type_str)


@pytest.mark.benchmark(group="IsBaseTuple")
@pytest.mark.parametrize("type_str", TYPE_STRINGS)
def test_faster_is_base_tuple(benchmark: BenchmarkFixture, type_str):
    benchmark(batch, ITERATIONS, faster_eth_abi.registry.is_base_tuple, type_str)


@pytest.mark.benchmark(group="RegistryHasEncoder")
@pytest.mark.parametrize("type_str", TYPE_STRINGS)
def test_ABIRegistry_has_encoder(benchmark: BenchmarkFixture, type_str):
    benchmark(batch, ITERATIONS, eth_abi.registry.registry.has_encoder, type_str)


@pytest.mark.benchmark(group="RegistryHasEncoder")
@pytest.mark.parametrize("type_str", TYPE_STRINGS)
def test_faster_ABIRegistry_has_encoder(benchmark: BenchmarkFixture, type_str):
    benchmark(batch, ITERATIONS, faster_eth_abi.registry.registry.has_encoder, type_str)


# --- Predicate Benchmarks ---


@pytest.mark.benchmark(group="Equals__call__")
@pytest.mark.parametrize("value", TYPE_STRINGS)
@pytest.mark.parametrize("other", TYPE_STRINGS)
def test_Equals__call__(benchmark: BenchmarkFixture, value, other):
    pred = eth_abi.registry.Equals(value)
    benchmark(batch, ITERATIONS, pred, other)


@pytest.mark.benchmark(group="Equals__call__")
@pytest.mark.parametrize("value", TYPE_STRINGS)
@pytest.mark.parametrize("other", TYPE_STRINGS)
def test_faster_Equals__call__(benchmark: BenchmarkFixture, value, other):
    pred = faster_eth_abi.registry.Equals(value)
    benchmark(batch, ITERATIONS, pred, other)


@pytest.mark.benchmark(group="BaseEquals__call__")
@pytest.mark.parametrize("base", ["uint", "int", "bytes"])
@pytest.mark.parametrize("type_str", TYPE_STRINGS)
def test_BaseEquals__call__(benchmark: BenchmarkFixture, base, type_str):
    pred = eth_abi.registry.BaseEquals(base)
    benchmark(batch, ITERATIONS, pred, type_str)


@pytest.mark.benchmark(group="BaseEquals__call__")
@pytest.mark.parametrize("base", ["uint", "int", "bytes"])
@pytest.mark.parametrize("type_str", TYPE_STRINGS)
def test_faster_BaseEquals__call__(benchmark: BenchmarkFixture, base, type_str):
    pred = faster_eth_abi.registry.BaseEquals(base)
    benchmark(batch, ITERATIONS, pred, type_str)


@pytest.mark.benchmark(group="Predicate__iter__")
@pytest.mark.parametrize("cls", ["Equals", "BaseEquals"])
@pytest.mark.parametrize("value", TYPE_STRINGS)
def test_Predicate___iter__(benchmark: BenchmarkFixture, cls, value):
    typ = getattr(eth_abi.registry, cls)
    predicate = typ(value)
    benchmark(batch, ITERATIONS, list, predicate)


@pytest.mark.benchmark(group="Predicate__iter__")
@pytest.mark.parametrize("cls", ["Equals", "BaseEquals"])
@pytest.mark.parametrize("value", TYPE_STRINGS)
def test_faster_Predicate___iter__(benchmark: BenchmarkFixture, cls, value):
    typ = getattr(faster_eth_abi.registry, cls)
    predicate = typ(value)
    benchmark(batch, ITERATIONS, list, predicate)


@pytest.mark.benchmark(group="Predicate__hash__")
@pytest.mark.parametrize("cls", ["Equals", "BaseEquals"])
@pytest.mark.parametrize("value", TYPE_STRINGS)
def test_Predicate___hash__(benchmark: BenchmarkFixture, cls, value):
    typ = getattr(eth_abi.registry, cls)
    predicate = typ(value)
    benchmark(batch, ITERATIONS, hash, predicate)


@pytest.mark.benchmark(group="Predicate__hash__")
@pytest.mark.parametrize("cls", ["Equals", "BaseEquals"])
@pytest.mark.parametrize("value", TYPE_STRINGS)
def test_faster_Predicate___hash__(benchmark: BenchmarkFixture, cls, value):
    typ = getattr(faster_eth_abi.registry, cls)
    predicate = typ(value)
    benchmark(batch, ITERATIONS, hash, predicate)
