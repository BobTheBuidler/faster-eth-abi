import pytest

import eth_abi.registry
from pytest_codspeed import (
    BenchmarkFixture,
)

from benchmarks.type_strings import (
    type_strings,
)
from faster_eth_abi.decoding import (
    UnsignedIntegerDecoder,
)
from faster_eth_abi.encoding import (
    UnsignedIntegerEncoder,
)
import faster_eth_abi.registry


@pytest.mark.benchmark(group="RegistryGetEncoder")
@pytest.mark.parametrize("type_str", type_strings)
def test_get_encoder(benchmark: BenchmarkFixture, type_str):
    benchmark(eth_abi.registry.registry.get_encoder, type_str)


@pytest.mark.benchmark(group="RegistryGetEncoder")
@pytest.mark.parametrize("type_str", type_strings)
def test_faster_get_encoder(benchmark: BenchmarkFixture, type_str):
    benchmark(faster_eth_abi.registry.registry.get_encoder, type_str)


@pytest.mark.benchmark(group="RegistryGetDecoder")
@pytest.mark.parametrize("type_str", type_strings)
def test_get_decoder(benchmark: BenchmarkFixture, type_str):
    benchmark(eth_abi.registry.registry.get_decoder, type_str)


@pytest.mark.benchmark(group="RegistryGetDecoder")
@pytest.mark.parametrize("type_str", type_strings)
def test_faster_get_decoder(benchmark: BenchmarkFixture, type_str):
    benchmark(faster_eth_abi.registry.registry.get_decoder, type_str)


@pytest.mark.benchmark(group="RegistryRegister")
def test_registry_register(benchmark: BenchmarkFixture):
    reg = eth_abi.registry.ABIRegistry()

    def register_uint():
        reg.register(
            "uint256",
            UnsignedIntegerEncoder,
            UnsignedIntegerDecoder,
            label="uint256",
        )

    benchmark(register_uint)


@pytest.mark.benchmark(group="RegistryRegister")
def test_faster_registry_register(benchmark: BenchmarkFixture):
    reg = faster_eth_abi.registry.ABIRegistry()

    def register_uint():
        reg.register(
            "uint256",
            UnsignedIntegerEncoder,
            UnsignedIntegerDecoder,
            label="uint256",
        )

    benchmark(register_uint)
