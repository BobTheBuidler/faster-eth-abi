"""
Benchmarks for faster_eth_abi.io.ContextFramesBytesIO

This file benchmarks the performance of ContextFramesBytesIO, a subclass of BytesIO
that supports contextual frame management for nested ABI decoding. It compares
key operations to standard BytesIO where appropriate.
"""

import pytest

import eth_abi.io
from pytest_codspeed import (
    BenchmarkFixture,
)

from benchmarks.batch import (
    batch,
)
import faster_eth_abi.io

# Test parameters
BUFFER_SIZES = [0, 32, 1024, 4096, 65536]
FRAME_DEPTHS = [1, 5, 10, 50]


@pytest.mark.benchmark(group="ContextFramesBytesIO-init")
@pytest.mark.parametrize("size", BUFFER_SIZES)
def test_contextframesbytesio_init(benchmark: BenchmarkFixture, size):
    data = b"\x01" * size
    benchmark(batch, 1000, eth_abi.io.ContextFramesBytesIO, data)


@pytest.mark.benchmark(group="ContextFramesBytesIO-init")
@pytest.mark.parametrize("size", BUFFER_SIZES)
def test_faster_contextframesbytesio_init(benchmark: BenchmarkFixture, size):
    data = b"\x01" * size
    benchmark(batch, 1000, faster_eth_abi.io.ContextFramesBytesIO, data)


@pytest.mark.benchmark(group="ContextFramesBytesIO-push-pop")
@pytest.mark.parametrize("depth", FRAME_DEPTHS)
def test_contextframesbytesio_push_pop(benchmark: BenchmarkFixture, depth):
    data = b"\x01" * 1024
    stream = eth_abi.io.ContextFramesBytesIO(data)

    def push_pop():
        for i in range(depth):
            stream.push_frame(i * 10)
        for _ in range(depth):
            stream.pop_frame()

    benchmark(batch, 100, push_pop)


@pytest.mark.benchmark(group="ContextFramesBytesIO-push-pop")
@pytest.mark.parametrize("depth", FRAME_DEPTHS)
def test_faster_contextframesbytesio_push_pop(benchmark: BenchmarkFixture, depth):
    data = b"\x01" * 1024
    stream = faster_eth_abi.io.ContextFramesBytesIO(data)
    ints = list(range(depth))

    def push_pop():
        for i in ints:
            stream.push_frame(i * 10)
        for _ in ints:
            stream.pop_frame()

    benchmark(batch, 100, push_pop)


@pytest.mark.benchmark(group="ContextFramesBytesIO-seek-in-frame")
@pytest.mark.parametrize("depth", FRAME_DEPTHS)
def test_contextframesbytesio_seek_in_frame(benchmark: BenchmarkFixture, depth):
    data = b"\x01" * 1024
    stream = eth_abi.io.ContextFramesBytesIO(data)
    # Set up the frame stack before timing
    for i in range(depth):
        stream.push_frame(i * 10)

    def seek_in_frame_ops():
        for i in range(depth):
            stream.seek_in_frame(i)

    benchmark(batch, 100, seek_in_frame_ops)


@pytest.mark.benchmark(group="ContextFramesBytesIO-seek-in-frame")
@pytest.mark.parametrize("depth", FRAME_DEPTHS)
def test_faster_contextframesbytesio_seek_in_frame(benchmark: BenchmarkFixture, depth):
    data = b"\x01" * 1024
    stream = faster_eth_abi.io.ContextFramesBytesIO(data)
    # Set up the frame stack before timing
    for i in range(depth):
        stream.push_frame(i * 10)

    def seek_in_frame_ops():
        for i in range(depth):
            stream.seek_in_frame(i)

    benchmark(batch, 100, seek_in_frame_ops)
