#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.001197269167100615 | 0.00028768081358888437 | 75.97% | 316.18% | 4.16x | ✅ |
| `encode_packed[bool]` | 0.0006668978656964264 | 0.00011206589637835204 | 83.20% | 495.09% | 5.95x | ✅ |
| `encode_packed[bytes]` | 0.0006240278371604758 | 9.772170004615052e-05 | 84.34% | 538.58% | 6.39x | ✅ |
| `encode_packed[string]` | 0.0006697834156355585 | 0.0001313463816305913 | 80.39% | 409.94% | 5.10x | ✅ |
| `encode_packed[tuple]` | 0.0016455110589171389 | 0.00037564645845683515 | 77.17% | 338.05% | 4.38x | ✅ |
| `encode_packed[uint256]` | 0.0008436450866597983 | 0.00018467368300389885 | 78.11% | 356.83% | 4.57x | ✅ |
| `is_encodable_packed[address]` | 6.294682988592607e-05 | 3.891152487569997e-05 | 38.18% | 61.77% | 1.62x | ✅ |
| `is_encodable_packed[bool]` | 4.322981244504015e-05 | 3.3154741135917714e-05 | 23.31% | 30.39% | 1.30x | ✅ |
| `is_encodable_packed[bytes]` | 4.29166072026563e-05 | 3.616097655718367e-05 | 15.74% | 18.68% | 1.19x | ✅ |
| `is_encodable_packed[string]` | 4.298473417549938e-05 | 3.225710576908618e-05 | 24.96% | 33.26% | 1.33x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002514972247605382 | 0.00010006117548416769 | 60.21% | 151.34% | 2.51x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010746091030386128 | 5.965262018045655e-05 | 44.49% | 80.14% | 1.80x | ✅ |
