#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0010939407567571013 | 0.0004139611165438953 | 62.16% | 164.26% | 2.64x | ✅ |
| `encode_packed[bool]` | 0.0006311447849509858 | 0.0002333216931340351 | 63.03% | 170.50% | 2.71x | ✅ |
| `encode_packed[bytes]` | 0.0005869471947816498 | 0.00023129376739372111 | 60.59% | 153.77% | 2.54x | ✅ |
| `encode_packed[string]` | 0.0006344101432789594 | 0.00025961319795119147 | 59.08% | 144.37% | 2.44x | ✅ |
| `encode_packed[tuple]` | 0.0015008057820979674 | 0.0007522650969231948 | 49.88% | 99.50% | 2.00x | ✅ |
| `encode_packed[uint256]` | 0.0007628509106924083 | 0.0003026704286255789 | 60.32% | 152.04% | 2.52x | ✅ |
| `is_encodable_packed[address]` | 6.172819339061171e-05 | 3.478357965393779e-05 | 43.65% | 77.46% | 1.77x | ✅ |
| `is_encodable_packed[bool]` | 4.445805922243448e-05 | 2.9531053518901132e-05 | 33.58% | 50.55% | 1.51x | ✅ |
| `is_encodable_packed[bytes]` | 4.493175896170191e-05 | 3.351135524874156e-05 | 25.42% | 34.08% | 1.34x | ✅ |
| `is_encodable_packed[string]` | 4.528679937883165e-05 | 3.5015494152352795e-05 | 22.68% | 29.33% | 1.29x | ✅ |
| `is_encodable_packed[tuple]` | 0.00023780777917744444 | 0.00019943195536894503 | 16.14% | 19.24% | 1.19x | ✅ |
| `is_encodable_packed[uint256]` | 9.621762817922461e-05 | 5.447901019732363e-05 | 43.38% | 76.61% | 1.77x | ✅ |
