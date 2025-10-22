#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.001197647384199872 | 0.00042704326642634604 | 64.34% | 180.45% | 2.80x | ✅ |
| `encode_packed[bool]` | 0.0007112427914028263 | 0.0002473915235432284 | 65.22% | 187.50% | 2.87x | ✅ |
| `encode_packed[bytes]` | 0.0006511962619906014 | 0.00023448741720887004 | 63.99% | 177.71% | 2.78x | ✅ |
| `encode_packed[string]` | 0.0006994075007841098 | 0.0002655254889143995 | 62.04% | 163.41% | 2.63x | ✅ |
| `encode_packed[tuple]` | 0.0016559417771654296 | 0.0007908051595675473 | 52.24% | 109.40% | 2.09x | ✅ |
| `encode_packed[uint256]` | 0.0008421991940813852 | 0.00031907817579170024 | 62.11% | 163.95% | 2.64x | ✅ |
| `is_encodable_packed[address]` | 6.544134428752061e-05 | 3.8974011262548785e-05 | 40.44% | 67.91% | 1.68x | ✅ |
| `is_encodable_packed[bool]` | 4.4850855753272713e-05 | 3.297957217953594e-05 | 26.47% | 36.00% | 1.36x | ✅ |
| `is_encodable_packed[bytes]` | 4.5964809308836556e-05 | 3.7987848206064156e-05 | 17.35% | 21.00% | 1.21x | ✅ |
| `is_encodable_packed[string]` | 4.556446334852127e-05 | 3.301050468483898e-05 | 27.55% | 38.03% | 1.38x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002566535065145419 | 0.00020274807576457389 | 21.00% | 26.59% | 1.27x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010136270346679244 | 6.398804063665628e-05 | 36.87% | 58.41% | 1.58x | ✅ |
