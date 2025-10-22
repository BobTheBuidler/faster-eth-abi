#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0012119043283547895 | 0.0004390988010831905 | 63.77% | 176.00% | 2.76x | ✅ |
| `encode_packed[bool]` | 0.0006955890864295363 | 0.00024712859140000145 | 64.47% | 181.47% | 2.81x | ✅ |
| `encode_packed[bytes]` | 0.000645685361463775 | 0.00023453701989726823 | 63.68% | 175.30% | 2.75x | ✅ |
| `encode_packed[string]` | 0.0006924174282351327 | 0.0002791500186902692 | 59.68% | 148.04% | 2.48x | ✅ |
| `encode_packed[tuple]` | 0.0016727680289404388 | 0.0008299737921371341 | 50.38% | 101.54% | 2.02x | ✅ |
| `encode_packed[uint256]` | 0.0008301317723669355 | 0.0003199167874124378 | 61.46% | 159.48% | 2.59x | ✅ |
| `is_encodable_packed[address]` | 6.479418179162292e-05 | 3.934438416474988e-05 | 39.28% | 64.68% | 1.65x | ✅ |
| `is_encodable_packed[bool]` | 4.3726456548945114e-05 | 3.4058470443708096e-05 | 22.11% | 28.39% | 1.28x | ✅ |
| `is_encodable_packed[bytes]` | 4.524324875049923e-05 | 3.787387299156413e-05 | 16.29% | 19.46% | 1.19x | ✅ |
| `is_encodable_packed[string]` | 4.638151252435197e-05 | 3.325306330648858e-05 | 28.31% | 39.48% | 1.39x | ✅ |
| `is_encodable_packed[tuple]` | 0.00025275498208020795 | 0.00020317444416547968 | 19.62% | 24.40% | 1.24x | ✅ |
| `is_encodable_packed[uint256]` | 0.0001006388562492105 | 6.16311922494929e-05 | 38.76% | 63.29% | 1.63x | ✅ |
