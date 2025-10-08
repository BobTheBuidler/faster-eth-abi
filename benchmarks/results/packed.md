#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.001201716820192301 | 0.00043592783487017393 | 63.72% | 175.67% | 2.76x | ✅ |
| `encode_packed[bool]` | 0.0006983318352668724 | 0.0002510148008159924 | 64.06% | 178.20% | 2.78x | ✅ |
| `encode_packed[bytes]` | 0.0006472254938591097 | 0.00023696506460727345 | 63.39% | 173.13% | 2.73x | ✅ |
| `encode_packed[string]` | 0.0007037032085543829 | 0.0002645083487420183 | 62.41% | 166.04% | 2.66x | ✅ |
| `encode_packed[tuple]` | 0.0016301698663141702 | 0.0007908340530093279 | 51.49% | 106.13% | 2.06x | ✅ |
| `encode_packed[uint256]` | 0.0008503775333315835 | 0.0003187229117196859 | 62.52% | 166.81% | 2.67x | ✅ |
| `is_encodable_packed[address]` | 6.502077859260738e-05 | 3.873575261456421e-05 | 40.43% | 67.86% | 1.68x | ✅ |
| `is_encodable_packed[bool]` | 4.39910870884775e-05 | 3.2620427078043214e-05 | 25.85% | 34.86% | 1.35x | ✅ |
| `is_encodable_packed[bytes]` | 4.525526164010161e-05 | 3.6968714546186186e-05 | 18.31% | 22.42% | 1.22x | ✅ |
| `is_encodable_packed[string]` | 4.5252180498061674e-05 | 3.240005029160519e-05 | 28.40% | 39.67% | 1.40x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002545885411064952 | 0.00020188930781415556 | 20.70% | 26.10% | 1.26x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010099013352767758 | 6.133785156575736e-05 | 39.26% | 64.65% | 1.65x | ✅ |
