#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0012107497849132283 | 0.0003435201446945255 | 71.63% | 252.45% | 3.52x | ✅ |
| `encode_packed[bool]` | 0.0007184861658474861 | 0.0001791149539638149 | 75.07% | 301.13% | 4.01x | ✅ |
| `encode_packed[bytes]` | 0.0006558896758173491 | 0.00015827476563245888 | 75.87% | 314.40% | 4.14x | ✅ |
| `encode_packed[string]` | 0.0006944753722196006 | 0.0001903309506523654 | 72.59% | 264.88% | 3.65x | ✅ |
| `encode_packed[tuple]` | 0.0016951991633257233 | 0.0005040522236876831 | 70.27% | 236.31% | 3.36x | ✅ |
| `encode_packed[uint256]` | 0.000852556009614493 | 0.00024912110725068255 | 70.78% | 242.23% | 3.42x | ✅ |
| `is_encodable_packed[address]` | 6.403422250415199e-05 | 3.88998295272044e-05 | 39.25% | 64.61% | 1.65x | ✅ |
| `is_encodable_packed[bool]` | 4.396283211152528e-05 | 3.331796507074866e-05 | 24.21% | 31.95% | 1.32x | ✅ |
| `is_encodable_packed[bytes]` | 4.516729692852708e-05 | 3.908215962956415e-05 | 13.47% | 15.57% | 1.16x | ✅ |
| `is_encodable_packed[string]` | 4.5035118428776604e-05 | 3.290770073272523e-05 | 26.93% | 36.85% | 1.37x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002530243043583941 | 0.0001039755686564805 | 58.91% | 143.35% | 2.43x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010081774949931327 | 6.0197336770506874e-05 | 40.29% | 67.48% | 1.67x | ✅ |
