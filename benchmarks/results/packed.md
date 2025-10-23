#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.001232348719178832 | 0.00035234831759690434 | 71.41% | 249.75% | 3.50x | ✅ |
| `encode_packed[bool]` | 0.0007127423662423083 | 0.00017747063277003807 | 75.10% | 301.61% | 4.02x | ✅ |
| `encode_packed[bytes]` | 0.0006567692387495136 | 0.0001649830588616743 | 74.88% | 298.08% | 3.98x | ✅ |
| `encode_packed[string]` | 0.0007042053913374822 | 0.0001971365937810973 | 72.01% | 257.22% | 3.57x | ✅ |
| `encode_packed[tuple]` | 0.0016643952674734752 | 0.0005082863606859948 | 69.46% | 227.45% | 3.27x | ✅ |
| `encode_packed[uint256]` | 0.0008464581285288119 | 0.0002596546728081858 | 69.32% | 225.99% | 3.26x | ✅ |
| `is_encodable_packed[address]` | 6.396306386320205e-05 | 3.860586863421529e-05 | 39.64% | 65.68% | 1.66x | ✅ |
| `is_encodable_packed[bool]` | 4.416365400345487e-05 | 3.331395659911331e-05 | 24.57% | 32.57% | 1.33x | ✅ |
| `is_encodable_packed[bytes]` | 4.517923803447612e-05 | 3.81684456949746e-05 | 15.52% | 18.37% | 1.18x | ✅ |
| `is_encodable_packed[string]` | 4.508467813353747e-05 | 3.2959793586171496e-05 | 26.89% | 36.79% | 1.37x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002627610311286123 | 0.0001044125754960012 | 60.26% | 151.66% | 2.52x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010160644141367947 | 6.227897428841138e-05 | 38.71% | 63.15% | 1.63x | ✅ |
