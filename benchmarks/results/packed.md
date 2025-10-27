#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0012162370761797927 | 0.00028249781141419857 | 76.77% | 330.53% | 4.31x | ✅ |
| `encode_packed[bool]` | 0.0007124247338232547 | 0.00011464011852209799 | 83.91% | 521.44% | 6.21x | ✅ |
| `encode_packed[bytes]` | 0.0006519711737842606 | 0.00010080427982290337 | 84.54% | 546.77% | 6.47x | ✅ |
| `encode_packed[string]` | 0.0006955074583026812 | 0.00013372458313398665 | 80.77% | 420.10% | 5.20x | ✅ |
| `encode_packed[tuple]` | 0.0016795588035993124 | 0.00038658659006955215 | 76.98% | 334.46% | 4.34x | ✅ |
| `encode_packed[uint256]` | 0.0008525039820208737 | 0.00018831104562085503 | 77.91% | 352.71% | 4.53x | ✅ |
| `is_encodable_packed[address]` | 6.125808024273847e-05 | 3.5351044799630715e-05 | 42.29% | 73.29% | 1.73x | ✅ |
| `is_encodable_packed[bool]` | 4.2894111013698335e-05 | 3.0507594461013005e-05 | 28.88% | 40.60% | 1.41x | ✅ |
| `is_encodable_packed[bytes]` | 4.675000770248349e-05 | 3.405174014941245e-05 | 27.16% | 37.29% | 1.37x | ✅ |
| `is_encodable_packed[string]` | 4.3090875242791324e-05 | 3.0620522767828105e-05 | 28.94% | 40.73% | 1.41x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002520626085375935 | 0.00010314376386039644 | 59.08% | 144.38% | 2.44x | ✅ |
| `is_encodable_packed[uint256]` | 9.982009408795175e-05 | 6.174737678723302e-05 | 38.14% | 61.66% | 1.62x | ✅ |
