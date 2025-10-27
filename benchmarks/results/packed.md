#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0012028900137167028 | 0.0002792340247026459 | 76.79% | 330.78% | 4.31x | ✅ |
| `encode_packed[bool]` | 0.000703720908944368 | 0.0001098663535519691 | 84.39% | 540.52% | 6.41x | ✅ |
| `encode_packed[bytes]` | 0.0006566624251621168 | 9.823588563601886e-05 | 85.04% | 568.45% | 6.68x | ✅ |
| `encode_packed[string]` | 0.0006888994187509212 | 0.00013096998517911747 | 80.99% | 426.00% | 5.26x | ✅ |
| `encode_packed[tuple]` | 0.0016682523882708342 | 0.0003791171535548885 | 77.27% | 340.04% | 4.40x | ✅ |
| `encode_packed[uint256]` | 0.0008384032823745366 | 0.00018275309923179668 | 78.20% | 358.76% | 4.59x | ✅ |
| `is_encodable_packed[address]` | 6.455371679273975e-05 | 3.875511727486265e-05 | 39.96% | 66.57% | 1.67x | ✅ |
| `is_encodable_packed[bool]` | 4.3535064863291925e-05 | 3.32168212685293e-05 | 23.70% | 31.06% | 1.31x | ✅ |
| `is_encodable_packed[bytes]` | 4.5035947767170645e-05 | 3.7681662047157283e-05 | 16.33% | 19.52% | 1.20x | ✅ |
| `is_encodable_packed[string]` | 4.5500488314017736e-05 | 3.263288935760635e-05 | 28.28% | 39.43% | 1.39x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002551994062396545 | 0.00010481609872801031 | 58.93% | 143.47% | 2.43x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010006782115072855 | 6.103871695396184e-05 | 39.00% | 63.94% | 1.64x | ✅ |
