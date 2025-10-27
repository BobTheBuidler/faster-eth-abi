#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.001202697120761032 | 0.00028923571678135957 | 75.95% | 315.82% | 4.16x | ✅ |
| `encode_packed[bool]` | 0.0006787499630187458 | 0.0001120621409207895 | 83.49% | 505.69% | 6.06x | ✅ |
| `encode_packed[bytes]` | 0.0006228094848697935 | 9.768110057562358e-05 | 84.32% | 537.59% | 6.38x | ✅ |
| `encode_packed[string]` | 0.000667042742874451 | 0.00013002106948798386 | 80.51% | 413.03% | 5.13x | ✅ |
| `encode_packed[tuple]` | 0.0016383900709309868 | 0.0003884676768407217 | 76.29% | 321.76% | 4.22x | ✅ |
| `encode_packed[uint256]` | 0.0008385237036296933 | 0.00018394674862867662 | 78.06% | 355.85% | 4.56x | ✅ |
| `is_encodable_packed[address]` | 6.466087828795397e-05 | 4.0403763615709794e-05 | 37.51% | 60.04% | 1.60x | ✅ |
| `is_encodable_packed[bool]` | 4.379875153524304e-05 | 3.326376606067954e-05 | 24.05% | 31.67% | 1.32x | ✅ |
| `is_encodable_packed[bytes]` | 4.370485319781245e-05 | 3.602594690254888e-05 | 17.57% | 21.31% | 1.21x | ✅ |
| `is_encodable_packed[string]` | 4.378269592712347e-05 | 3.288910579089068e-05 | 24.88% | 33.12% | 1.33x | ✅ |
| `is_encodable_packed[tuple]` | 0.00025215183206751145 | 9.951300737637445e-05 | 60.53% | 153.39% | 2.53x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010767084219433377 | 6.0760265766497034e-05 | 43.57% | 77.21% | 1.77x | ✅ |
