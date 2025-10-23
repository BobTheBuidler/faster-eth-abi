#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0012264829500799846 | 0.00032222071723091324 | 73.73% | 280.63% | 3.81x | ✅ |
| `encode_packed[bool]` | 0.0007226435828639339 | 0.00015128887359962931 | 79.06% | 377.66% | 4.78x | ✅ |
| `encode_packed[bytes]` | 0.0006559348899483475 | 0.00013790569735111513 | 78.98% | 375.64% | 4.76x | ✅ |
| `encode_packed[string]` | 0.0006954035706258585 | 0.0001685813236397408 | 75.76% | 312.50% | 4.13x | ✅ |
| `encode_packed[tuple]` | 0.0016711252230327239 | 0.0004650240942925798 | 72.17% | 259.36% | 3.59x | ✅ |
| `encode_packed[uint256]` | 0.0008550096878011906 | 0.0002238347050554855 | 73.82% | 281.98% | 3.82x | ✅ |
| `is_encodable_packed[address]` | 6.526741105397853e-05 | 3.956077250703751e-05 | 39.39% | 64.98% | 1.65x | ✅ |
| `is_encodable_packed[bool]` | 4.470292942015262e-05 | 3.327090591616879e-05 | 25.57% | 34.36% | 1.34x | ✅ |
| `is_encodable_packed[bytes]` | 4.5753740041811035e-05 | 3.772823682045872e-05 | 17.54% | 21.27% | 1.21x | ✅ |
| `is_encodable_packed[string]` | 4.5791696251794584e-05 | 3.2646803348324744e-05 | 28.71% | 40.26% | 1.40x | ✅ |
| `is_encodable_packed[tuple]` | 0.00025023988434716893 | 0.00010186166044156612 | 59.29% | 145.67% | 2.46x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010019498031189568 | 6.153095256136842e-05 | 38.59% | 62.84% | 1.63x | ✅ |
