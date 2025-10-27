#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0012113013219199624 | 0.0002788052797595064 | 76.98% | 334.46% | 4.34x | ✅ |
| `encode_packed[bool]` | 0.0007124277264839929 | 0.00011065982201870889 | 84.47% | 543.80% | 6.44x | ✅ |
| `encode_packed[bytes]` | 0.0006531628281918956 | 9.847050731904728e-05 | 84.92% | 563.31% | 6.63x | ✅ |
| `encode_packed[string]` | 0.0006958805281442174 | 0.00012970690155847883 | 81.36% | 436.50% | 5.37x | ✅ |
| `encode_packed[tuple]` | 0.0016656653825554237 | 0.00037564410398203014 | 77.45% | 343.42% | 4.43x | ✅ |
| `encode_packed[uint256]` | 0.0008366520891683395 | 0.000182580797205993 | 78.18% | 358.24% | 4.58x | ✅ |
| `is_encodable_packed[address]` | 6.3902435788647e-05 | 3.9394970382386644e-05 | 38.35% | 62.21% | 1.62x | ✅ |
| `is_encodable_packed[bool]` | 4.3880250966939355e-05 | 3.3691646353298005e-05 | 23.22% | 30.24% | 1.30x | ✅ |
| `is_encodable_packed[bytes]` | 4.496562032177719e-05 | 3.778751848755156e-05 | 15.96% | 19.00% | 1.19x | ✅ |
| `is_encodable_packed[string]` | 4.529415815813078e-05 | 3.376827567239693e-05 | 25.45% | 34.13% | 1.34x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002512794243826729 | 0.00010430721774953217 | 58.49% | 140.90% | 2.41x | ✅ |
| `is_encodable_packed[uint256]` | 9.960368211839233e-05 | 6.0527049186503095e-05 | 39.23% | 64.56% | 1.65x | ✅ |
