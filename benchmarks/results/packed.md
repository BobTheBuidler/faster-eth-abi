#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.001225915072526728 | 0.0004223230126537076 | 65.55% | 190.28% | 2.90x | ✅ |
| `encode_packed[bool]` | 0.0007029107206441401 | 0.00024256740110391092 | 65.49% | 189.78% | 2.90x | ✅ |
| `encode_packed[bytes]` | 0.0006527558797706183 | 0.00023013356390073488 | 64.74% | 183.64% | 2.84x | ✅ |
| `encode_packed[string]` | 0.000694340355152691 | 0.00026338456591602175 | 62.07% | 163.62% | 2.64x | ✅ |
| `encode_packed[tuple]` | 0.0016482829964129034 | 0.0007988236128155659 | 51.54% | 106.34% | 2.06x | ✅ |
| `encode_packed[uint256]` | 0.0008392694302219542 | 0.00031318321186417673 | 62.68% | 167.98% | 2.68x | ✅ |
| `is_encodable_packed[address]` | 6.250309633654009e-05 | 3.858012734138635e-05 | 38.27% | 62.01% | 1.62x | ✅ |
| `is_encodable_packed[bool]` | 4.547580070478542e-05 | 3.2940380285995354e-05 | 27.57% | 38.05% | 1.38x | ✅ |
| `is_encodable_packed[bytes]` | 4.620931748323866e-05 | 3.722692897121467e-05 | 19.44% | 24.13% | 1.24x | ✅ |
| `is_encodable_packed[string]` | 4.4739811291691636e-05 | 3.308242923634993e-05 | 26.06% | 35.24% | 1.35x | ✅ |
| `is_encodable_packed[tuple]` | 0.00024857820858685374 | 0.00020311268125316844 | 18.29% | 22.38% | 1.22x | ✅ |
| `is_encodable_packed[uint256]` | 9.909945617493102e-05 | 6.079213514898407e-05 | 38.66% | 63.01% | 1.63x | ✅ |
