#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0011996323853598707 | 0.0002631576138478555 | 78.06% | 355.86% | 4.56x | ✅ |
| `encode_packed[bool]` | 0.0006742092511513733 | 0.0001019976860509007 | 84.87% | 561.00% | 6.61x | ✅ |
| `encode_packed[bytes]` | 0.0006134923608423397 | 9.124719948060435e-05 | 85.13% | 572.34% | 6.72x | ✅ |
| `encode_packed[string]` | 0.0006676380974125581 | 0.00012246535581184948 | 81.66% | 445.16% | 5.45x | ✅ |
| `encode_packed[tuple]` | 0.0016615144723247939 | 0.00034411124912811297 | 79.29% | 382.84% | 4.83x | ✅ |
| `encode_packed[uint256]` | 0.0008307986266758612 | 0.00016850520489236127 | 79.72% | 393.04% | 4.93x | ✅ |
| `is_encodable_packed[address]` | 6.460789421266683e-05 | 3.859950088321308e-05 | 40.26% | 67.38% | 1.67x | ✅ |
| `is_encodable_packed[bool]` | 4.4049782525343505e-05 | 3.400422686363208e-05 | 22.81% | 29.54% | 1.30x | ✅ |
| `is_encodable_packed[bytes]` | 4.39504511692619e-05 | 3.694527457192328e-05 | 15.94% | 18.96% | 1.19x | ✅ |
| `is_encodable_packed[string]` | 4.3785818755691793e-05 | 3.389228205793576e-05 | 22.60% | 29.19% | 1.29x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002503775873777862 | 9.672093996914932e-05 | 61.37% | 158.87% | 2.59x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010787938646943455 | 6.005222981861514e-05 | 44.33% | 79.64% | 1.80x | ✅ |
