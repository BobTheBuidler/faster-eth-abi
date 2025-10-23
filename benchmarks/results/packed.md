#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0010762058114888054 | 0.00031763994343925856 | 70.49% | 238.81% | 3.39x | ✅ |
| `encode_packed[bool]` | 0.0006214229939999246 | 0.00014717491612646646 | 76.32% | 322.23% | 4.22x | ✅ |
| `encode_packed[bytes]` | 0.0005867673657481374 | 0.00013355295990718648 | 77.24% | 339.35% | 4.39x | ✅ |
| `encode_packed[string]` | 0.0006254073596075365 | 0.00016381246270627965 | 73.81% | 281.78% | 3.82x | ✅ |
| `encode_packed[tuple]` | 0.0014804522253955709 | 0.0004543186902213439 | 69.31% | 225.86% | 3.26x | ✅ |
| `encode_packed[uint256]` | 0.0007504165843935439 | 0.00021814034723035387 | 70.93% | 244.01% | 3.44x | ✅ |
| `is_encodable_packed[address]` | 6.178756355961981e-05 | 3.514523825313867e-05 | 43.12% | 75.81% | 1.76x | ✅ |
| `is_encodable_packed[bool]` | 4.408713627147328e-05 | 3.0609294097386063e-05 | 30.57% | 44.03% | 1.44x | ✅ |
| `is_encodable_packed[bytes]` | 4.494065473369159e-05 | 3.3864113464678374e-05 | 24.65% | 32.71% | 1.33x | ✅ |
| `is_encodable_packed[string]` | 4.512969030236796e-05 | 3.1151202929890184e-05 | 30.97% | 44.87% | 1.45x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002471469643337757 | 0.00010099940496532988 | 59.13% | 144.70% | 2.45x | ✅ |
| `is_encodable_packed[uint256]` | 0.0001001804470773834 | 5.8017556358360746e-05 | 42.09% | 72.67% | 1.73x | ✅ |
