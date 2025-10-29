#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0012145322232826191 | 0.00028591983153487355 | 76.46% | 324.78% | 4.25x | ✅ |
| `encode_packed[bool]` | 0.0006758521856614984 | 0.00011149530040103962 | 83.50% | 506.17% | 6.06x | ✅ |
| `encode_packed[bytes]` | 0.0006202150006999442 | 0.00010098943161521182 | 83.72% | 514.14% | 6.14x | ✅ |
| `encode_packed[string]` | 0.0006761007341671392 | 0.00013442310411679613 | 80.12% | 402.96% | 5.03x | ✅ |
| `encode_packed[tuple]` | 0.001636948543363867 | 0.0003752426007195305 | 77.08% | 336.24% | 4.36x | ✅ |
| `encode_packed[uint256]` | 0.0008335334211577762 | 0.0001823167780403456 | 78.13% | 357.19% | 4.57x | ✅ |
| `is_encodable_packed[address]` | 6.387690937986907e-05 | 3.801801982268786e-05 | 40.48% | 68.02% | 1.68x | ✅ |
| `is_encodable_packed[bool]` | 4.3839079057674956e-05 | 3.3083117269411495e-05 | 24.54% | 32.51% | 1.33x | ✅ |
| `is_encodable_packed[bytes]` | 4.379662254536346e-05 | 3.715253010633415e-05 | 15.17% | 17.88% | 1.18x | ✅ |
| `is_encodable_packed[string]` | 4.3315281565222636e-05 | 3.2879440668273954e-05 | 24.09% | 31.74% | 1.32x | ✅ |
| `is_encodable_packed[tuple]` | 0.00025162962510227833 | 0.00010126304383314688 | 59.76% | 148.49% | 2.48x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010834771897156863 | 5.990859319944564e-05 | 44.71% | 80.86% | 1.81x | ✅ |
