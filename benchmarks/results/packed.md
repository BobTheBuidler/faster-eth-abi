#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0012043214687477396 | 0.00044639855130598966 | 62.93% | 169.79% | 2.70x | ✅ |
| `encode_packed[bool]` | 0.0007090100791643777 | 0.0002518141772051948 | 64.48% | 181.56% | 2.82x | ✅ |
| `encode_packed[bytes]` | 0.0006463033533635246 | 0.000239844836546699 | 62.89% | 169.47% | 2.69x | ✅ |
| `encode_packed[string]` | 0.0007042335984607025 | 0.0002664274010151755 | 62.17% | 164.32% | 2.64x | ✅ |
| `encode_packed[tuple]` | 0.0016888216654407542 | 0.000798041923545465 | 52.75% | 111.62% | 2.12x | ✅ |
| `encode_packed[uint256]` | 0.000849650365738165 | 0.0003190690339906769 | 62.45% | 166.29% | 2.66x | ✅ |
| `is_encodable_packed[address]` | 6.41603917559152e-05 | 3.9390838200725395e-05 | 38.61% | 62.88% | 1.63x | ✅ |
| `is_encodable_packed[bool]` | 4.83376494825082e-05 | 3.299742026774422e-05 | 31.74% | 46.49% | 1.46x | ✅ |
| `is_encodable_packed[bytes]` | 4.611788447548868e-05 | 3.708080390320373e-05 | 19.60% | 24.37% | 1.24x | ✅ |
| `is_encodable_packed[string]` | 5.375085471980355e-05 | 3.2594265958156316e-05 | 39.36% | 64.91% | 1.65x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002552257774943617 | 0.0002084026152441107 | 18.35% | 22.47% | 1.22x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010251740583127366 | 6.38453389051554e-05 | 37.72% | 60.57% | 1.61x | ✅ |
