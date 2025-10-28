#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0012247411236106448 | 0.00029026177084106 | 76.30% | 321.94% | 4.22x | ✅ |
| `encode_packed[bool]` | 0.0006728953174300304 | 0.00010891158501414885 | 83.81% | 517.84% | 6.18x | ✅ |
| `encode_packed[bytes]` | 0.0006241748096239377 | 9.697006475198423e-05 | 84.46% | 543.68% | 6.44x | ✅ |
| `encode_packed[string]` | 0.0006679768047266215 | 0.00012733984468792512 | 80.94% | 424.56% | 5.25x | ✅ |
| `encode_packed[tuple]` | 0.0016362523835191185 | 0.0003752389589064611 | 77.07% | 336.06% | 4.36x | ✅ |
| `encode_packed[uint256]` | 0.0008327199311344363 | 0.00017773842756888144 | 78.66% | 368.51% | 4.69x | ✅ |
| `is_encodable_packed[address]` | 6.461171083511398e-05 | 3.9184555063093534e-05 | 39.35% | 64.89% | 1.65x | ✅ |
| `is_encodable_packed[bool]` | 4.4062971452206424e-05 | 3.41017565070062e-05 | 22.61% | 29.21% | 1.29x | ✅ |
| `is_encodable_packed[bytes]` | 4.42839704705783e-05 | 3.6815257218154544e-05 | 16.87% | 20.29% | 1.20x | ✅ |
| `is_encodable_packed[string]` | 4.453575003628428e-05 | 3.338260245050826e-05 | 25.04% | 33.41% | 1.33x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002501014443260503 | 0.00010052527220294506 | 59.81% | 148.79% | 2.49x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010790546723097054 | 5.988111852441222e-05 | 44.51% | 80.20% | 1.80x | ✅ |
