#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0011845591825572761 | 0.00028315257292763004 | 76.10% | 318.35% | 4.18x | ✅ |
| `encode_packed[bool]` | 0.0006736567474679502 | 0.00011164153259709702 | 83.43% | 503.41% | 6.03x | ✅ |
| `encode_packed[bytes]` | 0.0006320087630489506 | 9.667872559525306e-05 | 84.70% | 553.72% | 6.54x | ✅ |
| `encode_packed[string]` | 0.0006695745995504289 | 0.00012917027251643985 | 80.71% | 418.37% | 5.18x | ✅ |
| `encode_packed[tuple]` | 0.0016503291258929353 | 0.0003721186046844031 | 77.45% | 343.50% | 4.43x | ✅ |
| `encode_packed[uint256]` | 0.0008302835471161311 | 0.00018070803420167038 | 78.24% | 359.46% | 4.59x | ✅ |
| `is_encodable_packed[address]` | 6.421812605025614e-05 | 3.85244515580655e-05 | 40.01% | 66.69% | 1.67x | ✅ |
| `is_encodable_packed[bool]` | 4.444749343188188e-05 | 3.353632182754128e-05 | 24.55% | 32.54% | 1.33x | ✅ |
| `is_encodable_packed[bytes]` | 4.4245205039279094e-05 | 3.75286915651524e-05 | 15.18% | 17.90% | 1.18x | ✅ |
| `is_encodable_packed[string]` | 4.311084382376187e-05 | 3.344684700183864e-05 | 22.42% | 28.89% | 1.29x | ✅ |
| `is_encodable_packed[tuple]` | 0.00025005579793604374 | 9.940293630125497e-05 | 60.25% | 151.56% | 2.52x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010620791164077687 | 5.853211921998708e-05 | 44.89% | 81.45% | 1.81x | ✅ |
