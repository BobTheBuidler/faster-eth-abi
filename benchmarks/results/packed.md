#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.001223207817190929 | 0.0002903222864624246 | 76.27% | 321.33% | 4.21x | ✅ |
| `encode_packed[bool]` | 0.0006737288253874305 | 0.00011184642295781172 | 83.40% | 502.37% | 6.02x | ✅ |
| `encode_packed[bytes]` | 0.0006151864478470379 | 9.719260842730977e-05 | 84.20% | 532.96% | 6.33x | ✅ |
| `encode_packed[string]` | 0.0006689024119021362 | 0.00013178839516096255 | 80.30% | 407.56% | 5.08x | ✅ |
| `encode_packed[tuple]` | 0.0016430261305857793 | 0.0003751438927776738 | 77.17% | 337.97% | 4.38x | ✅ |
| `encode_packed[uint256]` | 0.0008385251493238337 | 0.00018492592830524223 | 77.95% | 353.44% | 4.53x | ✅ |
| `is_encodable_packed[address]` | 6.507825833012634e-05 | 3.97687053769569e-05 | 38.89% | 63.64% | 1.64x | ✅ |
| `is_encodable_packed[bool]` | 4.374464954417558e-05 | 3.429705505942172e-05 | 21.60% | 27.55% | 1.28x | ✅ |
| `is_encodable_packed[bytes]` | 4.373101017054685e-05 | 3.723143397078951e-05 | 14.86% | 17.46% | 1.17x | ✅ |
| `is_encodable_packed[string]` | 4.4181230367373414e-05 | 3.359774754936314e-05 | 23.95% | 31.50% | 1.32x | ✅ |
| `is_encodable_packed[tuple]` | 0.00024930504458843186 | 0.00010218564771201838 | 59.01% | 143.97% | 2.44x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010839866694888287 | 5.939851008054462e-05 | 45.20% | 82.49% | 1.82x | ✅ |
