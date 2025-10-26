#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0010609074104469633 | 0.00027645807321734054 | 73.94% | 283.75% | 3.84x | ✅ |
| `encode_packed[bool]` | 0.0006269561843235106 | 0.00011239836876912956 | 82.07% | 457.80% | 5.58x | ✅ |
| `encode_packed[bytes]` | 0.0005905417476407068 | 9.750826454417228e-05 | 83.49% | 505.63% | 6.06x | ✅ |
| `encode_packed[string]` | 0.0006261542263768366 | 0.00012816086222626285 | 79.53% | 388.57% | 4.89x | ✅ |
| `encode_packed[tuple]` | 0.001468223106973962 | 0.00036528916666622355 | 75.12% | 301.93% | 4.02x | ✅ |
| `encode_packed[uint256]` | 0.0007576550570463322 | 0.00018232453738473183 | 75.94% | 315.55% | 4.16x | ✅ |
| `is_encodable_packed[address]` | 6.130525352941717e-05 | 4.000698039870025e-05 | 34.74% | 53.24% | 1.53x | ✅ |
| `is_encodable_packed[bool]` | 4.3744840083700046e-05 | 3.6060597083888696e-05 | 17.57% | 21.31% | 1.21x | ✅ |
| `is_encodable_packed[bytes]` | 4.4894217469538e-05 | 3.9049368864921055e-05 | 13.02% | 14.97% | 1.15x | ✅ |
| `is_encodable_packed[string]` | 4.515470260965305e-05 | 3.6573627403074254e-05 | 19.00% | 23.46% | 1.23x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002467234766246865 | 9.923359390872944e-05 | 59.78% | 148.63% | 2.49x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010329894918707188 | 5.433640791811176e-05 | 47.40% | 90.11% | 1.90x | ✅ |
