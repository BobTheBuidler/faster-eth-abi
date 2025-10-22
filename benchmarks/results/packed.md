#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0012417749106646333 | 0.0004304018365376483 | 65.34% | 188.52% | 2.89x | ✅ |
| `encode_packed[bool]` | 0.000718363720721586 | 0.0002533315771972946 | 64.73% | 183.57% | 2.84x | ✅ |
| `encode_packed[bytes]` | 0.0006589542586154856 | 0.00023821087894397873 | 63.85% | 176.63% | 2.77x | ✅ |
| `encode_packed[string]` | 0.0007017564030157832 | 0.00027150417353562017 | 61.31% | 158.47% | 2.58x | ✅ |
| `encode_packed[tuple]` | 0.001698077566421687 | 0.0008037580226426678 | 52.67% | 111.27% | 2.11x | ✅ |
| `encode_packed[uint256]` | 0.0008558868509796822 | 0.0003226598326990788 | 62.30% | 165.26% | 2.65x | ✅ |
| `is_encodable_packed[address]` | 6.499454821806694e-05 | 3.896380403359648e-05 | 40.05% | 66.81% | 1.67x | ✅ |
| `is_encodable_packed[bool]` | 4.5705781609254116e-05 | 3.384574269495485e-05 | 25.95% | 35.04% | 1.35x | ✅ |
| `is_encodable_packed[bytes]` | 4.587714147110527e-05 | 3.8468656682329586e-05 | 16.15% | 19.26% | 1.19x | ✅ |
| `is_encodable_packed[string]` | 4.551147909588499e-05 | 3.330898020067146e-05 | 26.81% | 36.63% | 1.37x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002556784438401529 | 0.0002080460824630417 | 18.63% | 22.90% | 1.23x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010382862438502557 | 6.351354192449427e-05 | 38.83% | 63.47% | 1.63x | ✅ |
