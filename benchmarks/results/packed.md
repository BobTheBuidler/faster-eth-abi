#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.001068033797577278 | 0.00027401867191120447 | 74.34% | 289.77% | 3.90x | ✅ |
| `encode_packed[bool]` | 0.0006147434520214149 | 0.00011161953443661332 | 81.84% | 450.75% | 5.51x | ✅ |
| `encode_packed[bytes]` | 0.000581119179532027 | 9.561901540871951e-05 | 83.55% | 507.74% | 6.08x | ✅ |
| `encode_packed[string]` | 0.0006220686862119429 | 0.00012810201965749877 | 79.41% | 385.60% | 4.86x | ✅ |
| `encode_packed[tuple]` | 0.001468365140379302 | 0.0003646506540225374 | 75.17% | 302.68% | 4.03x | ✅ |
| `encode_packed[uint256]` | 0.0007475398790338789 | 0.0001830494966850067 | 75.51% | 308.38% | 4.08x | ✅ |
| `is_encodable_packed[address]` | 6.151425965350671e-05 | 3.493160637088355e-05 | 43.21% | 76.10% | 1.76x | ✅ |
| `is_encodable_packed[bool]` | 4.384686771745621e-05 | 3.0439391469278514e-05 | 30.58% | 44.05% | 1.44x | ✅ |
| `is_encodable_packed[bytes]` | 4.4645250628630314e-05 | 3.363676712601545e-05 | 24.66% | 32.73% | 1.33x | ✅ |
| `is_encodable_packed[string]` | 4.464422171546778e-05 | 3.08769545722499e-05 | 30.84% | 44.59% | 1.45x | ✅ |
| `is_encodable_packed[tuple]` | 0.00024644808537863127 | 9.753112035282295e-05 | 60.43% | 152.69% | 2.53x | ✅ |
| `is_encodable_packed[uint256]` | 9.650352368267121e-05 | 5.3673881493787434e-05 | 44.38% | 79.80% | 1.80x | ✅ |
