#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0012112901462340657 | 0.0002777447823253353 | 77.07% | 336.12% | 4.36x | ✅ |
| `encode_packed[bool]` | 0.0007094336217061184 | 0.00011127619815745915 | 84.31% | 537.54% | 6.38x | ✅ |
| `encode_packed[bytes]` | 0.0006549141777648118 | 0.00010114054908715042 | 84.56% | 547.53% | 6.48x | ✅ |
| `encode_packed[string]` | 0.0006932313232101121 | 0.00012852466807137392 | 81.46% | 439.38% | 5.39x | ✅ |
| `encode_packed[tuple]` | 0.0016651516586442313 | 0.0003726445659698761 | 77.62% | 346.85% | 4.47x | ✅ |
| `encode_packed[uint256]` | 0.0008486852965463549 | 0.0001833337096216617 | 78.40% | 362.92% | 4.63x | ✅ |
| `is_encodable_packed[address]` | 6.414884851756277e-05 | 3.891561256607998e-05 | 39.34% | 64.84% | 1.65x | ✅ |
| `is_encodable_packed[bool]` | 4.4438709250037814e-05 | 3.320339066496146e-05 | 25.28% | 33.84% | 1.34x | ✅ |
| `is_encodable_packed[bytes]` | 4.565441847043332e-05 | 3.787830808264321e-05 | 17.03% | 20.53% | 1.21x | ✅ |
| `is_encodable_packed[string]` | 4.55905032440763e-05 | 3.227906995242089e-05 | 29.20% | 41.24% | 1.41x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002516369190358383 | 0.00010264921478895644 | 59.21% | 145.14% | 2.45x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010026885357430123 | 6.04382629331985e-05 | 39.72% | 65.90% | 1.66x | ✅ |
