#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0012065166694296744 | 0.0004337048012379005 | 64.05% | 178.19% | 2.78x | ✅ |
| `encode_packed[bool]` | 0.0007074897091810283 | 0.00024837175128085713 | 64.89% | 184.85% | 2.85x | ✅ |
| `encode_packed[bytes]` | 0.0006552738873124597 | 0.00023525944949654288 | 64.10% | 178.53% | 2.79x | ✅ |
| `encode_packed[string]` | 0.0007043320626980713 | 0.00026858235620405856 | 61.87% | 162.24% | 2.62x | ✅ |
| `encode_packed[tuple]` | 0.0016645752531881267 | 0.0008000080027340116 | 51.94% | 108.07% | 2.08x | ✅ |
| `encode_packed[uint256]` | 0.000846364776575719 | 0.0003205613312773816 | 62.12% | 164.03% | 2.64x | ✅ |
| `is_encodable_packed[address]` | 6.52894611830512e-05 | 3.989145809533389e-05 | 38.90% | 63.67% | 1.64x | ✅ |
| `is_encodable_packed[bool]` | 4.674092843528042e-05 | 3.506311337669572e-05 | 24.98% | 33.31% | 1.33x | ✅ |
| `is_encodable_packed[bytes]` | 4.606161739015109e-05 | 3.877739258188242e-05 | 15.81% | 18.78% | 1.19x | ✅ |
| `is_encodable_packed[string]` | 4.4118408789256596e-05 | 3.343474944583635e-05 | 24.22% | 31.95% | 1.32x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002526565133226104 | 0.00020750669495040784 | 17.87% | 21.76% | 1.22x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010200952947389481 | 6.304594505596437e-05 | 38.20% | 61.80% | 1.62x | ✅ |
