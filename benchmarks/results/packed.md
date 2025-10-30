#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0012280509654666396 | 0.0002817866776421531 | 77.05% | 335.81% | 4.36x | ✅ |
| `encode_packed[bool]` | 0.000680805093075273 | 0.00010815958484395163 | 84.11% | 529.44% | 6.29x | ✅ |
| `encode_packed[bytes]` | 0.0006284995466785404 | 9.729182527974386e-05 | 84.52% | 545.99% | 6.46x | ✅ |
| `encode_packed[string]` | 0.0006762789656010417 | 0.00012869261984293348 | 80.97% | 425.50% | 5.25x | ✅ |
| `encode_packed[tuple]` | 0.0016530773850276328 | 0.0003686646350119482 | 77.70% | 348.40% | 4.48x | ✅ |
| `encode_packed[uint256]` | 0.0008462622085398419 | 0.0001793361981139866 | 78.81% | 371.89% | 4.72x | ✅ |
| `is_encodable_packed[address]` | 6.264363079508601e-05 | 3.810789469092974e-05 | 39.17% | 64.38% | 1.64x | ✅ |
| `is_encodable_packed[bool]` | 4.348022268801073e-05 | 3.318524239895318e-05 | 23.68% | 31.02% | 1.31x | ✅ |
| `is_encodable_packed[bytes]` | 4.351838203884063e-05 | 3.6901741663989566e-05 | 15.20% | 17.93% | 1.18x | ✅ |
| `is_encodable_packed[string]` | 4.363523098956106e-05 | 3.306399479253895e-05 | 24.23% | 31.97% | 1.32x | ✅ |
| `is_encodable_packed[tuple]` | 0.00024729357001269096 | 9.946071287907115e-05 | 59.78% | 148.63% | 2.49x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010714477947118831 | 5.8101943445417254e-05 | 45.77% | 84.41% | 1.84x | ✅ |
