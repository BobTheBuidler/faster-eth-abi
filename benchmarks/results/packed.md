#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0012592251346656216 | 0.0004369340218906919 | 65.30% | 188.20% | 2.88x | ✅ |
| `encode_packed[bool]` | 0.0007416110584162138 | 0.0002461169630577573 | 66.81% | 201.32% | 3.01x | ✅ |
| `encode_packed[bytes]` | 0.0006978548658610798 | 0.000244150421283868 | 65.01% | 185.83% | 2.86x | ✅ |
| `encode_packed[string]` | 0.0007332304194644802 | 0.0002680323231821411 | 63.45% | 173.56% | 2.74x | ✅ |
| `encode_packed[tuple]` | 0.001703523598512744 | 0.0007883809920359108 | 53.72% | 116.08% | 2.16x | ✅ |
| `encode_packed[uint256]` | 0.0009026773158982393 | 0.000315169274851013 | 65.09% | 186.41% | 2.86x | ✅ |
| `is_encodable_packed[address]` | 6.664223294258654e-05 | 4.999121237617008e-05 | 24.99% | 33.31% | 1.33x | ✅ |
| `is_encodable_packed[bool]` | 4.480656533756894e-05 | 4.280994070228932e-05 | 4.46% | 4.66% | 1.05x | ✅ |
| `is_encodable_packed[bytes]` | 4.6266020849519696e-05 | 4.77947116456353e-05 | -3.30% | -3.20% | 0.97x | ❌ |
| `is_encodable_packed[string]` | 4.637218390073385e-05 | 4.2699306160197725e-05 | 7.92% | 8.60% | 1.09x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002551428594286129 | 0.0002046457479141113 | 19.79% | 24.68% | 1.25x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010204138309883231 | 6.049325712519185e-05 | 40.72% | 68.68% | 1.69x | ✅ |
