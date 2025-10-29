#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0011884530543499834 | 0.0002820807938740475 | 76.26% | 321.32% | 4.21x | ✅ |
| `encode_packed[bool]` | 0.0006568187538433672 | 0.00010963992261047161 | 83.31% | 499.07% | 5.99x | ✅ |
| `encode_packed[bytes]` | 0.000608742461913102 | 9.935131920341848e-05 | 83.68% | 512.72% | 6.13x | ✅ |
| `encode_packed[string]` | 0.0006533675484118411 | 0.0001295562608364385 | 80.17% | 404.31% | 5.04x | ✅ |
| `encode_packed[tuple]` | 0.0016259781898996862 | 0.000373422033585622 | 77.03% | 335.43% | 4.35x | ✅ |
| `encode_packed[uint256]` | 0.000828376908137207 | 0.00018240119502176415 | 77.98% | 354.15% | 4.54x | ✅ |
| `is_encodable_packed[address]` | 6.429927929292379e-05 | 3.9904984326434505e-05 | 37.94% | 61.13% | 1.61x | ✅ |
| `is_encodable_packed[bool]` | 4.432089338843601e-05 | 3.362870649773979e-05 | 24.12% | 31.79% | 1.32x | ✅ |
| `is_encodable_packed[bytes]` | 4.417761810718693e-05 | 3.732169619475163e-05 | 15.52% | 18.37% | 1.18x | ✅ |
| `is_encodable_packed[string]` | 4.4585270604293016e-05 | 3.273347413582996e-05 | 26.58% | 36.21% | 1.36x | ✅ |
| `is_encodable_packed[tuple]` | 0.00025231766675916893 | 9.994055011634959e-05 | 60.39% | 152.47% | 2.52x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010726718497603819 | 5.924020037651018e-05 | 44.77% | 81.07% | 1.81x | ✅ |
