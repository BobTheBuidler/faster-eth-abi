#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.001207582172919477 | 0.00028509653082601415 | 76.39% | 323.57% | 4.24x | ✅ |
| `encode_packed[bool]` | 0.0007034728800021648 | 0.00011394233481634014 | 83.80% | 517.39% | 6.17x | ✅ |
| `encode_packed[bytes]` | 0.0006410569006419423 | 9.848584471960677e-05 | 84.64% | 550.91% | 6.51x | ✅ |
| `encode_packed[string]` | 0.0006865122965721977 | 0.00012994118254234556 | 81.07% | 428.33% | 5.28x | ✅ |
| `encode_packed[tuple]` | 0.001671822620803648 | 0.0003930787399437867 | 76.49% | 325.31% | 4.25x | ✅ |
| `encode_packed[uint256]` | 0.0008357495009859555 | 0.0001842153203466452 | 77.96% | 353.68% | 4.54x | ✅ |
| `is_encodable_packed[address]` | 6.428784402397986e-05 | 3.860862724113372e-05 | 39.94% | 66.51% | 1.67x | ✅ |
| `is_encodable_packed[bool]` | 4.437916897036878e-05 | 3.304513070484864e-05 | 25.54% | 34.30% | 1.34x | ✅ |
| `is_encodable_packed[bytes]` | 4.606474279683863e-05 | 3.6874734398196315e-05 | 19.95% | 24.92% | 1.25x | ✅ |
| `is_encodable_packed[string]` | 4.491372184369161e-05 | 3.267470516960591e-05 | 27.25% | 37.46% | 1.37x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002650672976211925 | 0.0001030902163329857 | 61.11% | 157.12% | 2.57x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010938203085739352 | 6.025021828954519e-05 | 44.92% | 81.55% | 1.82x | ✅ |
