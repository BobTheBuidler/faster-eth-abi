#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0012153142888583382 | 0.00043578713453376464 | 64.14% | 178.88% | 2.79x | ✅ |
| `encode_packed[bool]` | 0.0007038683904910622 | 0.0002478478817632175 | 64.79% | 183.99% | 2.84x | ✅ |
| `encode_packed[bytes]` | 0.0006521526733792573 | 0.00023880947461822467 | 63.38% | 173.08% | 2.73x | ✅ |
| `encode_packed[string]` | 0.0006884758250964973 | 0.00026769808161702523 | 61.12% | 157.18% | 2.57x | ✅ |
| `encode_packed[tuple]` | 0.0017078239620893626 | 0.0007878577162448453 | 53.87% | 116.77% | 2.17x | ✅ |
| `encode_packed[uint256]` | 0.0008422847541308826 | 0.0003176476441626619 | 62.29% | 165.16% | 2.65x | ✅ |
| `is_encodable_packed[address]` | 6.494986760583446e-05 | 4.901115231641871e-05 | 24.54% | 32.52% | 1.33x | ✅ |
| `is_encodable_packed[bool]` | 4.5250662544503054e-05 | 4.215131436101496e-05 | 6.85% | 7.35% | 1.07x | ✅ |
| `is_encodable_packed[bytes]` | 4.5997347280997335e-05 | 4.601212650857172e-05 | -0.03% | -0.03% | 1.00x | ❌ |
| `is_encodable_packed[string]` | 4.593266956268343e-05 | 4.243856450277384e-05 | 7.61% | 8.23% | 1.08x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002514567833742493 | 0.00020274072683569338 | 19.37% | 24.03% | 1.24x | ✅ |
| `is_encodable_packed[uint256]` | 9.944377178439617e-05 | 5.937102222221666e-05 | 40.30% | 67.50% | 1.67x | ✅ |
