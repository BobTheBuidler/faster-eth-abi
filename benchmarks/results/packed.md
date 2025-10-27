#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0011947672202453294 | 0.00029077320281772234 | 75.66% | 310.89% | 4.11x | ✅ |
| `encode_packed[bool]` | 0.0006757605278621784 | 0.00011517083771078871 | 82.96% | 486.75% | 5.87x | ✅ |
| `encode_packed[bytes]` | 0.0006262760581310456 | 9.972892756033418e-05 | 84.08% | 527.98% | 6.28x | ✅ |
| `encode_packed[string]` | 0.0006697713528508865 | 0.00013533792410183956 | 79.79% | 394.89% | 4.95x | ✅ |
| `encode_packed[tuple]` | 0.0016680286032309958 | 0.0003830584641808961 | 77.04% | 335.45% | 4.35x | ✅ |
| `encode_packed[uint256]` | 0.0008421064094881087 | 0.00018929978816367935 | 77.52% | 344.85% | 4.45x | ✅ |
| `is_encodable_packed[address]` | 6.438214952389876e-05 | 3.915221720704429e-05 | 39.19% | 64.44% | 1.64x | ✅ |
| `is_encodable_packed[bool]` | 4.4133901552272844e-05 | 3.327160598702158e-05 | 24.61% | 32.65% | 1.33x | ✅ |
| `is_encodable_packed[bytes]` | 4.430265654636005e-05 | 3.634158065331005e-05 | 17.97% | 21.91% | 1.22x | ✅ |
| `is_encodable_packed[string]` | 4.411829896596444e-05 | 3.3166003045456764e-05 | 24.82% | 33.02% | 1.33x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002551082388258656 | 0.00010282669664895785 | 59.69% | 148.10% | 2.48x | ✅ |
| `is_encodable_packed[uint256]` | 0.00011421592560043178 | 6.145854687028366e-05 | 46.19% | 85.84% | 1.86x | ✅ |
