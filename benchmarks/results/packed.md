#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.001216206686717192 | 0.0002852137114585762 | 76.55% | 326.42% | 4.26x | ✅ |
| `encode_packed[bool]` | 0.0006723986432300402 | 0.00011119419530667215 | 83.46% | 504.71% | 6.05x | ✅ |
| `encode_packed[bytes]` | 0.0006114023091589969 | 9.77541519025717e-05 | 84.01% | 525.45% | 6.25x | ✅ |
| `encode_packed[string]` | 0.0006637641874080912 | 0.00012960631466793425 | 80.47% | 412.14% | 5.12x | ✅ |
| `encode_packed[tuple]` | 0.0016624698287810076 | 0.00037681096438493665 | 77.33% | 341.19% | 4.41x | ✅ |
| `encode_packed[uint256]` | 0.0008396828778829173 | 0.00017996881179398918 | 78.57% | 366.57% | 4.67x | ✅ |
| `is_encodable_packed[address]` | 6.341395517637788e-05 | 3.854775306152725e-05 | 39.21% | 64.51% | 1.65x | ✅ |
| `is_encodable_packed[bool]` | 4.4027556639097666e-05 | 3.353266988297222e-05 | 23.84% | 31.30% | 1.31x | ✅ |
| `is_encodable_packed[bytes]` | 4.4208388748610506e-05 | 3.750645360906269e-05 | 15.16% | 17.87% | 1.18x | ✅ |
| `is_encodable_packed[string]` | 4.362823960781543e-05 | 3.3468126918703566e-05 | 23.29% | 30.36% | 1.30x | ✅ |
| `is_encodable_packed[tuple]` | 0.0002506693408657867 | 0.00010144436711533016 | 59.53% | 147.10% | 2.47x | ✅ |
| `is_encodable_packed[uint256]` | 0.0001084984904249806 | 5.840882628700511e-05 | 46.17% | 85.76% | 1.86x | ✅ |
