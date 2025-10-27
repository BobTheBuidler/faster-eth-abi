#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0012424133209737265 | 0.00027762620352959715 | 77.65% | 347.51% | 4.48x | ✅ |
| `encode_packed[bool]` | 0.0007075366260808187 | 0.00011468927322614472 | 83.79% | 516.92% | 6.17x | ✅ |
| `encode_packed[bytes]` | 0.0006575112828476717 | 0.00010019825004189721 | 84.76% | 556.21% | 6.56x | ✅ |
| `encode_packed[string]` | 0.0006971740007714845 | 0.00012996851886090582 | 81.36% | 436.42% | 5.36x | ✅ |
| `encode_packed[tuple]` | 0.00170476083985027 | 0.00038197137866045677 | 77.59% | 346.31% | 4.46x | ✅ |
| `encode_packed[uint256]` | 0.0008653475933180461 | 0.00018808382230028623 | 78.26% | 360.09% | 4.60x | ✅ |
| `is_encodable_packed[address]` | 6.453865583727094e-05 | 3.918452782942775e-05 | 39.29% | 64.70% | 1.65x | ✅ |
| `is_encodable_packed[bool]` | 4.4840447209459166e-05 | 3.4543030982565374e-05 | 22.96% | 29.81% | 1.30x | ✅ |
| `is_encodable_packed[bytes]` | 4.5823544678057064e-05 | 3.793213516827522e-05 | 17.22% | 20.80% | 1.21x | ✅ |
| `is_encodable_packed[string]` | 4.618409800662993e-05 | 3.4186245877000584e-05 | 25.98% | 35.10% | 1.35x | ✅ |
| `is_encodable_packed[tuple]` | 0.00025576146718906003 | 0.00010675394699324658 | 58.26% | 139.58% | 2.40x | ✅ |
| `is_encodable_packed[uint256]` | 0.0001009711593391369 | 6.365057201693546e-05 | 36.96% | 58.63% | 1.59x | ✅ |
