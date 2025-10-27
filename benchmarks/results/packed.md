#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0012550726199165572 | 0.0002804328460132739 | 77.66% | 347.55% | 4.48x | ✅ |
| `encode_packed[bool]` | 0.0007321868286213847 | 0.00011066962106048447 | 84.89% | 561.60% | 6.62x | ✅ |
| `encode_packed[bytes]` | 0.000669244154512308 | 9.959829546379337e-05 | 85.12% | 571.94% | 6.72x | ✅ |
| `encode_packed[string]` | 0.0007106070055314099 | 0.00012994308840383705 | 81.71% | 446.86% | 5.47x | ✅ |
| `encode_packed[tuple]` | 0.0017072340457934675 | 0.00038248930828779825 | 77.60% | 346.35% | 4.46x | ✅ |
| `encode_packed[uint256]` | 0.0008736968538543935 | 0.00018523149764216847 | 78.80% | 371.68% | 4.72x | ✅ |
| `is_encodable_packed[address]` | 6.367740369044237e-05 | 3.9125968091532356e-05 | 38.56% | 62.75% | 1.63x | ✅ |
| `is_encodable_packed[bool]` | 4.48609419156723e-05 | 3.403882788742778e-05 | 24.12% | 31.79% | 1.32x | ✅ |
| `is_encodable_packed[bytes]` | 4.6182346303438975e-05 | 3.9254698780270905e-05 | 15.00% | 17.65% | 1.18x | ✅ |
| `is_encodable_packed[string]` | 4.5278376266611336e-05 | 3.396405361485336e-05 | 24.99% | 33.31% | 1.33x | ✅ |
| `is_encodable_packed[tuple]` | 0.00025254272764981326 | 0.00010371446796080879 | 58.93% | 143.50% | 2.43x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010165069219136934 | 6.193486943702043e-05 | 39.07% | 64.13% | 1.64x | ✅ |
