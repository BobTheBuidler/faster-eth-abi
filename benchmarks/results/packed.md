#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.0012206231683298788 | 0.00035365828234232256 | 71.03% | 245.14% | 3.45x | ✅ |
| `encode_packed[bool]` | 0.0007077185218789775 | 0.00017628131246922408 | 75.09% | 301.47% | 4.01x | ✅ |
| `encode_packed[bytes]` | 0.0006576656773015501 | 0.00016135589313760678 | 75.47% | 307.59% | 4.08x | ✅ |
| `encode_packed[string]` | 0.0007044936750988293 | 0.00019313802471288 | 72.58% | 264.76% | 3.65x | ✅ |
| `encode_packed[tuple]` | 0.0016984392631648486 | 0.0004991928880885673 | 70.61% | 240.24% | 3.40x | ✅ |
| `encode_packed[uint256]` | 0.00086095064371474 | 0.000255543384981498 | 70.32% | 236.91% | 3.37x | ✅ |
| `is_encodable_packed[address]` | 6.673683811049593e-05 | 4.125258682528195e-05 | 38.19% | 61.78% | 1.62x | ✅ |
| `is_encodable_packed[bool]` | 4.5681307117191316e-05 | 3.306228059596424e-05 | 27.62% | 38.17% | 1.38x | ✅ |
| `is_encodable_packed[bytes]` | 4.5347736091704576e-05 | 3.790385582924335e-05 | 16.42% | 19.64% | 1.20x | ✅ |
| `is_encodable_packed[string]` | 4.448670971931466e-05 | 3.353411097485072e-05 | 24.62% | 32.66% | 1.33x | ✅ |
| `is_encodable_packed[tuple]` | 0.00025445604812352726 | 0.0001058698682447533 | 58.39% | 140.35% | 2.40x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010278240743847179 | 6.215273983406938e-05 | 39.53% | 65.37% | 1.65x | ✅ |
