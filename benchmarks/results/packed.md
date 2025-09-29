#### [faster_eth_abi.packed](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/packed.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_packed_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `encode_packed[address]` | 0.001238354573034444 | 0.0004340535270468641 | 64.95% | 185.30% | 2.85x | ✅ |
| `encode_packed[bool]` | 0.0007062157545415326 | 0.00025777747722175923 | 63.50% | 173.96% | 2.74x | ✅ |
| `encode_packed[bytes]` | 0.000661908274814946 | 0.0002504795839060695 | 62.16% | 164.26% | 2.64x | ✅ |
| `encode_packed[string]` | 0.0007065589830507178 | 0.00027789587985589643 | 60.67% | 154.25% | 2.54x | ✅ |
| `encode_packed[tuple]` | 0.0016631383949310891 | 0.0008022235747738386 | 51.76% | 107.32% | 2.07x | ✅ |
| `encode_packed[uint256]` | 0.0008654342280752231 | 0.00032925878909115843 | 61.95% | 162.84% | 2.63x | ✅ |
| `is_encodable_packed[address]` | 6.384262127394412e-05 | 4.796149469768371e-05 | 24.88% | 33.11% | 1.33x | ✅ |
| `is_encodable_packed[bool]` | 4.420413902208423e-05 | 4.291264286287604e-05 | 2.92% | 3.01% | 1.03x | ✅ |
| `is_encodable_packed[bytes]` | 4.5923078649814404e-05 | 4.579282662904083e-05 | 0.28% | 0.28% | 1.00x | ✅ |
| `is_encodable_packed[string]` | 4.560585204214317e-05 | 4.200494395577694e-05 | 7.90% | 8.57% | 1.09x | ✅ |
| `is_encodable_packed[tuple]` | 0.00025325544123665347 | 0.00020781615534555466 | 17.94% | 21.87% | 1.22x | ✅ |
| `is_encodable_packed[uint256]` | 0.00010272889972959525 | 6.0934774448988794e-05 | 40.68% | 68.59% | 1.69x | ✅ |
