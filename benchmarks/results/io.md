#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0006903130061306368 | 0.0006282850512625308 | 8.99% | 9.87% | 1.10x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006896946912463727 | 0.0006264204687130148 | 9.17% | 10.10% | 1.10x | ✅ |
| `contextframesbytesio_init[32]` | 0.0007059205010284734 | 0.0006245783169687936 | 11.52% | 13.02% | 1.13x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0006945460871129903 | 0.0006219520966353225 | 10.45% | 11.67% | 1.12x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006894644044967954 | 0.0006261430667090236 | 9.18% | 10.11% | 1.10x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009674611785020818 | 0.0009545806245146213 | 1.33% | 1.35% | 1.01x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012589008362438292 | 0.00010920241695872172 | 13.26% | 15.28% | 1.15x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.004871575049514606 | 0.004846442697567554 | 0.52% | 0.52% | 1.01x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.00048010276384107025 | 0.00047004295026461954 | 2.10% | 2.14% | 1.02x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.00040021527606713263 | 0.0003996810178114358 | 0.13% | 0.13% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[1]` | 5.479157387039521e-05 | 5.6287873082201715e-05 | -2.73% | -2.66% | 0.97x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0018965817280013652 | 0.0019163686718182249 | -1.04% | -1.03% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[5]` | 0.0001955293489089683 | 0.00019640214228305232 | -0.45% | -0.44% | 1.00x | ❌ |
