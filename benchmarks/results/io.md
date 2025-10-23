#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0007037078691532956 | 0.0006319094246874511 | 10.20% | 11.36% | 1.11x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006936705524377226 | 0.0006299962864617308 | 9.18% | 10.11% | 1.10x | ✅ |
| `contextframesbytesio_init[32]` | 0.0006974485489082697 | 0.0006313646700247718 | 9.48% | 10.47% | 1.10x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0006926461302188688 | 0.0006323604813211611 | 8.70% | 9.53% | 1.10x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006924730089729105 | 0.0006341224230001829 | 8.43% | 9.20% | 1.09x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009840952909933095 | 0.0009589457814976284 | 2.56% | 2.62% | 1.03x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012005554769042925 | 0.00011398610421820895 | 5.06% | 5.32% | 1.05x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.004988204994950165 | 0.004965068340000016 | 0.46% | 0.47% | 1.00x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.0005009010980278549 | 0.0004696689437727602 | 6.24% | 6.65% | 1.07x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.00043448289233569495 | 0.0004368125907665179 | -0.54% | -0.53% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.3487207249223464e-05 | 5.428146960132265e-05 | -1.48% | -1.46% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.002095101631803365 | 0.0020959322993597037 | -0.04% | -0.04% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[5]` | 0.0001991058398072996 | 0.0002003442776864138 | -0.62% | -0.62% | 0.99x | ❌ |
