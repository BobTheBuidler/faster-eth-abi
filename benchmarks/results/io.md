#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0006965283443992796 | 0.0006161930513359092 | 11.53% | 13.04% | 1.13x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006987164094660703 | 0.0006278964492600045 | 10.14% | 11.28% | 1.11x | ✅ |
| `contextframesbytesio_init[32]` | 0.000697138602395088 | 0.0006205019499103829 | 10.99% | 12.35% | 1.12x | ✅ |
| `contextframesbytesio_init[4096]` | 0.000698957420709391 | 0.0006249589407272967 | 10.59% | 11.84% | 1.12x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0007020244192201887 | 0.0006219336541466786 | 11.41% | 12.88% | 1.13x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009797291219583117 | 0.0009551674570758534 | 2.51% | 2.57% | 1.03x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012602454756402003 | 0.00011186577503611111 | 11.23% | 12.66% | 1.13x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.005062792071737185 | 0.004972183169120942 | 1.79% | 1.82% | 1.02x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.0004844119994970002 | 0.0004630575026983218 | 4.41% | 4.61% | 1.05x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0004073958811866239 | 0.000406945414678621 | 0.11% | 0.11% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[1]` | 5.6208475140552806e-05 | 5.600102217454129e-05 | 0.37% | 0.37% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[50]` | 0.001936370519494801 | 0.0019393840545860628 | -0.16% | -0.16% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00019756255712574444 | 0.00020112041637871745 | -1.80% | -1.77% | 0.98x | ❌ |
