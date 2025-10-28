#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.000697551134627335 | 0.0006276719615841605 | 10.02% | 11.13% | 1.11x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006954824989348656 | 0.0006405136301219071 | 7.90% | 8.58% | 1.09x | ✅ |
| `contextframesbytesio_init[32]` | 0.000700723949604293 | 0.0006295485870125409 | 10.16% | 11.31% | 1.11x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0006962959800021703 | 0.0006200204993740499 | 10.95% | 12.30% | 1.12x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006989672537620508 | 0.0006247357022944945 | 10.62% | 11.88% | 1.12x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009740012004086101 | 0.0009555985680905484 | 1.89% | 1.93% | 1.02x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012548005018789198 | 0.00011134897593304104 | 11.26% | 12.69% | 1.13x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.004929037300499107 | 0.004930997207915119 | -0.04% | -0.04% | 1.00x | ❌ |
| `contextframesbytesio_push_pop[5]` | 0.0004900292226656675 | 0.00046936797631724606 | 4.22% | 4.40% | 1.04x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.000402139168812231 | 0.00040253882481355277 | -0.10% | -0.10% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.536242326514968e-05 | 5.437320146915285e-05 | 1.79% | 1.82% | 1.02x | ✅ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0019136991445091497 | 0.0019226309941701596 | -0.47% | -0.46% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00019952093305998769 | 0.0001986620510314489 | 0.43% | 0.43% | 1.00x | ✅ |
