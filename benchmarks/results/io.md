#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0007070021957648779 | 0.0006234282036118528 | 11.82% | 13.41% | 1.13x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0007117978674692272 | 0.0006288511710870709 | 11.65% | 13.19% | 1.13x | ✅ |
| `contextframesbytesio_init[32]` | 0.0007061308243130467 | 0.0006256796623916491 | 11.39% | 12.86% | 1.13x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0007050266942622708 | 0.0006263510891920101 | 11.16% | 12.56% | 1.13x | ✅ |
| `contextframesbytesio_init[65536]` | 0.00069871024982254 | 0.0006207344012623984 | 11.16% | 12.56% | 1.13x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009678097339924602 | 0.0009426914529741189 | 2.60% | 2.66% | 1.03x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012683753065482377 | 0.0001117352179602224 | 11.91% | 13.52% | 1.14x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.004916634413796247 | 0.004881869282929451 | 0.71% | 0.71% | 1.01x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.00048203158867719304 | 0.0004631617989371576 | 3.91% | 4.07% | 1.04x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0003966300983133744 | 0.0003971517280613494 | -0.13% | -0.13% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.57549429038388e-05 | 5.524013814143308e-05 | 0.92% | 0.93% | 1.01x | ✅ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0018907650248994807 | 0.001878586293330608 | 0.64% | 0.65% | 1.01x | ✅ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00019560950985415452 | 0.000195057707833025 | 0.28% | 0.28% | 1.00x | ✅ |
