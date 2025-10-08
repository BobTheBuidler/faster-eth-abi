#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0007018614630314503 | 0.000632610343687661 | 9.87% | 10.95% | 1.11x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006927912862176652 | 0.000636296716365543 | 8.15% | 8.88% | 1.09x | ✅ |
| `contextframesbytesio_init[32]` | 0.0006987646186404692 | 0.0006321055086174295 | 9.54% | 10.55% | 1.11x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0006945133660606718 | 0.0006353692165687529 | 8.52% | 9.31% | 1.09x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006886792392722374 | 0.0006363788571467945 | 7.59% | 8.22% | 1.08x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.001002127848670758 | 0.0009854490803228003 | 1.66% | 1.69% | 1.02x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012323363772705665 | 0.00011382385588366418 | 7.64% | 8.27% | 1.08x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.005103578283500817 | 0.005241211683934818 | -2.70% | -2.63% | 0.97x | ❌ |
| `contextframesbytesio_push_pop[5]` | 0.0004949939542139534 | 0.00048371674350130433 | 2.28% | 2.33% | 1.02x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0004391828273758127 | 0.0004394759008593704 | -0.07% | -0.07% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.6332195749030844e-05 | 5.519951477424251e-05 | 2.01% | 2.05% | 1.02x | ✅ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0021269008305023554 | 0.002112294305730552 | 0.69% | 0.69% | 1.01x | ✅ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00020468784420266462 | 0.00020226090128156233 | 1.19% | 1.20% | 1.01x | ✅ |
