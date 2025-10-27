#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0006950961623749304 | 0.0005830498752287065 | 16.12% | 19.22% | 1.19x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0007412418414542546 | 0.0005859849051534614 | 20.95% | 26.50% | 1.26x | ✅ |
| `contextframesbytesio_init[32]` | 0.0007132726286131045 | 0.0006407700026067267 | 10.16% | 11.31% | 1.11x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0007032904395751828 | 0.0005874986309463522 | 16.46% | 19.71% | 1.20x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0007084568213006623 | 0.0005978052807771473 | 15.62% | 18.51% | 1.19x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0010035371691964703 | 0.0009917015411316978 | 1.18% | 1.19% | 1.01x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012389291056898616 | 0.00011365396295209955 | 8.26% | 9.01% | 1.09x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.005067805147207182 | 0.005037927743723546 | 0.59% | 0.59% | 1.01x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.0004999531645088041 | 0.00048359952719595364 | 3.27% | 3.38% | 1.03x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0004369799623315678 | 0.00043601627515650474 | 0.22% | 0.22% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[1]` | 5.528772304758063e-05 | 5.420736044797989e-05 | 1.95% | 1.99% | 1.02x | ✅ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0020667931503164155 | 0.0020617225525819374 | 0.25% | 0.25% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00020124926814611582 | 0.00020047671801809078 | 0.38% | 0.39% | 1.00x | ✅ |
