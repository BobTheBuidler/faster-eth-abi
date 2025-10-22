#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0007896833629737091 | 0.0007049832174213268 | 10.73% | 12.01% | 1.12x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0007923250415329406 | 0.0007089600935253218 | 10.52% | 11.76% | 1.12x | ✅ |
| `contextframesbytesio_init[32]` | 0.0007981602381709216 | 0.0007045675822500151 | 11.73% | 13.28% | 1.13x | ✅ |
| `contextframesbytesio_init[4096]` | 0.000786081609086774 | 0.0007058098462103498 | 10.21% | 11.37% | 1.11x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0007893135281212341 | 0.0007192887375201972 | 8.87% | 9.74% | 1.10x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009805510923813715 | 0.0009700306876839922 | 1.07% | 1.08% | 1.01x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012346979359146651 | 0.00011399373051026372 | 7.67% | 8.31% | 1.08x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.0050422130309330316 | 0.005181251840003825 | -2.76% | -2.68% | 0.97x | ❌ |
| `contextframesbytesio_push_pop[5]` | 0.0004936868816662574 | 0.00047880879742377653 | 3.01% | 3.11% | 1.03x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0004375911492199113 | 0.00043550179687260976 | 0.48% | 0.48% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[1]` | 5.494051734518659e-05 | 5.5186826115493636e-05 | -0.45% | -0.45% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0020637313249550113 | 0.002080129217759313 | -0.79% | -0.79% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00019870365020644375 | 0.00019962529767431783 | -0.46% | -0.46% | 1.00x | ❌ |
