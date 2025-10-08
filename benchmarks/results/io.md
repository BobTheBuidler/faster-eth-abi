#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0006926054223803204 | 0.000629879112804186 | 9.06% | 9.96% | 1.10x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006947272697295206 | 0.0006269670757499013 | 9.75% | 10.81% | 1.11x | ✅ |
| `contextframesbytesio_init[32]` | 0.0006882975505769047 | 0.0006271157171504103 | 8.89% | 9.76% | 1.10x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0006851336975249924 | 0.0006235986994170015 | 8.98% | 9.87% | 1.10x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006891830722469707 | 0.0006217624657595888 | 9.78% | 10.84% | 1.11x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.000992267862660059 | 0.0009729150818312753 | 1.95% | 1.99% | 1.02x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012246385375856264 | 0.0001127217706190942 | 7.96% | 8.64% | 1.09x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.0050180555228385385 | 0.005015071255103039 | 0.06% | 0.06% | 1.00x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.00049544614681507 | 0.00047880041436784845 | 3.36% | 3.48% | 1.03x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0004340224107279509 | 0.0004359366566008036 | -0.44% | -0.44% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.4724859139349716e-05 | 5.525306834744334e-05 | -0.97% | -0.96% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0020905709873439665 | 0.0021028626523600267 | -0.59% | -0.58% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00020006192774437408 | 0.00020081606533160727 | -0.38% | -0.38% | 1.00x | ❌ |
