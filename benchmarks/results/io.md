#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0006986331000031701 | 0.0006315308742655531 | 9.60% | 10.63% | 1.11x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0007015242879669456 | 0.0006423394894577583 | 8.44% | 9.21% | 1.09x | ✅ |
| `contextframesbytesio_init[32]` | 0.000689466544225329 | 0.0006370562476875317 | 7.60% | 8.23% | 1.08x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0006922790790051353 | 0.0006422189419541576 | 7.23% | 7.79% | 1.08x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006932033683452925 | 0.0006394621451894972 | 7.75% | 8.40% | 1.08x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0010001392054213962 | 0.0009654502078060099 | 3.47% | 3.59% | 1.04x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012715696468324004 | 0.00011439641756196175 | 10.04% | 11.15% | 1.11x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.005026005737372635 | 0.004940563079205979 | 1.70% | 1.73% | 1.02x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.0004899301626660954 | 0.0004854785627182648 | 0.91% | 0.92% | 1.01x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0004403788137199927 | 0.0004402451861177667 | 0.03% | 0.03% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[1]` | 5.449964184580357e-05 | 5.4674149338722424e-05 | -0.32% | -0.32% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0020971202096457826 | 0.0021087416012713083 | -0.55% | -0.55% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00020229645076432517 | 0.00020226537699221338 | 0.02% | 0.02% | 1.00x | ✅ |
