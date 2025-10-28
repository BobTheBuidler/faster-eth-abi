#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0007009319006995172 | 0.0006316335200486728 | 9.89% | 10.97% | 1.11x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0007022928658182788 | 0.0006259522440454599 | 10.87% | 12.20% | 1.12x | ✅ |
| `contextframesbytesio_init[32]` | 0.0007053554634299006 | 0.0006310099330410375 | 10.54% | 11.78% | 1.12x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0006974189544439945 | 0.000627013004345406 | 10.10% | 11.23% | 1.11x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006957806827180804 | 0.0006276861604277606 | 9.79% | 10.85% | 1.11x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009863439555076543 | 0.0009590866254963366 | 2.76% | 2.84% | 1.03x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012579989525664449 | 0.00011063410337380654 | 12.06% | 13.71% | 1.14x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.005045653595003614 | 0.004995032507539046 | 1.00% | 1.01% | 1.01x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.0004895052151443676 | 0.0004649682904319849 | 5.01% | 5.28% | 1.05x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0004032338518640152 | 0.0004116303234301087 | -2.08% | -2.04% | 0.98x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.6212706933245046e-05 | 5.517325404653695e-05 | 1.85% | 1.88% | 1.02x | ✅ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0019274759727121345 | 0.0019176947084967655 | 0.51% | 0.51% | 1.01x | ✅ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00019886657723215386 | 0.00020115785100124412 | -1.15% | -1.14% | 0.99x | ❌ |
