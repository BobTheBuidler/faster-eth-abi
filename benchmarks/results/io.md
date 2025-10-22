#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0007059493972818854 | 0.0006312098749212568 | 10.59% | 11.84% | 1.12x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0007058473956996462 | 0.0006336646574537018 | 10.23% | 11.39% | 1.11x | ✅ |
| `contextframesbytesio_init[32]` | 0.0007145773892093301 | 0.0006285654831631994 | 12.04% | 13.68% | 1.14x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0006989119087658326 | 0.0006341250155208253 | 9.27% | 10.22% | 1.10x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0007050922923265213 | 0.000631715852489945 | 10.41% | 11.62% | 1.12x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009987623114763803 | 0.0009712126669926826 | 2.76% | 2.84% | 1.03x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.0001232887058747086 | 0.00011221187282978195 | 8.98% | 9.87% | 1.10x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.005069150882653568 | 0.005031879434344581 | 0.74% | 0.74% | 1.01x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.0004971540625647529 | 0.0004771224792722684 | 4.03% | 4.20% | 1.04x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0004416174003573966 | 0.0004386267102302852 | 0.68% | 0.68% | 1.01x | ✅ |
| `contextframesbytesio_seek_in_frame[1]` | 5.5376206618734125e-05 | 5.5397508101043585e-05 | -0.04% | -0.04% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0021174907914737946 | 0.002102750691831924 | 0.70% | 0.70% | 1.01x | ✅ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00020203366976894656 | 0.00020213848038559562 | -0.05% | -0.05% | 1.00x | ❌ |
