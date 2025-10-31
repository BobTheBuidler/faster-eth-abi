#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0007071054506858424 | 0.0006305980494970239 | 10.82% | 12.13% | 1.12x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0007070374862052694 | 0.0006265109741964131 | 11.39% | 12.85% | 1.13x | ✅ |
| `contextframesbytesio_init[32]` | 0.0007056439488110218 | 0.000627622620087224 | 11.06% | 12.43% | 1.12x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0007150699749253074 | 0.0006280574721690251 | 12.17% | 13.85% | 1.14x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006971053307102336 | 0.0006292147817937331 | 9.74% | 10.79% | 1.11x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009843710733665049 | 0.0009568393440204038 | 2.80% | 2.88% | 1.03x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012555636304449378 | 0.00011128413809687396 | 11.37% | 12.83% | 1.13x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.004999778519994606 | 0.005028703633159002 | -0.58% | -0.58% | 0.99x | ❌ |
| `contextframesbytesio_push_pop[5]` | 0.0004860455380730624 | 0.000469653176871953 | 3.37% | 3.49% | 1.03x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0004025123699539057 | 0.0004041999054419845 | -0.42% | -0.42% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.595365715251749e-05 | 5.609696249674048e-05 | -0.26% | -0.26% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0019413368274537753 | 0.0019351520548039174 | 0.32% | 0.32% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[5]` | 0.0001944520989863957 | 0.00019697797654572022 | -1.30% | -1.28% | 0.99x | ❌ |
