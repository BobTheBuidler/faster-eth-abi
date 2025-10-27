#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0006751571729271567 | 0.0006395803999993084 | 5.27% | 5.56% | 1.06x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006915068770972691 | 0.0006385471972371808 | 7.66% | 8.29% | 1.08x | ✅ |
| `contextframesbytesio_init[32]` | 0.0006927488678443929 | 0.0006263157986919753 | 9.59% | 10.61% | 1.11x | ✅ |
| `contextframesbytesio_init[4096]` | 0.000705269771897039 | 0.0006354776383824891 | 9.90% | 10.98% | 1.11x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0007011352110185571 | 0.0006319933686265263 | 9.86% | 10.94% | 1.11x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0010089636317448705 | 0.0009801545802617538 | 2.86% | 2.94% | 1.03x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.0001238917183538814 | 0.00011544595730046271 | 6.82% | 7.32% | 1.07x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.005027764020306321 | 0.004950299519995269 | 1.54% | 1.56% | 1.02x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.0004965343401936859 | 0.0004801495737089398 | 3.30% | 3.41% | 1.03x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.00043888489325149535 | 0.0004418780749872402 | -0.68% | -0.68% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.357207444027967e-05 | 5.656295594837034e-05 | -5.58% | -5.29% | 0.95x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0021062546054791873 | 0.002109995635982669 | -0.18% | -0.18% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00020034589928098344 | 0.00020380585408015484 | -1.73% | -1.70% | 0.98x | ❌ |
