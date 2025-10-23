#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0006934023180252398 | 0.0006342734999971903 | 8.53% | 9.32% | 1.09x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006990236883163206 | 0.0006305238685736369 | 9.80% | 10.86% | 1.11x | ✅ |
| `contextframesbytesio_init[32]` | 0.0007007509388180687 | 0.000633320079713805 | 9.62% | 10.65% | 1.11x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0007096502731843904 | 0.0006376734487553992 | 10.14% | 11.29% | 1.11x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006922756272951913 | 0.000633457968825596 | 8.50% | 9.29% | 1.09x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009964939878895998 | 0.000979052269384343 | 1.75% | 1.78% | 1.02x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012611224196560015 | 0.00011484473591657102 | 8.93% | 9.81% | 1.10x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.005018090060611893 | 0.005092640252527041 | -1.49% | -1.46% | 0.99x | ❌ |
| `contextframesbytesio_push_pop[5]` | 0.0004983259831635446 | 0.00048270851218367334 | 3.13% | 3.24% | 1.03x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0004397596320684089 | 0.0004401743080341641 | -0.09% | -0.09% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.5783440166338475e-05 | 5.559507272470715e-05 | 0.34% | 0.34% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0021157872489319363 | 0.002085867555787397 | 1.41% | 1.43% | 1.01x | ✅ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00020254584238562384 | 0.00020162031743096293 | 0.46% | 0.46% | 1.00x | ✅ |
