#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0007100404378087125 | 0.0006371914916948045 | 10.26% | 11.43% | 1.11x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006969579972290146 | 0.0006356062982248766 | 8.80% | 9.65% | 1.10x | ✅ |
| `contextframesbytesio_init[32]` | 0.0006935815083213839 | 0.0006361243312362981 | 8.28% | 9.03% | 1.09x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0006850753794353283 | 0.0006367492071270581 | 7.05% | 7.59% | 1.08x | ✅ |
| `contextframesbytesio_init[65536]` | 0.000699205027508607 | 0.0006370864319978864 | 8.88% | 9.75% | 1.10x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0010041098584909986 | 0.0009782781958056258 | 2.57% | 2.64% | 1.03x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012434656007968896 | 0.0001133224892804473 | 8.87% | 9.73% | 1.10x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.005086295010263105 | 0.00499839087436514 | 1.73% | 1.76% | 1.02x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.0004997252716727248 | 0.00048465306485717295 | 3.02% | 3.11% | 1.03x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0004393955258513811 | 0.00044154509149863154 | -0.49% | -0.49% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.511704776880297e-05 | 5.532792659241755e-05 | -0.38% | -0.38% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0020894824686196268 | 0.0021007459565215987 | -0.54% | -0.54% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[5]` | 0.0002012741819779599 | 0.00020066344903145626 | 0.30% | 0.30% | 1.00x | ✅ |
