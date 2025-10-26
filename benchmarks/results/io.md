#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0006267292777766052 | 0.0005533230568341546 | 11.71% | 13.27% | 1.13x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006391031470555248 | 0.0005535299845635956 | 13.39% | 15.46% | 1.15x | ✅ |
| `contextframesbytesio_init[32]` | 0.0006271022130720643 | 0.0005534102654479394 | 11.75% | 13.32% | 1.13x | ✅ |
| `contextframesbytesio_init[4096]` | 0.000628294305218648 | 0.0005540154607265221 | 11.82% | 13.41% | 1.13x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006270182368249556 | 0.0005545250585555289 | 11.56% | 13.07% | 1.13x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009091792662144365 | 0.0009421849785523687 | -3.63% | -3.50% | 0.96x | ❌ |
| `contextframesbytesio_push_pop[1]` | 0.00011629511781720885 | 0.00011092729248194848 | 4.62% | 4.84% | 1.05x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.004693744089206415 | 0.004666132042863562 | 0.59% | 0.59% | 1.01x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.0004574064997468355 | 0.0004541764635775305 | 0.71% | 0.71% | 1.01x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.00039298881294245227 | 0.00039264199717484465 | 0.09% | 0.09% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[1]` | 5.11293824421839e-05 | 5.141135564322441e-05 | -0.55% | -0.55% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0018838158790727526 | 0.0018836933186212297 | 0.01% | 0.01% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00019098234686017217 | 0.0001873394250388761 | 1.91% | 1.94% | 1.02x | ✅ |
