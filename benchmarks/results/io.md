#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0006973783432395305 | 0.000627558849154209 | 10.01% | 11.13% | 1.11x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006944078062279822 | 0.0006292289711693293 | 9.39% | 10.36% | 1.10x | ✅ |
| `contextframesbytesio_init[32]` | 0.0006912359497534394 | 0.0006337318166974515 | 8.32% | 9.07% | 1.09x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0006974924817747496 | 0.0006258799592510389 | 10.27% | 11.44% | 1.11x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006995401358208569 | 0.0006323251631213959 | 9.61% | 10.63% | 1.11x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009892310569370422 | 0.0009716925506551944 | 1.77% | 1.80% | 1.02x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.0001235250825244559 | 0.00011463297897403912 | 7.20% | 7.76% | 1.08x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.005030803948712231 | 0.0050148681363675635 | 0.32% | 0.32% | 1.00x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.0004946314710804972 | 0.00047765405252610894 | 3.43% | 3.55% | 1.04x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0004375789405694291 | 0.000438087739227746 | -0.12% | -0.12% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.494999417965516e-05 | 5.527194758150646e-05 | -0.59% | -0.58% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0020839359558894707 | 0.002106831844299637 | -1.10% | -1.09% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00020007809839200666 | 0.00019849961599834864 | 0.79% | 0.80% | 1.01x | ✅ |
