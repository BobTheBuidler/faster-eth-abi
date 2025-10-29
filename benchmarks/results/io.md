#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0007083759259242845 | 0.0006260882898680741 | 11.62% | 13.14% | 1.13x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0007046882030335982 | 0.0006261672931612735 | 11.14% | 12.54% | 1.13x | ✅ |
| `contextframesbytesio_init[32]` | 0.0007043884425642974 | 0.0006230405564567146 | 11.55% | 13.06% | 1.13x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0007051471028564394 | 0.0006222068123345771 | 11.76% | 13.33% | 1.13x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0007065494418101422 | 0.0006243126950078039 | 11.64% | 13.17% | 1.13x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009618259378114426 | 0.0009500835954530355 | 1.22% | 1.24% | 1.01x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.0001246414566016257 | 0.00011113445379584325 | 10.84% | 12.15% | 1.12x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.004925885253731765 | 0.0049235868888826365 | 0.05% | 0.05% | 1.00x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.0004832462843373277 | 0.0004687771280777238 | 2.99% | 3.09% | 1.03x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0003996857602329349 | 0.0004018134967446566 | -0.53% | -0.53% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.487576364041081e-05 | 5.5261176564447773e-05 | -0.70% | -0.70% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.00190561884007562 | 0.001919178870910204 | -0.71% | -0.71% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[5]` | 0.0001961221415276524 | 0.00019716191150604887 | -0.53% | -0.53% | 0.99x | ❌ |
