#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.000691686315825103 | 0.0006184454840567123 | 10.59% | 11.84% | 1.12x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0007008027166548391 | 0.0006262719194795592 | 10.64% | 11.90% | 1.12x | ✅ |
| `contextframesbytesio_init[32]` | 0.0006936198179341616 | 0.0006162543779980358 | 11.15% | 12.55% | 1.13x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0006996542496350133 | 0.0006201815526161834 | 11.36% | 12.81% | 1.13x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006736411612691481 | 0.0006229711821762884 | 7.52% | 8.13% | 1.08x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0010019402413433793 | 0.00097957073904333 | 2.23% | 2.28% | 1.02x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012425142225432122 | 0.00011563010681730836 | 6.94% | 7.46% | 1.07x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.005138664969073015 | 0.005086691119171463 | 1.01% | 1.02% | 1.01x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.000498240263678483 | 0.0004820060626881308 | 3.26% | 3.37% | 1.03x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0004437891655858479 | 0.0004399244858174576 | 0.87% | 0.88% | 1.01x | ✅ |
| `contextframesbytesio_seek_in_frame[1]` | 5.502438067896595e-05 | 5.503554839215103e-05 | -0.02% | -0.02% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.002128492796136749 | 0.0021183363170195584 | 0.48% | 0.48% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00020355409769118004 | 0.0002007393404259542 | 1.38% | 1.40% | 1.01x | ✅ |
