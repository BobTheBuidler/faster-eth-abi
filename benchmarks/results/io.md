#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0006937803373648259 | 0.0006168786701733937 | 11.08% | 12.47% | 1.12x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0007001110468410483 | 0.0006218382616441627 | 11.18% | 12.59% | 1.13x | ✅ |
| `contextframesbytesio_init[32]` | 0.0007005887397906695 | 0.000617967292913877 | 11.79% | 13.37% | 1.13x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0007046311396669911 | 0.0006148515396469126 | 12.74% | 14.60% | 1.15x | ✅ |
| `contextframesbytesio_init[65536]` | 0.000703074235558059 | 0.0006159407651560344 | 12.39% | 14.15% | 1.14x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009750794341202567 | 0.0009401097651016723 | 3.59% | 3.72% | 1.04x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012530553014916917 | 0.0001110055896041207 | 11.41% | 12.88% | 1.13x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.004860941267328472 | 0.00485335034147128 | 0.16% | 0.16% | 1.00x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.000482814126652265 | 0.0004634128860988051 | 4.02% | 4.19% | 1.04x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.00039882777365144687 | 0.00040009417739100405 | -0.32% | -0.32% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.471632399189961e-05 | 5.502779664138502e-05 | -0.57% | -0.57% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0019024835480737378 | 0.0019156567223331188 | -0.69% | -0.69% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00019491835598686177 | 0.00019613816610712632 | -0.63% | -0.62% | 0.99x | ❌ |
