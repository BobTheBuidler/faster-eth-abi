#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0007084879043253438 | 0.0006355753343665331 | 10.29% | 11.47% | 1.11x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006931422325227856 | 0.0006261298833358535 | 9.67% | 10.70% | 1.11x | ✅ |
| `contextframesbytesio_init[32]` | 0.0006916355674890224 | 0.000624794120601389 | 9.66% | 10.70% | 1.11x | ✅ |
| `contextframesbytesio_init[4096]` | 0.000691727770481103 | 0.0006207338420058463 | 10.26% | 11.44% | 1.11x | ✅ |
| `contextframesbytesio_init[65536]` | 0.000693827724637866 | 0.0006219889081484223 | 10.35% | 11.55% | 1.12x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009602193094305577 | 0.0009531115259023143 | 0.74% | 0.75% | 1.01x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.0001254477598689261 | 0.00011205076755797767 | 10.68% | 11.96% | 1.12x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.004908257633168382 | 0.004836256985065609 | 1.47% | 1.49% | 1.01x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.0004999937525850407 | 0.0004629171951555322 | 7.42% | 8.01% | 1.08x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0003937562601228107 | 0.0003947423655109642 | -0.25% | -0.25% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.373198521041825e-05 | 5.480051085924012e-05 | -1.99% | -1.95% | 0.98x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0018915712190430765 | 0.001889780235184199 | 0.09% | 0.09% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00019250558995830808 | 0.00019240902653988403 | 0.05% | 0.05% | 1.00x | ✅ |
