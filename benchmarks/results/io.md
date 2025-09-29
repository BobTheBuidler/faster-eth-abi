#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0007036361087102705 | 0.0006300549403670309 | 10.46% | 11.68% | 1.12x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0007193667060890365 | 0.0006410755936684839 | 10.88% | 12.21% | 1.12x | ✅ |
| `contextframesbytesio_init[32]` | 0.0007037180914916861 | 0.0006364308677568871 | 9.56% | 10.57% | 1.11x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0007043522235059761 | 0.0006372040577187839 | 9.53% | 10.54% | 1.11x | ✅ |
| `contextframesbytesio_init[65536]` | 0.00070845475157828 | 0.0006243275447435565 | 11.87% | 13.47% | 1.13x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0010012378949573687 | 0.0009841519283545642 | 1.71% | 1.74% | 1.02x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.0001212668197034077 | 0.000112348169304775 | 7.35% | 7.94% | 1.08x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.005001958994932978 | 0.004960185116745374 | 0.84% | 0.84% | 1.01x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.0004963781653738927 | 0.0004736077300374083 | 4.59% | 4.81% | 1.05x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.00045214050151267955 | 0.0004449454798708764 | 1.59% | 1.62% | 1.02x | ✅ |
| `contextframesbytesio_seek_in_frame[1]` | 5.475953544732382e-05 | 5.6317801567446095e-05 | -2.85% | -2.77% | 0.97x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0021153726729948607 | 0.0021142613283641337 | 0.05% | 0.05% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00020090139403762322 | 0.00020368294155947465 | -1.38% | -1.37% | 0.99x | ❌ |
