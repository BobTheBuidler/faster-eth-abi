#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0007081623071909896 | 0.0006360255049898143 | 10.19% | 11.34% | 1.11x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006957285657284873 | 0.0006338026111505512 | 8.90% | 9.77% | 1.10x | ✅ |
| `contextframesbytesio_init[32]` | 0.0007062350722997771 | 0.0006361520085137359 | 9.92% | 11.02% | 1.11x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0007001176895550705 | 0.0006371224318200456 | 9.00% | 9.89% | 1.10x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006999133599968641 | 0.0006280254413433175 | 10.27% | 11.45% | 1.11x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009915707653566704 | 0.0009730305337943466 | 1.87% | 1.91% | 1.02x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012671220884691897 | 0.00011221523209872981 | 11.44% | 12.92% | 1.13x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.005079719908156695 | 0.005045778065664308 | 0.67% | 0.67% | 1.01x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.0004936274546374638 | 0.00047559103957498075 | 3.65% | 3.79% | 1.04x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.00044095195652202855 | 0.00043955889002789545 | 0.32% | 0.32% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[1]` | 5.6182078910916306e-05 | 5.606831184203032e-05 | 0.20% | 0.20% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0021042443700621228 | 0.0020905903676499147 | 0.65% | 0.65% | 1.01x | ✅ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00020343154960636008 | 0.00020315813067424575 | 0.13% | 0.13% | 1.00x | ✅ |
