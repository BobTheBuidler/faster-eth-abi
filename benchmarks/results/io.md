#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0006909574992996023 | 0.0006220452717864747 | 9.97% | 11.08% | 1.11x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006872212140807201 | 0.0006275118501970018 | 8.69% | 9.52% | 1.10x | ✅ |
| `contextframesbytesio_init[32]` | 0.0006919232236580889 | 0.0006249054066385535 | 9.69% | 10.72% | 1.11x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0006834078447904018 | 0.0006250660275319822 | 8.54% | 9.33% | 1.09x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006880567767530268 | 0.0006274879604524976 | 8.80% | 9.65% | 1.10x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009877327316168828 | 0.0009634625004961662 | 2.46% | 2.52% | 1.03x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.0001212933868823534 | 0.00011267614435925456 | 7.10% | 7.65% | 1.08x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.00506261318973301 | 0.004965304787109483 | 1.92% | 1.96% | 1.02x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.0004873354941589207 | 0.0004692226583846949 | 3.72% | 3.86% | 1.04x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.00043429468875907874 | 0.00043257162397869416 | 0.40% | 0.40% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[1]` | 5.588699036012418e-05 | 5.377121687588254e-05 | 3.79% | 3.93% | 1.04x | ✅ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0020768996267863785 | 0.002079977728435073 | -0.15% | -0.15% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00019942345030376954 | 0.00019653522274782405 | 1.45% | 1.47% | 1.01x | ✅ |
