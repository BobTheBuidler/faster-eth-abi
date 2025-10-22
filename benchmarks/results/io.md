#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0007131801324396457 | 0.0006345177955627668 | 11.03% | 12.40% | 1.12x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0007091019818053318 | 0.0006389116935048895 | 9.90% | 10.99% | 1.11x | ✅ |
| `contextframesbytesio_init[32]` | 0.0007058830417009386 | 0.0006358953047313802 | 9.91% | 11.01% | 1.11x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0007003865794572691 | 0.0006327199086370249 | 9.66% | 10.69% | 1.11x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006998035621870801 | 0.0006322344298795627 | 9.66% | 10.69% | 1.11x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.001010017071793976 | 0.0009950601820013813 | 1.48% | 1.50% | 1.02x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.000123516417126475 | 0.00011383469203449332 | 7.84% | 8.51% | 1.09x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.005095940189741481 | 0.005040406477162713 | 1.09% | 1.10% | 1.01x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.000499490709337607 | 0.00048446164571035747 | 3.01% | 3.10% | 1.03x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.00044458075525161713 | 0.00044449603733558634 | 0.02% | 0.02% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[1]` | 5.4984459241959444e-05 | 5.6084527001019355e-05 | -2.00% | -1.96% | 0.98x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0021394726944435143 | 0.0021189429787213197 | 0.96% | 0.97% | 1.01x | ✅ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00020272802544700068 | 0.00020683310584089805 | -2.02% | -1.98% | 0.98x | ❌ |
