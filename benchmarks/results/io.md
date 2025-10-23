#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0006911970248127384 | 0.0006295966350716798 | 8.91% | 9.78% | 1.10x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006875266847593907 | 0.0006344826073278728 | 7.72% | 8.36% | 1.08x | ✅ |
| `contextframesbytesio_init[32]` | 0.0006872054770510456 | 0.0006259619153134596 | 8.91% | 9.78% | 1.10x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0007007969168399096 | 0.0006299595353231505 | 10.11% | 11.24% | 1.11x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006952888743838607 | 0.0006283627250152532 | 9.63% | 10.65% | 1.11x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0010010450553841694 | 0.0009747232462916386 | 2.63% | 2.70% | 1.03x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012501095536645825 | 0.00011450748700410487 | 8.40% | 9.17% | 1.09x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.005121434795912638 | 0.004990087432434922 | 2.56% | 2.63% | 1.03x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.0005006543428145576 | 0.0004844306957899509 | 3.24% | 3.35% | 1.03x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0004372461839815914 | 0.00043890911751316437 | -0.38% | -0.38% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.602828041643514e-05 | 5.486758671251856e-05 | 2.07% | 2.12% | 1.02x | ✅ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0021114251468076117 | 0.0021087862441604684 | 0.12% | 0.13% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00020163932096561822 | 0.00020075944691755443 | 0.44% | 0.44% | 1.00x | ✅ |
