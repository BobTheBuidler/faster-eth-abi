#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0006263450739517879 | 0.0005541841174783457 | 11.52% | 13.02% | 1.13x | ✅ |
| `contextframesbytesio_init[1024]` | 0.000628397336655599 | 0.0005536818238243564 | 11.89% | 13.49% | 1.13x | ✅ |
| `contextframesbytesio_init[32]` | 0.0006260654137769869 | 0.0005533464194303594 | 11.62% | 13.14% | 1.13x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0006268027682583527 | 0.0005534814860375082 | 11.70% | 13.25% | 1.13x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006266670286735083 | 0.0005563844665555553 | 11.22% | 12.63% | 1.13x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009189578234841145 | 0.0009504883696966292 | -3.43% | -3.32% | 0.97x | ❌ |
| `contextframesbytesio_push_pop[1]` | 0.00011311607159546772 | 0.00011017508698620393 | 2.60% | 2.67% | 1.03x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.00469696654028227 | 0.004927647890476042 | -4.91% | -4.68% | 0.95x | ❌ |
| `contextframesbytesio_push_pop[5]` | 0.0004582431375175598 | 0.0004790581510654549 | -4.54% | -4.34% | 0.96x | ❌ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0003950778108016491 | 0.00039356403619842046 | 0.38% | 0.38% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[1]` | 5.1214685368473625e-05 | 5.1173574156270636e-05 | 0.08% | 0.08% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0018886163048556378 | 0.0018915085841371413 | -0.15% | -0.15% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00018800442215987517 | 0.00018773134758993685 | 0.15% | 0.15% | 1.00x | ✅ |
