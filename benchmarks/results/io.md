#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0007048480902173791 | 0.0006483801465095002 | 8.01% | 8.71% | 1.09x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0007037506064384656 | 0.0006401934785718108 | 9.03% | 9.93% | 1.10x | ✅ |
| `contextframesbytesio_init[32]` | 0.000698605681689732 | 0.0006400277294288035 | 8.38% | 9.15% | 1.09x | ✅ |
| `contextframesbytesio_init[4096]` | 0.000701003095854176 | 0.0006362002609254286 | 9.24% | 10.19% | 1.10x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006913541196954661 | 0.0006374903887086444 | 7.79% | 8.45% | 1.08x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0010032602922582835 | 0.000977710559403355 | 2.55% | 2.61% | 1.03x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012306069435373865 | 0.00011357704962593552 | 7.71% | 8.35% | 1.08x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.005136259209179143 | 0.005004678572862045 | 2.56% | 2.63% | 1.03x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.000494965853469371 | 0.000479545754489914 | 3.12% | 3.22% | 1.03x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.00043859909668899705 | 0.00044522034973327497 | -1.51% | -1.49% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.5193918215265003e-05 | 5.46022263204446e-05 | 1.07% | 1.08% | 1.01x | ✅ |
| `contextframesbytesio_seek_in_frame[50]` | 0.002087491887237639 | 0.002121231692474119 | -1.62% | -1.59% | 0.98x | ❌ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00019798800195712553 | 0.0001996078156272704 | -0.82% | -0.81% | 0.99x | ❌ |
