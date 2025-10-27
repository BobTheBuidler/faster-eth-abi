#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0007000502168947271 | 0.0006396977318340525 | 8.62% | 9.43% | 1.09x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0007121668233600546 | 0.0006347585094350902 | 10.87% | 12.19% | 1.12x | ✅ |
| `contextframesbytesio_init[32]` | 0.0007058525998576515 | 0.0006407664385263075 | 9.22% | 10.16% | 1.10x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0007089921336222329 | 0.0006384303335461897 | 9.95% | 11.05% | 1.11x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0007121014978422892 | 0.0006353494075964118 | 10.78% | 12.08% | 1.12x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009956885971520156 | 0.0009700721331990707 | 2.57% | 2.64% | 1.03x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.0001246503493266387 | 0.00011179515596731247 | 10.31% | 11.50% | 1.11x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.005053243918788849 | 0.004964792733666921 | 1.75% | 1.78% | 1.02x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.0004916134138474239 | 0.0004760168378775326 | 3.17% | 3.28% | 1.03x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0004361865521936974 | 0.00043517008805689443 | 0.23% | 0.23% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[1]` | 5.643353061817745e-05 | 5.54534249188192e-05 | 1.74% | 1.77% | 1.02x | ✅ |
| `contextframesbytesio_seek_in_frame[50]` | 0.00208369697903594 | 0.0020741899521801803 | 0.46% | 0.46% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[5]` | 0.0002001163637837004 | 0.000202103709331618 | -0.99% | -0.98% | 0.99x | ❌ |
