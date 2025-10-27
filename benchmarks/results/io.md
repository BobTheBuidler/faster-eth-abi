#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.000686697496880757 | 0.0006169581603233323 | 10.16% | 11.30% | 1.11x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006926419869222665 | 0.0006277897420534623 | 9.36% | 10.33% | 1.10x | ✅ |
| `contextframesbytesio_init[32]` | 0.0006967170665695201 | 0.000616140825342978 | 11.57% | 13.08% | 1.13x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0006909015576176377 | 0.0006370031542017852 | 7.80% | 8.46% | 1.08x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006929860703108142 | 0.0006212609251407881 | 10.35% | 11.55% | 1.12x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.000990064204429569 | 0.00096416057879257 | 2.62% | 2.69% | 1.03x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012224437123524754 | 0.00011383986037323039 | 6.88% | 7.38% | 1.07x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.005076891814428798 | 0.0049934581356773835 | 1.64% | 1.67% | 1.02x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.0004894384908130651 | 0.00047136526702317284 | 3.69% | 3.83% | 1.04x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0004266717882411461 | 0.00043179277555341046 | -1.20% | -1.19% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.457265913809006e-05 | 5.475040918681779e-05 | -0.33% | -0.32% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.00207392087974071 | 0.002058780830895751 | 0.73% | 0.74% | 1.01x | ✅ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00020105126981438538 | 0.00019809751582240657 | 1.47% | 1.49% | 1.01x | ✅ |
