#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0007030813928816941 | 0.0006240049403087854 | 11.25% | 12.67% | 1.13x | ✅ |
| `contextframesbytesio_init[1024]` | 0.000700621687804316 | 0.000625947235142665 | 10.66% | 11.93% | 1.12x | ✅ |
| `contextframesbytesio_init[32]` | 0.0006988637641558029 | 0.0006302429322163455 | 9.82% | 10.89% | 1.11x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0007042205722598698 | 0.0006226036195205567 | 11.59% | 13.11% | 1.13x | ✅ |
| `contextframesbytesio_init[65536]` | 0.000698665658503077 | 0.0006248850526326094 | 10.56% | 11.81% | 1.12x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009629638794467969 | 0.000932942175042866 | 3.12% | 3.22% | 1.03x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012550536971978312 | 0.00011045232119136894 | 11.99% | 13.63% | 1.14x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.00489970217588861 | 0.004823226419505484 | 1.56% | 1.59% | 1.02x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.00047809365646324197 | 0.0004598901006971075 | 3.81% | 3.96% | 1.04x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.00039418862638623283 | 0.0003944979650351409 | -0.08% | -0.08% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.426292390515594e-05 | 5.361635411014748e-05 | 1.19% | 1.21% | 1.01x | ✅ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0018953787200066473 | 0.0018897332881654635 | 0.30% | 0.30% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00019134289020185374 | 0.000195280435124844 | -2.06% | -2.02% | 0.98x | ❌ |
