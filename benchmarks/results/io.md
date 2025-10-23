#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.000630093471637838 | 0.0006197030041010385 | 1.65% | 1.68% | 1.02x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006331872577851456 | 0.0006019680672833507 | 4.93% | 5.19% | 1.05x | ✅ |
| `contextframesbytesio_init[32]` | 0.0006400025746673539 | 0.0006088089040707304 | 4.87% | 5.12% | 1.05x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0006300983448103249 | 0.0006072717512581899 | 3.62% | 3.76% | 1.04x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006347215936065847 | 0.0005996194351850035 | 5.53% | 5.85% | 1.06x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009162377565049359 | 0.0009267782332996134 | -1.15% | -1.14% | 0.99x | ❌ |
| `contextframesbytesio_push_pop[1]` | 0.0001168943247153154 | 0.00011156928418558816 | 4.56% | 4.77% | 1.05x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.004679757034648333 | 0.004773104870817963 | -1.99% | -1.96% | 0.98x | ❌ |
| `contextframesbytesio_push_pop[5]` | 0.0004626209177423686 | 0.00046788433940507496 | -1.14% | -1.12% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[10]` | 0.00039987463047077394 | 0.00039485877362653934 | 1.25% | 1.27% | 1.01x | ✅ |
| `contextframesbytesio_seek_in_frame[1]` | 5.347042399078656e-05 | 5.336283773324003e-05 | 0.20% | 0.20% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[50]` | 0.001893092001942723 | 0.0018850207451364068 | 0.43% | 0.43% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[5]` | 0.0001908090466089924 | 0.0001926550873028751 | -0.97% | -0.96% | 0.99x | ❌ |
