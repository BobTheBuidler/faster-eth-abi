#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0007001754868145139 | 0.000626789142672264 | 10.48% | 11.71% | 1.12x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006950629125178399 | 0.0006281398226735046 | 9.63% | 10.65% | 1.11x | ✅ |
| `contextframesbytesio_init[32]` | 0.0007056320142669489 | 0.0006303555636163915 | 10.67% | 11.94% | 1.12x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0006880452237846667 | 0.0006268687021707936 | 8.89% | 9.76% | 1.10x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006935225997163626 | 0.0006327113082959242 | 8.77% | 9.61% | 1.10x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.000983313613225604 | 0.0009624155087897268 | 2.13% | 2.17% | 1.02x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00012056503916735937 | 0.00011296640069555677 | 6.30% | 6.73% | 1.07x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.004991180447232456 | 0.005021160475001807 | -0.60% | -0.60% | 0.99x | ❌ |
| `contextframesbytesio_push_pop[5]` | 0.0004911825452301866 | 0.000474290315792168 | 3.44% | 3.56% | 1.04x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.00043973030883393634 | 0.00044180190254548114 | -0.47% | -0.47% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.561301435178739e-05 | 5.580044876822675e-05 | -0.34% | -0.34% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.002098278044305125 | 0.002101171578953271 | -0.14% | -0.14% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00020088138980158874 | 0.0002016350923478742 | -0.38% | -0.37% | 1.00x | ❌ |
