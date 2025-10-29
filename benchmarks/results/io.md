#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.000699018591234335 | 0.0006172022710213393 | 11.70% | 13.26% | 1.13x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006850166414164375 | 0.0006177469361157437 | 9.82% | 10.89% | 1.11x | ✅ |
| `contextframesbytesio_init[32]` | 0.0006871981358368283 | 0.0006149134126308389 | 10.52% | 11.76% | 1.12x | ✅ |
| `contextframesbytesio_init[4096]` | 0.0006906980313382755 | 0.0006123799495984471 | 11.34% | 12.79% | 1.13x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006858869601617468 | 0.000612468199505131 | 10.70% | 11.99% | 1.12x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.000960950291746646 | 0.0009388053374626373 | 2.30% | 2.36% | 1.02x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.0001251156354853256 | 0.00011028716384545823 | 11.85% | 13.45% | 1.13x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.004874158436283484 | 0.0048359028647370645 | 0.78% | 0.79% | 1.01x | ✅ |
| `contextframesbytesio_push_pop[5]` | 0.00048313742026088823 | 0.00045909549792239767 | 4.98% | 5.24% | 1.05x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0004014155438788961 | 0.00039880896058067225 | 0.65% | 0.65% | 1.01x | ✅ |
| `contextframesbytesio_seek_in_frame[1]` | 5.488876696345479e-05 | 5.477005952591524e-05 | 0.22% | 0.22% | 1.00x | ✅ |
| `contextframesbytesio_seek_in_frame[50]` | 0.001908469758553131 | 0.0019213800134541368 | -0.68% | -0.67% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[5]` | 0.0001962189371933141 | 0.0001969495060351743 | -0.37% | -0.37% | 1.00x | ❌ |
