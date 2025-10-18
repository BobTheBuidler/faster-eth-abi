#### [faster_eth_abi.io](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/faster_eth_abi/io.py) - [view benchmarks](https://github.com/BobTheBuidler/faster-eth-abi/blob/master/benchmarks/test_io_benchmarks.py)

| Function | Reference Mean | Faster Mean | % Change | Speedup (%) | x Faster | Faster |
|----------|---------------|-------------|----------|-------------|----------|--------|
| `contextframesbytesio_init[0]` | 0.0006241428716600361 | 0.0005497852272405953 | 11.91% | 13.52% | 1.14x | ✅ |
| `contextframesbytesio_init[1024]` | 0.0006226424438574493 | 0.0005496158384605703 | 11.73% | 13.29% | 1.13x | ✅ |
| `contextframesbytesio_init[32]` | 0.000621556625165682 | 0.0005500550132117941 | 11.50% | 13.00% | 1.13x | ✅ |
| `contextframesbytesio_init[4096]` | 0.000624234032511806 | 0.0005507202728888131 | 11.78% | 13.35% | 1.13x | ✅ |
| `contextframesbytesio_init[65536]` | 0.0006211198438680906 | 0.0005495244658427953 | 11.53% | 13.03% | 1.13x | ✅ |
| `contextframesbytesio_push_pop[10]` | 0.0009115035469230387 | 0.0009044521850665715 | 0.77% | 0.78% | 1.01x | ✅ |
| `contextframesbytesio_push_pop[1]` | 0.00011430101773287653 | 0.0001052566290165511 | 7.91% | 8.59% | 1.09x | ✅ |
| `contextframesbytesio_push_pop[50]` | 0.0046567827264092955 | 0.0046665069624389575 | -0.21% | -0.21% | 1.00x | ❌ |
| `contextframesbytesio_push_pop[5]` | 0.0004535129820296784 | 0.00044323155472487827 | 2.27% | 2.32% | 1.02x | ✅ |
| `contextframesbytesio_seek_in_frame[10]` | 0.0003887476243204804 | 0.0003913573022477132 | -0.67% | -0.67% | 0.99x | ❌ |
| `contextframesbytesio_seek_in_frame[1]` | 5.104595396884731e-05 | 5.127766803879996e-05 | -0.45% | -0.45% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[50]` | 0.0018612967984684922 | 0.001867615976790734 | -0.34% | -0.34% | 1.00x | ❌ |
| `contextframesbytesio_seek_in_frame[5]` | 0.00018786226181654453 | 0.0001875217068911964 | 0.18% | 0.18% | 1.00x | ✅ |
