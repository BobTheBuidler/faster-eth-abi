# Type-Safe ABI Overloads in faster-eth-abi

**faster-eth-abi provides type-safe ABI overloads and comprehensive type annotations that are not available in eth-abi. This means you get precise, static type checking for ABI encoding and decoding—making faster-eth-abi a major improvement over eth-abi for any codebase that cares about type safety.**

~~Users of the original eth-abi can get access to this enhanced typing information by installing the `eth-abi-stubs` package provided in this repository.~~  
<sup>(Coming soon: easy install for eth-abi users!)</sup>

## Example: Type-Safe ABI Decoding

With overloads, you get exact type inference for ABI decode operations:

```python
from faster_eth_abi import abi
from typing_extensions import assert_type

# Example: decode a single uint256 value
data = bytes.fromhex("000000000000000000000000000000000000000000000000000000000000002a")
result = abi.decode(("uint256",), data)
assert_type(result, tuple[int])  # mypy will check this is correct

# Example: decode multiple values
data = bytes.fromhex(
    "000000000000000000000000000000000000000000000000000000000000002a"
    "0000000000000000000000000000000000000000000000000000000000000042"
)
result = abi.decode(("uint256", "uint256"), data)
assert_type(result, tuple[int, int])  # mypy will check this is correct
```

Type checkers like mypy will verify that the result type matches the ABI type string, thanks to overloads in faster-eth-abi.

## How it works

- Overloads are defined for `abi.decode` and related functions, mapping ABI type strings to precise Python types.
- The stubs package (`eth-abi-stubs`) provides the type information for both runtime and type checking.
- See the testdata and [tests/typecheck/abi/README.md](tests/typecheck/abi/README.md) for more on how overloads are tested.

## More Information

- For details on generating and running the overload test suite, see [tests/typecheck/abi/README.md](tests/typecheck/abi/README.md).
- For maintainers, see [tests/typecheck/abi/.llm.md](tests/typecheck/abi/.llm.md).
