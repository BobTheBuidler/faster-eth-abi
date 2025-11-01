# eth-abi-stubs

**eth-abi-stubs** provides comprehensive type stubs for [eth-abi](https://github.com/ethereum/eth-abi) and [faster-eth-abi](https://github.com/BobTheBuidler/faster-eth-abi), enabling precise static type checking with tools like mypy.

## What is this?

- A drop-in stubs package for eth-abi and faster-eth-abi.
- Adds type-safe overloads for ABI encoding/decoding, so you get exact type inference for ABI operations.
- Makes type checking with mypy much more powerful and accurate than with eth-abi alone.

## How to use

1. Install eth-abi-stubs alongside eth-abi or faster-eth-abi.
2. Type check your code with mypy or another type checker.
3. Enjoy precise type inference for ABI operations!

## Example

See [TYPE_CHECKING.md](../TYPE_CHECKING.md) for a full example of type-safe ABI overloads in action.

## Why use this?

- Get type safety and static analysis for ABI operations.
- Catch bugs and type mismatches at development time.
- Works with both eth-abi and faster-eth-abi.

## More information

- For details on how the stubs are generated and maintained, see [.llm.md](.llm.md).
