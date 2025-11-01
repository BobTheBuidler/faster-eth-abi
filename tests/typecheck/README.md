# Overload Typecheck Data

This folder contains **automatically generated files** that help guarantee the type safety of this library's ABI decoding functions.

- There are over **79 million test cases** generated to cover the vast number of possible combinations of ABI types and usage patterns. Only a small example subset is included in this repository; see below for how to generate the full suite.

> **Note:**  
> Only a small example subset of testdata files is included in this repository.  
> To run the full typecheck suite, you must generate the complete set of testdata files using the provided script.  
> See below for instructions.

## What does this mean for you?

- Every possible way you can use the ABI decoding API is checked for type correctness—covering even rare or complex cases.
- This means you get better autocomplete, more accurate type hints, and fewer surprises when using this library in your own code.
- If you use an editor or IDE with type checking (like VSCode, PyCharm, or mypy), you'll get accurate feedback and fewer bugs.
- You don't need to run or edit these files. They are not normal tests and are ignored by test runners like pytest.

## How to Run the Full Typecheck Suite

To generate the full set of testdata files and run the complete suite:
```bash
python scripts/generate_overload_tests.py --impl both
```
This will regenerate all testdata files in the `abi/` and `codec/` subdirectories.

## More info

- For technical details, see the generator script: [`scripts/generate_overload_tests.py`](../../scripts/generate_overload_tests.py)
- For CI details, see: [`.github/workflows/mypy.yaml`](../../.github/workflows/mypy.yaml)
- For testdata management policy, see: [`tests/typecheck/.llm.md`](./.llm.md)
