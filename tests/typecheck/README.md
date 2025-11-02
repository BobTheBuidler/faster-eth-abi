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

To generate the full set of testdata files and run the complete suite, use the script with the new CLI flags:

```bash
# Generate all testdata for both ABI and codec, all lengths
python scripts/generate_overload_tests.py --impl both

# Generate only a specific length (e.g., length 3) for both ABI and codec
python scripts/generate_overload_tests.py --impl both --lengths 3

# Generate only a random 1/10th of the test files for length 3 (useful for quick checks)
python scripts/generate_overload_tests.py --impl both --lengths 3 --sample-1-of-x 10

# Generate only a random 1/200th of the test files for length 4, with a fixed seed for reproducibility
python scripts/generate_overload_tests.py --impl both --lengths 4 --sample-1-of-x 200 --seed 42
```

- The `--lengths` flag accepts a comma-separated list (e.g., `--lengths 1,2,3`).
- The `--sample-1-of-x` flag controls chunk-level sampling (e.g., 10 means only 1/10th of files are generated).
- The `--seed` flag ensures the same files are selected each run (default: 42).

This will regenerate all testdata files in the `abi/` and `codec/` subdirectories.

## CI Integration

- The GitHub Actions workflow ([`.github/workflows/mypy.yaml`](../../.github/workflows/mypy.yaml)) uses these flags to efficiently generate and check a representative subset of testdata for large lengths.
- See the workflow file for details on how sampling and length selection are used in CI.

## More info

- For technical details, see the generator script: [`scripts/generate_overload_tests.py`](../../scripts/generate_overload_tests.py)
- For CI details, see: [`.github/workflows/mypy.yaml`](../../.github/workflows/mypy.yaml)
- For testdata management policy, see: [`tests/typecheck/.llm.md`](./.llm.md)
