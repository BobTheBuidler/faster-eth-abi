# Overload Typecheck Data

This folder contains **automatically generated files** that help guarantee the type safety of this library's ABI decoding functions.

## What does this mean for you?

- These files are here to make sure that every possible way you can use the ABI decoding API is checked for type correctness.
- This means you get better autocomplete, more accurate type hints, and fewer surprises when using this library in your own code.
- You don't need to run or edit these files. They are not normal tests and are ignored by test runners like pytest.

## Why so many files?

- There are thousands of possible ways to use the ABI decoder, and we check every single one for type safety.
- To keep things fast and reliable, the checks are split into many files.

## How does this help you?

- You can trust that the library's type hints are correct, even for rare or complex cases.
- If you use an editor or IDE with type checking (like VSCode, PyCharm, or mypy), you'll get accurate feedback and fewer bugs.

## Advanced: Regenerating the files

If you are a developer working on the internals of this library, you can regenerate these files with:
```bash
python scripts/generate_typecheck_codec_overloads_yaml.py
```
This will update all the typecheck data files.

## More info

- For technical details, see the generator script: [`scripts/generate_typecheck_codec_overloads_yaml.py`](../../scripts/generate_typecheck_codec_overloads_yaml.py)
- For CI details, see: [`.github/workflows/mypy.yaml`](../../.github/workflows/mypy.yaml)
