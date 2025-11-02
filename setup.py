#!/usr/bin/env python
import sys
from typing import (
    List,
)

from mypyc.build import (
    mypycify,
)
from setuptools import (
    find_packages,
    setup,
)

install_requires = []


def parse_requirements(filename: str) -> List[str]:
    lines = []
    with open(filename) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-r"):
                lines.extend(
                    line
                    for line in parse_requirements(line[2:].strip())
                    if line not in install_requires
                )
            else:
                lines.append(line.strip())
    return lines


install_requires.extend(parse_requirements("requirements.txt"))

extras_require = {
    "dev": parse_requirements("requirements-dev.txt"),
    "docs": [
        "sphinx>=6.0.0",
        "sphinx-autobuild>=2021.3.14",
        "sphinx_rtd_theme>=1.0.0",
        "towncrier>=24,<26",
    ],
    "test": parse_requirements("requirements-test.txt"),
    "tools": parse_requirements("requirements-tools.txt"),
    "codspeed": parse_requirements("requirements-codspeed.txt"),
    "benchmark": parse_requirements("requirements-codspeed.txt"),
    "mypy": parse_requirements("requirements-mypy.txt"),
}

extras_require["dev"] = (
    extras_require["dev"] + extras_require["docs"] + extras_require["test"]
)


with open("./README.md") as readme:
    long_description = readme.read()


skip_mypyc = any(
    cmd in sys.argv
    for cmd in ("sdist", "egg_info", "--name", "--version", "--help", "--help-commands")
)

if skip_mypyc:
    ext_modules = []
else:
    mypycify_kwargs = {"strict_dunder_typing": True}
    if sys.version_info >= (3, 9):
        mypycify_kwargs["group_name"] = "faster_eth_abi"

    flags = [
        "--pretty",
        "--install-types",
        # all of these are safe to disable long term
        "--disable-error-code=override",
        "--disable-error-code=no-any-return",
    ]

    if sys.version_info[:1] != (3, 8):
        # We only enable these on the lowest supported Python version
        flags.append("--disable-error-code=redundant-cast")
        flags.append("--disable-error-code=unused-ignore")
        
    ext_modules = mypycify(
        [
            "faster_eth_abi/_codec.py",
            "faster_eth_abi/_decoding.py",
            "faster_eth_abi/_encoding.py",
            "faster_eth_abi/_grammar.py",
            "faster_eth_abi/abi.py",
            "faster_eth_abi/constants.py",
            # "faster_eth_abi/exceptions.py",  segfaults on mypyc 1.18.2
            "faster_eth_abi/from_type_str.py",
            # "faster_eth_abi/io.py",
            "faster_eth_abi/packed.py",
            "faster_eth_abi/tools",
            "faster_eth_abi/utils",
            *flags,
        ],
        **mypycify_kwargs,
    )


setup(
    name="faster_eth_abi",
    # *IMPORTANT*: Don't manually change the version here. See Contributing docs for the release process.
    version="5.2.16",
    description="""A ~2-6x faster fork of eth_abi: Python utilities for working with Ethereum ABI definitions, especially encoding and decoding. Implemented in C.""",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="The Ethereum Foundation",
    author_email="snakecharmers@ethereum.org",
    url="https://github.com/BobTheBuidler/faster-eth-abi",
    project_urls={
        "Documentation": "https://eth-abi.readthedocs.io/en/stable/",
        "Release Notes": "https://github.com/BobTheBuidler/faster-eth-abi/releases",
        "Issues": "https://github.com/BobTheBuidler/faster-eth-abi/issues",
        "Source - Precompiled (.py)": "https://github.com/BobTheBuidler/faster-eth-utils/tree/master/faster_eth_utils",
        "Source - Compiled (.c)": "https://github.com/BobTheBuidler/faster-eth-utils/tree/master/build",
        "Benchmarks": "https://github.com/BobTheBuidler/faster-eth-utils/tree/master/benchmarks",
        "Benchmarks - Results": "https://github.com/BobTheBuidler/faster-eth-utils/tree/master/benchmarks/results",
        "Original": "https://github.com/ethereum/eth-abi",
    },
    include_package_data=True,
    install_requires=install_requires,
    python_requires=">=3.8, <4",
    extras_require=extras_require,
    license="MIT",
    zip_safe=False,
    keywords="ethereum",
    packages=find_packages(
        exclude=[
            "benchmarks",
            "benchmarks.*",
            "scripts",
            "scripts.*",
            "tests",
            "tests.*",
            "eth-abi-stubs",
            "eth-abi-stubs.*",
        ]
    ),
    ext_modules=ext_modules,
    package_data={"faster_eth_abi": ["py.typed"]},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Programming Language :: Python :: Implementation :: CPython",
    ],
)
