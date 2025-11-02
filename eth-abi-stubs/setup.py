from setuptools import (
    setup,
)

setup(
    name="types-eth-utils",
    version="5.2.0.20251102",
    description="Type stubs for eth-abi and faster-eth-abi",
    author="BobTheBuidler",
    author_email="bobthebuidlerdefi@gmail.com",
    url="https://github.com/BobTheBuidler/faster-eth-abi",
    license="MIT",
    keywords="ethereum",
    packages=["faster_eth_abi", "eth_abi"],
    package_data={
        "faster_eth_abi": ["*.pyi", "py.typed"],
        "eth_abi": ["*.pyi", "py.typed"],
    },
    install_requires=[],
    python_requires=">=3.8,",
    zip_safe=False,
    include_package_data=True,
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Typing :: Stubs Only",
        "Programming Language :: Python :: 3",
    ],
)
