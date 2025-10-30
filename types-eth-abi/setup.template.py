from setuptools import (
    setup,
)

setup(
    name="types-eth-utils",
    version="{{VERSION}}",
    description="Type stubs for eth-abi and faster-eth-abi",
    author="BobTheBuidler",
    author_email="bobthebuidlerdefi@gmail.com",
    url="{{URL}}",
    license="{{LICENSE}}",
    keywords="{{KEYWORDS}}",
    packages=["faster_eth_abi", "eth_abi"],
    package_data={
        "faster_eth_abi": ["*.pyi", "py.typed"],
        "eth_abi": ["*.pyi", "py.typed"],
    },
    install_requires=[],
    python_requires="{{PYTHON_REQUIRES}}",
    zip_safe=False,
    include_package_data=True,
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Typing :: Stubs Only",
        "Programming Language :: Python :: 3",
    ],
)
