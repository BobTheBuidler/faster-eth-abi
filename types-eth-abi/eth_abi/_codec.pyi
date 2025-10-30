from eth_typing import Decodable as Decodable, TypeStr as TypeStr
from faster_eth_abi.codec import ABIDecoder as ABIDecoder, ABIEncoder as ABIEncoder
from faster_eth_abi.utils.validation import validate_bytes_param as validate_bytes_param, validate_list_like_param as validate_list_like_param
from typing import Any, Iterable

def encode_c(self, types: Iterable[TypeStr], args: Iterable[Any]) -> bytes: ...
def decode_c(self, types: Iterable[TypeStr], data: Decodable, strict: bool = True) -> tuple[Any, ...]: ...
