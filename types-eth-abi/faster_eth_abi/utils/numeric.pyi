import decimal
from _typeshed import Incomplete
from typing import Callable, Final

ABI_DECIMAL_PREC: Final[int]
abi_decimal_context: Final[Incomplete]
decimal_localcontext: Final[Incomplete]
ZERO: Final[Incomplete]
TEN: Final[Incomplete]
Decimal: Final[Incomplete]

def ceil32(x: int) -> int: ...

_unsigned_integer_bounds_cache: Final[dict[int, tuple[int, int]]]

def compute_unsigned_integer_bounds(num_bits: int) -> tuple[int, int]: ...

_signed_integer_bounds_cache: Final[dict[int, tuple[int, int]]]

def compute_signed_integer_bounds(num_bits: int) -> tuple[int, int]: ...

_unsigned_fixed_bounds_cache: Final[dict[tuple[int, int], decimal.Decimal]]

def compute_unsigned_fixed_bounds(num_bits: int, frac_places: int) -> tuple[decimal.Decimal, decimal.Decimal]: ...

_signed_fixed_bounds_cache: Final[dict[tuple[int, int], tuple[decimal.Decimal, decimal.Decimal]]]

def compute_signed_fixed_bounds(num_bits: int, frac_places: int) -> tuple[decimal.Decimal, decimal.Decimal]: ...
def scale_places(places: int) -> Callable[[decimal.Decimal], decimal.Decimal]: ...
