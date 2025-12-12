from _typeshed import Incomplete
from decimal import Context
from faster_eth_abi.utils.numeric import abi_decimal_context as abi_decimal_context
from types import TracebackType
from typing import Final

getcontext: Final[Incomplete]
setcontext: Final[Incomplete]

class _DecimalContextManager:
    """Context manager class to support decimal.localcontext().

    Sets a copy of the supplied context in __enter__() and restores
    the previous decimal context in __exit__()
    """

    saved_context: Context
    new_context: Final[Incomplete]
    def __init__(self, new_context: Context) -> None: ...
    def __enter__(self) -> Context: ...
    def __exit__(
        self, t: type[_TExc] | None, v: _TExc | None, tb: TracebackType | None
    ) -> None: ...

DECIMAL_CONTEXT: Final[Incomplete]
