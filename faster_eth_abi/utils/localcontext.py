import decimal
from decimal import (
    Context,
)
from types import (
    TracebackType,
)
from typing import (
    Final,
    Optional,
    Type,
    TypeVar,
    final,
)

from faster_eth_abi.utils.numeric import (
    abi_decimal_context,
)


_TExc = TypeVar("_TExc", bound=BaseException)

getcontext: Final = decimal.getcontext
setcontext: Final = decimal.setcontext


@final
class _DecimalContextManager:
    """Context manager class to support decimal.localcontext().

      Sets a copy of the supplied context in __enter__() and restores
      the previous decimal context in __exit__()
    """
    saved_context: Context
    def __init__(self, new_context: Context) -> None:
        self.new_context: Final = new_context.copy()
    def __enter__(self) -> Context:
        self.saved_context = getcontext()
        setcontext(self.new_context)
        return self.new_context
    def __exit__(
        self,
        t: Optional[Type[_TExc]],
        v: Optional[_TExc],
        tb: Optional[TracebackType],
    ) -> None:
        setcontext(self.saved_context)

DECIMAL_CONTEXT: Final = _DecimalContextManager(abi_decimal_context)
