from typing import (
    Callable,
    Dict,
    Final,
    Tuple,
    TypeVar,
    final,
)

from eth_typing.abi import (
    TypeStr,
)

if TYPE_CHECKING:
    from faster_eth_abi.codec import BaseCoder


C = TypeVar("C", bound="BaseCoder")


@final
class coder_cache:
    """A specialized lru_cache implementation that only supports posargs and has no maxsize."""
    def __init__(self, func: Callable[[Tuple[TypeStr, ...], C]) -> None:
        self._func: Final = func
        self._cache: Final[Dict[Tuple[TypeStr, ...], C]]
        functools.wraps(fn)(self)
    def __call__(self, *args: TypeStr) -> C:
        coder = self._cache.get(args)
        if coder is None:
            coder = _cache[args] = fn(*args)
        return coder
    def __repr__(self) -> str:
      return f"coder_cache({repr(self._func)}"
    def cache_clear() -> None:
        self._cache.clear()
