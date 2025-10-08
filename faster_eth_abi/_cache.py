import functools
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Final,
    Generic,
    Tuple,
    TypeVar,
    final,
)

from eth_typing.abi import (
    TypeStr,
)

from faster_eth_abi.base import (
    BaseCoder,
)

if TYPE_CHECKING:
    from faster_eth_abi.registry import ABIRegistry


C = TypeVar("C", bound=Callable)


class _CacheBase(Generic[C]):
    def __repr__(self) -> str:
      return f"{type(self).__name__}({repr(self._func)}"
    def cache_clear(self) -> None:
        self._cache.clear()


@final
class EncoderCache(Generic[C]):
    """A specialized lru_cache implementation that only supports posargs and has no maxsize."""
    def __init__(self, func: Callable[..., C]) -> None:
        self._func: Final = func
        self._cache: Final[Dict[Tuple[TypeStr, ...], C]] = {}
        functools.wraps(func)(self)
    def __call__(self, *args: TypeStr) -> C:
        coder = self._cache.get(args)
        if coder is None:
            coder = self._cache[args] = self._func(*args)
        return coder


@final
class DecoderCache(Generic[C]):
    """A specialized lru_cache implementation that only supports posargs and has no maxsize."""
    def __init__(self, func: Callable[..., bool], C]) -> None:
        self._func: Final = func
        self._cache: Final[Dict[Tuple[Tuple[TypeStr, ...], bool], C]] = {}
        functools.wraps(func)(self)
    def __call__(self, *args: TypeStr, strict: bool = False) -> C:
        key = args, strict
        coder = self._cache.get(key)
        if coder is None:
            coder = self._cache[key] = self._func(*args, strict=strict)
        return coder


def _clear_encoder_cache(old_method: Callable[..., None]) -> Callable[..., None]:
    @functools.wraps(old_method)
    def new_method(self: "ABIRegistry", *args: Any, **kwargs: Any) -> None:
        self.get_encoder.cache_clear()
        self.get_tuple_encoder.cache_clear()
        return old_method(self, *args, **kwargs)

    return new_method


def _clear_decoder_cache(old_method: Callable[..., None]) -> Callable[..., None]:
    @functools.wraps(old_method)
    def new_method(self: "ABIRegistry", *args: Any, **kwargs: Any) -> None:
        self.get_decoder.cache_clear()
        self.get_tuple_decoder.cache_clear()
        return old_method(self, *args, **kwargs)

    return new_method
