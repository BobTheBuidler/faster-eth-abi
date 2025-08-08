from typing import (
    Any,
    TypeVar,
)

from eth_typing import (
    TypeStr,
)
from mypy_extensions import (
    mypyc_attr,
)
from typing_extensions import (
    Self,
)

TCoder = TypeVar("TCoder", bound="BaseCoder")


@mypyc_attr(native_class=False)
class BaseCoder:
    """
    Base class for all encoder and decoder classes.
    """

    is_dynamic: bool = False

    def __init__(self: TCoder, **kwargs: Any) -> None:
        cls = type(self)

        # Ensure no unrecognized kwargs were given
        for key, value in kwargs.items():
            if not hasattr(cls, key):
                raise AttributeError(
                    "Property {key} not found on {cls_name} class. "
                    "`{cls_name}.__init__` only accepts keyword arguments which are "
                    "present on the {cls_name} class.".format(
                        key=key,
                        cls_name=cls.__name__,
                    )
                )
            setattr(self, key, value)

        # Validate given combination of kwargs
        self.validate()

    def validate(self) -> None:
        pass

    @classmethod
    def from_type_str(  # pragma: no cover
        cls: TCoder, type_str: TypeStr, registry: Any
    ) -> Self:
        """
        Used by :any:`ABIRegistry` to get an appropriate encoder or decoder
        instance for the given type string and type registry.
        """
        raise NotImplementedError("Must implement `from_type_str`")
