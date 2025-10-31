from typing import Any

class BaseCoder:
    """
    Base class for all encoder and decoder classes.
    """

    is_dynamic: bool
    def __init__(self, **kwargs: Any) -> None: ...
    def validate(self) -> None: ...
    @classmethod
    def from_type_str(cls, type_str, registry) -> None:
        """
        Used by :any:`ABIRegistry` to get an appropriate encoder or decoder
        instance for the given type string and type registry.
        """
