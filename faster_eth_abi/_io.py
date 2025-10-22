# I need to do this import from a non-compiled file to prevent a module name conflict
from io import (
    BytesIO,
)

__all__ = ["BytesIO"]
