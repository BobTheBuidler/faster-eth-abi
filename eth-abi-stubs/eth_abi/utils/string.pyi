from typing import Any

def abbr(value: Any, limit: int = 79) -> str:
    """
    Converts a value into its string representation and abbreviates that
    representation based on the given length `limit` if necessary.
    """
