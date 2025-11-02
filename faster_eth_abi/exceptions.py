# mypy: disable-error-code="misc"
# cannot subclass `Any`

"""
Exception classes for error handling during ABI encoding and decoding operations.

faster-eth-abi exceptions always inherit from eth-abi exceptions, so porting to faster-eth-abi
does not require any change to your existing exception handlers. They will continue to work.
"""

import eth_abi.exceptions


class EncodingError(eth_abi.exceptions.EncodingError):
    """
    Base exception for any error that occurs during encoding.
    """


class EncodingTypeError(EncodingError, eth_abi.exceptions.EncodingTypeError):
    """
    Raised when trying to encode a python value whose type is not supported for
    the output ABI type.
    """


class IllegalValue(EncodingError, eth_abi.exceptions.IllegalValue):
    """
    Raised when trying to encode a python value with the correct type but with
    a value that is not considered legal for the output ABI type.

    .. code-block:: python

        fixed128x19_encoder(Decimal('NaN'))  # cannot encode NaN

    """


class ValueOutOfBounds(IllegalValue, eth_abi.exceptions.ValueOutOfBounds):
    """
    Raised when trying to encode a python value with the correct type but with
    a value that appears outside the range of valid values for the output ABI
    type.

    .. code-block:: python

        ufixed8x1_encoder(Decimal('25.6'))  # out of bounds

    """


class DecodingError(eth_abi.exceptions.DecodingError):
    """
    Base exception for any error that occurs during decoding.
    """


class InsufficientDataBytes(DecodingError, eth_abi.exceptions.InsufficientDataBytes):
    """
    Raised when there are insufficient data to decode a value for a given ABI type.
    """


class NonEmptyPaddingBytes(DecodingError, eth_abi.exceptions.NonEmptyPaddingBytes):
    """
    Raised when the padding bytes of an ABI value are malformed.
    """


class InvalidPointer(DecodingError, eth_abi.exceptions.InvalidPointer):
    """
    Raised when the pointer to a value in the ABI encoding is invalid.
    """


class ParseError(eth_abi.exceptions.ParseError):
    """
    Raised when an ABI type string cannot be parsed.
    """

    def __str__(self) -> str:
        return (
            f"Parse error at '{self.text[self.pos : self.pos + 5]}' "
            f"(column {self.column()}) in type string '{self.text}'"
        )


class ABITypeError(eth_abi.exceptions.ABITypeError):
    """
    Raised when a parsed ABI type has inconsistent properties; for example,
    when trying to parse the type string ``'uint7'`` (which has a bit-width
    that is not congruent with zero modulo eight).
    """


class PredicateMappingError(eth_abi.exceptions.PredicateMappingError):
    """
    Raised when an error occurs in a registry's internal mapping.
    """


class NoEntriesFound(PredicateMappingError, eth_abi.exceptions.NoEntriesFound):
    """
    Raised when no registration is found for a type string in a registry's
    internal mapping.

    .. warning::

        In a future version of ``faster-eth-abi``, this error class will no longer
        inherit from ``ValueError``.
    """


class MultipleEntriesFound(
    PredicateMappingError, eth_abi.exceptions.MultipleEntriesFound
):
    """
    Raised when multiple registrations are found for a type string in a
    registry's internal mapping.  This error is non-recoverable and indicates
    that a registry was configured incorrectly.  Registrations are expected to
    cover completely distinct ranges of type strings.

    .. warning::

        In a future version of ``faster-eth-abi``, this error class will no longer
        inherit from ``ValueError``.
    """
