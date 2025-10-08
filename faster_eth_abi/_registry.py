import abc
from typing import (
    Dict,
    Final,
    Generic,
    TypeVar,
    Union,
    final,
)

from faster_eth_abi.grammar import (
    BasicType,
    parse,
)


_T = TypeVar("_T")


class Copyable(abc.ABC):
    @abc.abstractmethod
    def copy(self) -> Self:
        pass

    def __copy__(self) -> Self:
        return self.copy()

    def __deepcopy__(self, *args) -> Self:
        return self.copy()


@final
class PredicateMapping(Copyable):
    """
    Acts as a mapping from predicate functions to values.  Values are retrieved
    when their corresponding predicate matches a given input.  Predicates can
    also be labeled to facilitate removal from the mapping.
    """

    def __init__(self, name: str) -> None:
        self._name: Final = name
        self._values: Final[Dict["Predicate", str]] = {}
        self._labeled_predicates: Final[Dict[str, "Predicate"]] = {}

    def add(self, predicate, value, label=None):
        if predicate in self._values:
            raise ValueError(f"Matcher {predicate!r} already exists in {self._name}")

        if label is not None:
            if label in self._labeled_predicates:
                raise ValueError(
                    f"Matcher {predicate!r} with label '{label}' "
                    f"already exists in {self._name}"
                )

            self._labeled_predicates[label] = predicate

        self._values[predicate] = value

    def find(self, type_str: TypeStr) -> str:
        results = tuple(
            (predicate, value)
            for predicate, value in self._values.items()
            if predicate(type_str)
        )

        if len(results) == 0:
            raise NoEntriesFound(
                f"No matching entries for '{type_str}' in {self._name}"
            )

        predicates, values = tuple(zip(*results))

        if len(results) > 1:
            predicate_reprs = ", ".join(map(repr, predicates))
            raise MultipleEntriesFound(
                f"Multiple matching entries for '{type_str}' in {self._name}: "
                f"{predicate_reprs}. This occurs when two registrations match the "
                "same type string. You may need to delete one of the "
                "registrations or modify its matching behavior to ensure it "
                'doesn\'t collide with other registrations. See the "Registry" '
                "documentation for more information."
            )

        return values[0]

    def remove_by_equality(self, predicate: "Predicate") -> None:
        # Delete the predicate mapping to the previously stored value
        try:
            del self._values[predicate]
        except KeyError:
            raise KeyError(f"Matcher {predicate!r} not found in {self._name}")

        # Delete any label which refers to this predicate
        try:
            label = self._label_for_predicate(predicate)
        except ValueError:
            pass
        else:
            del self._labeled_predicates[label]

    def _label_for_predicate(self, predicate: "Predicate") -> str:
        # Both keys and values in `_labeled_predicates` are unique since the
        # `add` method enforces this
        for key, value in self._labeled_predicates.items():
            if value is predicate:
                return key

        raise ValueError(
            f"Matcher {predicate!r} not referred to by any label in {self._name}"
        )

    def remove_by_label(self, label: str) -> None:
        try:
            predicate = self._labeled_predicates[label]
        except KeyError:
            raise KeyError(f"Label '{label}' not found in {self._name}")

        del self._labeled_predicates[label]
        del self._values[predicate]

    def remove(self, predicate_or_label: Union["Predicate", str]) -> None:
        if callable(predicate_or_label):
            self.remove_by_equality(predicate_or_label)
        elif isinstance(predicate_or_label, str):
            self.remove_by_label(predicate_or_label)
        else:
            raise TypeError(
                "Key to be removed must be callable or string: got "
                f"{type(predicate_or_label)}"
            )

    def copy(self) -> Self:
        cpy = type(self)(self._name)

        cpy._values = copy.copy(self._values)
        cpy._labeled_predicates = copy.copy(self._labeled_predicates)

        return cpy


class Predicate(Generic[_T]):
    """
    Represents a predicate function to be used for type matching in
    ``ABIRegistry``.
    """

    __slots__ = tuple()

    def __call__(self, *args, **kwargs) -> bool:  # pragma: no cover
        raise NotImplementedError("Must implement `__call__`")

    def __str__(self) -> str:  # pragma: no cover
        raise NotImplementedError("Must implement `__str__`")

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self}>"

    def __iter__(self) -> Iterator[_T]:
        for attr in self.__slots__:
            yield getattr(self, attr)

    def __hash__(self) -> int:
        return hash(tuple(self))

    def __eq__(self, other: "Predicate") -> bool:
        return type(self) is type(other) and tuple(self) == tuple(other)


@final
class Equals(Predicate[str]):
    """
    A predicate that matches any input equal to `value`.
    """

    __slots__ = ("value",)

    def __init__(self, value: str) -> None:
        self.value = value

    def __call__(self, other: str) -> bool:
        return self.value == other

    def __str__(self) -> str:
        return f"(== {self.value!r})"


@final
class BaseEquals(Predicate[Union[str, Optional[bool]]]):
    """
    A predicate that matches a basic type string with a base component equal to
    `value` and no array component.  If `with_sub` is `True`, the type string
    must have a sub component to match.  If `with_sub` is `False`, the type
    string must *not* have a sub component to match.  If `with_sub` is None,
    the type string's sub component is ignored.
    """

    __slots__ = ("base", "with_sub")

    def __init__(self, base: TypeStr, *, with_sub: Optional[bool] = None) -> None:
        self.base: Final = base
        self.with_sub: Final = with_sub

    def __call__(self, type_str: TypeStr) -> bool:
        try:
            abi_type = parse(type_str)
        except (exceptions.ParseError, ValueError):
            return False

        if isinstance(abi_type, BasicType):
            if abi_type.arrlist is not None:
                return False

            if self.with_sub is not None:
                if self.with_sub and abi_type.sub is None:
                    return False
                if not self.with_sub and abi_type.sub is not None:
                    return False

            return abi_type.base == self.base

        # We'd reach this point if `type_str` did not contain a basic type
        # e.g. if it contained a tuple type
        return False

    def __str__(self) -> str:
        return (
            f"(base == {self.base!r}"
            + (
                ""
                if self.with_sub is None
                else (" and sub is not None" if self.with_sub else " and sub is None")
            )
            + ")"
        )
