"""A strict SCALE reader for read results. Decoders say what they expect, field
by field, and must consume every byte: a value whose layout the runtime has
changed fails here instead of decoding into something plausible and wrong.
"""

from typing import Callable, List, Optional, TypeVar

from ..errors import ChainError
from ._leaf import read_error

T = TypeVar("T")

_COMPACT_MODE_MASK = 0b11
_COMPACT_MODE_BITS = 2
#: Compact modes, by the low two bits of the first byte.
_ONE_BYTE, _TWO_BYTES, _FOUR_BYTES = 0, 1, 2
#: The big-integer mode's first byte carries ``byte count - 4`` above the mode bits.
_COMPACT_BIG_MIN_BYTES = 4
#: The largest value each fixed-width mode may carry; a larger mode for it is
#: not canonical.
_COMPACT_ONE_BYTE_MAX = (1 << 6) - 1
_COMPACT_TWO_BYTE_MAX = (1 << 14) - 1
_COMPACT_FOUR_BYTE_MAX = (1 << 30) - 1

_U32_MAX = (1 << 32) - 1
_U64_MAX = (1 << 64) - 1
_U128_MAX = (1 << 128) - 1

_BOOLS = {0: False, 1: True}
_OPTION_NONE, _OPTION_SOME = 0, 1


class ScaleReader:
    """Reads one value's fields in wire order. ``target`` names the source in
    errors."""

    __slots__ = ("_data", "_target", "_offset")

    def __init__(self, data: bytes, target: str) -> None:
        self._data = bytes(data)
        self._target = target
        self._offset = 0

    def _fail(self, why: str) -> ChainError:
        return read_error(
            self._target, f"the value does not have the layout this SDK decodes: {why}"
        )

    def fixed(self, length: int) -> bytes:
        """The next ``length`` bytes, exactly as stored."""
        end = self._offset + length
        if end > len(self._data):
            left = len(self._data) - self._offset
            raise self._fail(f"needs {length} more bytes at offset {self._offset}, has {left}")
        chunk = self._data[self._offset : end]
        self._offset = end
        return chunk

    def _unsigned(self, length: int) -> int:
        return int.from_bytes(self.fixed(length), "little")

    def u8(self) -> int:
        return self._unsigned(1)

    def u16(self) -> int:
        return self._unsigned(2)

    def u32(self) -> int:
        return self._unsigned(4)

    def u64(self) -> int:
        return self._unsigned(8)

    def u128(self) -> int:
        return self._unsigned(16)

    def boolean(self) -> bool:
        byte = self.u8()
        if byte not in _BOOLS:
            raise self._fail(f"a bool is 0 or 1, found {byte}")
        return _BOOLS[byte]

    def _compact(self, widest: int) -> int:
        """A compact-encoded unsigned integer no wider than ``widest``, refusing
        any encoding longer than needed: the reference codec refuses both."""
        if self._offset >= len(self._data):
            raise self._fail("needs a compact integer, has no bytes left")
        value = self._compact_value(self._data[self._offset] & _COMPACT_MODE_MASK)
        if value > widest:
            raise self._fail(f"a compact integer of {value} is wider than its type")
        return value

    def _compact_value(self, mode: int) -> int:
        if mode == _ONE_BYTE:
            return self._unsigned(1) >> _COMPACT_MODE_BITS
        if mode == _TWO_BYTES:
            return self._canonical(self._unsigned(2) >> _COMPACT_MODE_BITS, _COMPACT_ONE_BYTE_MAX)
        if mode == _FOUR_BYTES:
            return self._canonical(self._unsigned(4) >> _COMPACT_MODE_BITS, _COMPACT_TWO_BYTE_MAX)
        length = (self.u8() >> _COMPACT_MODE_BITS) + _COMPACT_BIG_MIN_BYTES
        body = self.fixed(length)
        if body[-1] == 0:
            raise self._fail("a compact integer has a leading zero byte")
        return self._canonical(int.from_bytes(body, "little"), _COMPACT_FOUR_BYTE_MAX)

    def _canonical(self, value: int, shorter_mode_max: int) -> int:
        """``value``, which a shorter mode could not have carried."""
        if value <= shorter_mode_max:
            raise self._fail("a compact integer is not in its shortest form")
        return value

    def compact_u32(self) -> int:
        return self._compact(_U32_MAX)

    def compact_u64(self) -> int:
        return self._compact(_U64_MAX)

    def compact_u128(self) -> int:
        return self._compact(_U128_MAX)

    def _length(self) -> int:
        """A compact length, checked against what is left so garbage cannot ask
        for gigabytes."""
        length = self.compact_u32()
        remaining = len(self._data) - self._offset
        if length > remaining:
            raise self._fail(f"a length of {length} runs past the input ({remaining} bytes left)")
        return length

    def byte_string(self) -> bytes:
        """A length-prefixed byte string (``Vec<u8>``, ``BoundedVec<u8>``)."""
        return self.fixed(self._length())

    def vec(self, item: Callable[["ScaleReader"], T]) -> List[T]:
        """A length-prefixed sequence; ``item`` reads one element."""
        return [item(self) for _ in range(self._length())]

    def option(self, item: Callable[["ScaleReader"], T]) -> Optional[T]:
        """An ``Option<T>``; ``None`` is ``None``."""
        tag = self.u8()
        if tag == _OPTION_NONE:
            return None
        if tag == _OPTION_SOME:
            return item(self)
        raise self._fail(f"an option tag is 0 or 1, found {tag}")

    def finish(self) -> None:
        """Assert the value ended where the layout says it does."""
        left = len(self._data) - self._offset
        if left:
            raise self._fail(f"{left} bytes left over")


def decode_strict(target: str, data: bytes, read: Callable[[ScaleReader], T]) -> T:
    """Decode ``data`` as exactly what ``read`` reads: nothing missing, nothing
    left over."""
    reader = ScaleReader(data, target)
    value = read(reader)
    reader.finish()
    return value


# --- the few values reads encode: runtime-API arguments -----------------------


def _unsigned_bytes(value: int, length: int) -> bytes:
    return value.to_bytes(length, "little")


def encode_u32(value: int) -> bytes:
    return _unsigned_bytes(value, 4)


def encode_u128(value: int) -> bytes:
    return _unsigned_bytes(value, 16)


def _encode_compact_length(length: int) -> bytes:
    """A compact length in its shortest form. Lengths here never reach the
    big-integer mode."""
    if length <= _COMPACT_ONE_BYTE_MAX:
        return _unsigned_bytes(length << _COMPACT_MODE_BITS | _ONE_BYTE, 1)
    if length <= _COMPACT_TWO_BYTE_MAX:
        return _unsigned_bytes(length << _COMPACT_MODE_BITS | _TWO_BYTES, 2)
    if length <= _COMPACT_FOUR_BYTE_MAX:
        return _unsigned_bytes(length << _COMPACT_MODE_BITS | _FOUR_BYTES, 4)
    raise ValueError(f"{length} bytes is too long to encode")


def encode_byte_string(data: bytes) -> bytes:
    """A length-prefixed byte string (``Vec<u8>``)."""
    return _encode_compact_length(len(data)) + bytes(data)
