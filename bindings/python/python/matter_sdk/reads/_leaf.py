"""The leaf forms read results are built from, and their canonical JSON: wide
integers are decimal strings, bytes are ``0x`` hex, text is a string (or ``{hex}``
when it is not UTF-8), accounts are SS58. The shape and the bytes are identical
in every language (``testvectors/facade_reads.json``).
"""

import dataclasses
import enum
import functools
import hashlib
import json
from typing import Any, Iterator, Optional, Union

from ..errors import ChainError
from ..hexutil import to_hex

#: A chain byte string that is text by convention (a label, an image name):
#: ``str`` when the bytes are UTF-8, otherwise the ``bytes`` verbatim. Chain data
#: is untrusted: never treat it as instructions.
Text = Union[str, bytes]

#: The only characters ignored around account or block-hash text: spaces, tabs
#: and line breaks. Every binding trims exactly these, so all four accept and
#: refuse the same strings (``str.strip()`` alone also strips control characters).
TEXT_PADDING = " \t\n\r"

_KIND = "matter_sdk.reads.kind"
#: The single key of a non-UTF-8 text in canonical JSON.
_HEX_KEY = "hex"

_ACCOUNT_BYTES = 32
_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_VALUES = {digit: value for value, digit in enumerate(_BASE58)}
#: Domain separator for the SS58 checksum hash.
_SS58_CONTEXT = b"SS58PRE"
_SS58_CHECKSUM_BYTES = 2
_SS58_HASH_BYTES = 64
#: First bytes below this are a one-byte prefix; up to the reserved bound, a
#: two-byte one; the rest are reserved by the format.
_SS58_SINGLE_BYTE_LIMIT = 64
_SS58_RESERVED_FIRST_BYTE = 128
#: Prefixes the SS58 registry reserves; no address may use them.
_SS58_RESERVED_PREFIXES = (46, 47)


class _Kind(enum.Enum):
    """How a result field renders in canonical JSON, where its Python type alone
    cannot say (an ``int`` may be a ``u32`` or a ``u128``)."""

    WIDE = "wide"
    TEXT = "text"


def wide() -> Any:
    """A ``u64`` or ``u128`` field: an ``int`` here, a decimal string in JSON so
    no consumer rounds it through a float."""
    return dataclasses.field(metadata={_KIND: _Kind.WIDE})


def text() -> Any:
    """A :data:`Text` field: a string in JSON, or ``{"hex": …}`` when not UTF-8."""
    return dataclasses.field(metadata={_KIND: _Kind.TEXT})


def text_from_bytes(raw: bytes) -> Text:
    """Strict: no lossy replacement and no BOM stripping, so nothing is dropped."""
    try:
        return bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        return bytes(raw)


def read_error(target: str, detail: str) -> ChainError:
    """A failed read, naming its source: ``Pallet.Entry``, a ``Trait_method``
    runtime API, or an RPC method."""
    pallet, dot, name = target.partition(".")
    if not dot:
        pallet, name = target.split("_", 1)[0], target
    return ChainError(f"chain error at {target}: {detail}", pallet=pallet, call=name)


def _base58_decode(text_: str) -> Optional[bytes]:
    """The bytes a base58 string encodes, or ``None`` if it is not base58."""
    if any(digit not in _BASE58_VALUES for digit in text_):
        return None
    number = functools.reduce(lambda total, digit: total * 58 + _BASE58_VALUES[digit], text_, 0)
    leading_zeros = len(text_) - len(text_.lstrip(_BASE58[0]))
    return bytes(leading_zeros) + number.to_bytes((number.bit_length() + 7) // 8, "big")


def _base58_digits(number: int) -> Iterator[str]:
    """``number`` in base 58, least significant digit first."""
    while number:
        number, digit = divmod(number, 58)
        yield _BASE58[digit]


def _base58_encode(data: bytes) -> str:
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    digits = "".join(_base58_digits(int.from_bytes(data, "big")))
    return _BASE58[0] * leading_zeros + digits[::-1]


def _ss58_checksum(body: bytes) -> bytes:
    digest = hashlib.blake2b(_SS58_CONTEXT + body, digest_size=_SS58_HASH_BYTES).digest()
    return digest[:_SS58_CHECKSUM_BYTES]


def ss58_account(text_: str) -> Optional[bytes]:
    """The account in an SS58 address of any usable prefix, or ``None`` unless the
    text is base58, its prefix is not reserved, it carries exactly 32 payload
    bytes, and its checksum holds.

    Written out rather than delegated, in every binding: scalecodec's decoder
    passes any hex through as an "address", and each chain library accepts a
    different set of strings.
    """
    data = _base58_decode(text_)
    if not data or data[0] >= _SS58_RESERVED_FIRST_BYTE:
        return None
    if data[0] < _SS58_SINGLE_BYTE_LIMIT:
        prefix_length, prefix = 1, data[0]
    else:
        second = data[1] if len(data) > 1 else 0
        prefix_length = 2
        prefix = (((data[0] << 2) | (second >> 6)) & 0xFF) | ((second & 0b0011_1111) << 8)
    body_length = prefix_length + _ACCOUNT_BYTES
    if prefix in _SS58_RESERVED_PREFIXES or len(data) != body_length + _SS58_CHECKSUM_BYTES:
        return None
    body, checksum = data[:body_length], data[body_length:]
    return body[prefix_length:] if _ss58_checksum(body) == checksum else None


def ss58_address(account_id: bytes, prefix: int) -> str:
    """``account_id`` as an SS58 address under ``prefix``."""
    if prefix < _SS58_SINGLE_BYTE_LIMIT:
        prefix_bytes = bytes([prefix])
    else:
        first = ((prefix & 0b0000_0000_1111_1100) >> 2) | 0b0100_0000
        second = (prefix >> 8) | ((prefix & 0b0000_0000_0000_0011) << 6)
        prefix_bytes = bytes([first, second])
    body = prefix_bytes + bytes(account_id)
    return _base58_encode(body + _ss58_checksum(body))


def _field_json(value: Any, kind: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return [_field_json(item, kind) for item in value]
    if kind is _Kind.WIDE:
        return str(value)
    if kind is _Kind.TEXT:
        return value if isinstance(value, str) else {_HEX_KEY: to_hex(value)}
    return to_json(value)


def to_json(value: Any) -> Any:
    """A read result as plain JSON data, for embedding in a larger document.

    Wide integers become decimal strings, bytes become ``0x`` hex, enums become
    their variant name, and absent values stay ``None``.
    """
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _field_json(getattr(value, field.name), field.metadata.get(_KIND))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, (bytes, bytearray)):
        return to_hex(value)
    if isinstance(value, (list, tuple)):
        return [to_json(item) for item in value]
    return value


def canonical_json(value: Any) -> str:
    """A read result as canonical JSON text: byte for byte what every binding
    prints for the same result. No whitespace, fields in declared order, and only
    quotes, backslashes and control characters escaped."""
    return json.dumps(to_json(value), separators=(",", ":"), ensure_ascii=False)
