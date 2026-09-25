"""Hex + numeric framing, byte-for-byte with the core's ``wire`` module."""

_U128_MAX = 1 << 128


def to_hex(data: bytes) -> str:
    """Encode bytes as a ``0x``-prefixed lowercase hex string."""
    return "0x" + bytes(data).hex()


def from_hex(s: str) -> bytes:
    """Decode a ``0x``-prefixed (or bare) hex string into bytes."""
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def secret_id_to_hex(secret_id: int) -> str:
    """Render a ``u128`` secret id as ``0x`` + 32 hex chars (16 big-endian bytes)."""
    if not 0 <= secret_id < _U128_MAX:
        raise ValueError("secret_id out of u128 range")
    return to_hex(secret_id.to_bytes(16, "big"))
