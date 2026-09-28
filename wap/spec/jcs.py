"""JSON Canonicalization Scheme (RFC 8785).

WAP signs the canonical form of JSON documents so that any implementation, in
any language, reproduces the exact signed bytes. JCS defines that form:

* objects: members sorted by the UTF-16 code units of their names;
* no insignificant whitespace;
* strings: the minimal ECMAScript ``JSON.stringify`` escaping, UTF-8 encoded;
* numbers: IEEE-754 doubles printed exactly as ECMAScript ``Number.prototype.toString``
  prints them (shortest round-trip digits; ``1e+21`` style exponents; ``-0`` as ``0``).

Integers outside ±2**53 cannot be represented exactly by a double and are
rejected, as are NaN and infinities (I-JSON, RFC 7493).
"""

from __future__ import annotations

import math
from typing import Any

MAX_SAFE_INTEGER = 2**53

_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


class CanonicalizationError(ValueError):
    """The value cannot be represented in canonical JSON."""


def _string(value: str) -> str:
    out = ['"']
    for ch in value:
        escaped = _ESCAPES.get(ch)
        if escaped is not None:
            out.append(escaped)
        elif ch < " ":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(value: float | int) -> str:
    if isinstance(value, bool):  # bool is an int subclass; handled by the caller
        raise CanonicalizationError("booleans are not numbers")
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError(f"integer {value} is outside the IEEE-754 safe range (±2**53)")
        value = float(value)
    if not math.isfinite(value):
        raise CanonicalizationError("NaN and infinities are not valid JSON")
    if value == 0:
        return "0"  # also -0
    sign = "-" if value < 0 else ""
    # Python's repr is the shortest round-trip representation, like ECMAScript; only the
    # layout (where the decimal point goes, exponent style) differs, so re-layout the digits.
    text = repr(abs(value))
    mantissa, _, exponent = text.partition("e")
    int_part, _, frac_part = mantissa.partition(".")
    digits = (int_part + frac_part).lstrip("0")
    leading_zeros = len(int_part + frac_part) - len((int_part + frac_part).lstrip("0"))
    point = len(int_part) - leading_zeros + (int(exponent) if exponent else 0)
    digits = digits.rstrip("0")
    k, n = len(digits), point
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        exp = f"e{'+' if e >= 0 else '-'}{abs(e)}"
        body = (digits + exp) if k == 1 else (digits[0] + "." + digits[1:] + exp)
    return sign + body


def _utf16_key(name: str) -> bytes:
    return name.encode("utf-16-be", "surrogatepass")


def _serialize(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_string(value))
    elif isinstance(value, (int, float)):
        out.append(_number(value))
    elif isinstance(value, dict):
        out.append("{")
        for i, key in enumerate(sorted(value, key=lambda k: _utf16_key(_check_key(k)))):
            if i:
                out.append(",")
            out.append(_string(key))
            out.append(":")
            _serialize(value[key], out)
        out.append("}")
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _serialize(item, out)
        out.append("]")
    else:
        raise CanonicalizationError(f"{type(value).__name__} is not a JSON type")


def _check_key(key: Any) -> str:
    if not isinstance(key, str):
        raise CanonicalizationError("object member names must be strings")
    return key


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes of a JSON-compatible Python value."""
    out: list[str] = []
    _serialize(value, out)
    return "".join(out).encode("utf-8", "surrogatepass")


def format_number(value: float | int) -> str:
    """ECMAScript ``Number.prototype.toString`` for a finite double (exposed for tests)."""
    return _number(value)


__all__ = ["CanonicalizationError", "MAX_SAFE_INTEGER", "canonicalize", "format_number"]
