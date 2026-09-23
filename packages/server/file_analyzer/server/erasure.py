"""
Reed-Solomon erasure coding over GF(2^8) -- pure standard library.

This is the codec behind erasure-coded (sharded) backups. It is a *systematic*
code: ``k`` data shards are stored verbatim and ``m`` parity shards are added,
and **any** ``k`` of the ``k + m`` shards reconstruct the data -- so up to ``m``
shards may be lost (erasures) without losing anything.

Construction
------------
* Field: GF(2^8) with the primitive polynomial ``x^8 + x^4 + x^3 + x^2 + 1``
  (``0x11d``) and generator ``2`` -- the field used by most storage RS codes.
* Generator matrix: ``[ I_k ; C ]`` where ``C`` is an ``m x k`` **Cauchy**
  matrix ``C[j][i] = 1 / (x_j + y_i)`` with ``x_j = k + j`` and ``y_i = i``
  (all ``k + m`` values distinct, so no denominator is zero). Every square
  submatrix of a Cauchy matrix is non-singular, which makes every ``k``-row
  submatrix of ``[I ; C]`` invertible: the code is MDS for any ``k + m <= 256``.
  (A plain Vandermonde ``[I ; V]`` does *not* have this property in general.)
* Decoding: pick ``k`` surviving shards, invert the matching ``k x k`` rows of
  the generator matrix by Gauss-Jordan elimination over the field, and multiply.

Speed
-----
Byte-wise field arithmetic in a Python loop would be far too slow for backups,
so the bulk operations run inside CPython's C code: multiplying a whole block
by a constant ``c`` is one ``bytes.translate`` through a 256-entry table, and
adding (XOR-ing) blocks is one arbitrary-precision integer XOR. A shard block of
a megabyte therefore costs a handful of C-level passes, not a million
interpreter steps.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

#: The field's primitive polynomial (x^8 + x^4 + x^3 + x^2 + 1).
PRIMITIVE_POLY = 0x11D
#: Hard limit on total shards: the Cauchy points must be distinct field elements.
MAX_SHARDS = 256

# --------------------------------------------------------------------------- #
# GF(2^8) arithmetic
# --------------------------------------------------------------------------- #
_EXP: List[int] = [0] * 512
_LOG: List[int] = [0] * 256


def _build_tables() -> None:
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= PRIMITIVE_POLY
    # Doubled so gf_mul can index LOG[a] + LOG[b] (<= 508) without a modulo.
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_build_tables()


def gf_add(a: int, b: int) -> int:
    """Addition (and subtraction) in GF(2^8) is XOR."""
    return a ^ b


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("0 has no inverse in GF(2^8)")
    return _EXP[255 - _LOG[a]]


def gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("division by 0 in GF(2^8)")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


_MUL_TABLES: Dict[int, bytes] = {}


def _mul_table(c: int) -> bytes:
    """The 256-byte translate table for ``x -> c * x``."""
    table = _MUL_TABLES.get(c)
    if table is None:
        table = bytes(gf_mul(c, x) for x in range(256))
        _MUL_TABLES[c] = table
    return table


def gf_mul_block(c: int, block: bytes) -> bytes:
    """Multiply every byte of ``block`` by the constant ``c``."""
    if c == 0:
        return bytes(len(block))
    if c == 1:
        return bytes(block)
    return bytes(block).translate(_mul_table(c))


def combine(coeffs: Sequence[int], blocks: Sequence[bytes], size: int) -> bytes:
    """``sum_i coeffs[i] * blocks[i]`` over GF(2^8), for equal-``size`` blocks."""
    acc = 0
    for c, block in zip(coeffs, blocks):
        if c == 0:
            continue
        term = block if c == 1 else bytes(block).translate(_mul_table(c))
        acc ^= int.from_bytes(term, "little")
    return acc.to_bytes(size, "little")


def gf_matrix_invert(matrix: Sequence[Sequence[int]]) -> List[List[int]]:
    """Invert a square matrix over GF(2^8) (Gauss-Jordan); raise if singular."""
    n = len(matrix)
    aug = []
    for i, row in enumerate(matrix):
        if len(row) != n:
            raise ValueError("matrix is not square")
        aug.append([int(v) for v in row] + [1 if j == i else 0 for j in range(n)])
    for col in range(n):
        pivot = next((r for r in range(col, n) if aug[r][col]), None)
        if pivot is None:
            raise ValueError("matrix is singular over GF(2^8)")
        aug[col], aug[pivot] = aug[pivot], aug[col]
        inv = gf_inv(aug[col][col])
        aug[col] = [gf_mul(inv, v) for v in aug[col]]
        for r in range(n):
            f = aug[r][col]
            if r != col and f:
                aug[r] = [a ^ gf_mul(f, b) for a, b in zip(aug[r], aug[col])]
    return [row[n:] for row in aug]


def gf_matmul(
    a: Sequence[Sequence[int]], b: Sequence[Sequence[int]]
) -> List[List[int]]:
    """Matrix product over GF(2^8) (used by tests and self-checks)."""
    cols = len(b[0])
    out = []
    for row in a:
        out_row = []
        for j in range(cols):
            acc = 0
            for t, v in enumerate(row):
                acc ^= gf_mul(v, b[t][j])
            out_row.append(acc)
        out.append(out_row)
    return out


# --------------------------------------------------------------------------- #
# The code
# --------------------------------------------------------------------------- #
class TooManyErasures(ValueError):
    """Fewer than ``k`` intact shards remain: the data cannot be reconstructed."""


class ReedSolomon:
    """A systematic ``(k + m, k)`` Reed-Solomon erasure code over GF(2^8)."""

    def __init__(self, data_shards: int, parity_shards: int) -> None:
        k, m = int(data_shards), int(parity_shards)
        if k < 1:
            raise ValueError("data_shards must be >= 1")
        if m < 0:
            raise ValueError("parity_shards must be >= 0")
        if k + m > MAX_SHARDS:
            raise ValueError(f"data_shards + parity_shards must be <= {MAX_SHARDS}")
        self.k = k
        self.m = m
        self.n = k + m
        # Cauchy parity rows: C[j][i] = 1 / (x_j ^ y_i), x_j = k + j, y_i = i.
        self.parity_matrix: List[List[int]] = [
            [gf_inv((k + j) ^ i) for i in range(k)] for j in range(m)
        ]
        self._inverse_cache: Dict[Tuple[int, ...], List[List[int]]] = {}

    def __repr__(self) -> str:
        return f"ReedSolomon(k={self.k}, m={self.m})"

    def generator_row(self, index: int) -> List[int]:
        """Row ``index`` of the ``n x k`` generator matrix ``[I ; C]``."""
        if not 0 <= index < self.n:
            raise IndexError(f"shard index {index} out of range 0..{self.n - 1}")
        if index < self.k:
            return [1 if i == index else 0 for i in range(self.k)]
        return list(self.parity_matrix[index - self.k])

    @staticmethod
    def _block_size(blocks: Sequence[Optional[bytes]]) -> int:
        sizes = {len(b) for b in blocks if b is not None}
        if len(sizes) != 1:
            raise ValueError("all shard blocks must be present-sized and equal")
        return sizes.pop()

    # -- encoding -----------------------------------------------------------
    def encode(self, data_blocks: Sequence[bytes]) -> List[bytes]:
        """Return the ``m`` parity blocks for ``k`` equal-sized data blocks."""
        if len(data_blocks) != self.k:
            raise ValueError(f"expected {self.k} data blocks, got {len(data_blocks)}")
        size = self._block_size(data_blocks)
        return [combine(row, data_blocks, size) for row in self.parity_matrix]

    def encode_shards(self, data_blocks: Sequence[bytes]) -> List[bytes]:
        """All ``n`` shard blocks: the data verbatim followed by the parity."""
        return [bytes(b) for b in data_blocks] + self.encode(data_blocks)

    # -- decoding -----------------------------------------------------------
    def _inverse_for(self, chosen: Tuple[int, ...]) -> List[List[int]]:
        inv = self._inverse_cache.get(chosen)
        if inv is None:
            inv = gf_matrix_invert([self.generator_row(i) for i in chosen])
            if len(self._inverse_cache) > 256:
                self._inverse_cache.clear()
            self._inverse_cache[chosen] = inv
        return inv

    def decode_data(self, shards: Sequence[Optional[bytes]]) -> List[bytes]:
        """Recover the ``k`` data blocks from ``n`` shards (``None`` = erased)."""
        if len(shards) != self.n:
            raise ValueError(f"expected {self.n} shard slots, got {len(shards)}")
        present = [i for i, b in enumerate(shards) if b is not None]
        if len(present) < self.k:
            raise TooManyErasures(
                f"only {len(present)} of {self.n} shards intact; "
                f"need at least {self.k}"
            )
        size = self._block_size(shards)
        if all(shards[i] is not None for i in range(self.k)):
            return [bytes(shards[i]) for i in range(self.k)]  # type: ignore[arg-type]
        # Prefer data shards (identity rows) -- fewer multiplications.
        chosen = tuple(present[: self.k])
        inv = self._inverse_for(chosen)
        sources = [shards[i] for i in chosen]
        out: List[bytes] = []
        for i in range(self.k):
            block = shards[i]
            if block is not None:
                out.append(bytes(block))
            else:
                out.append(combine(inv[i], sources, size))  # type: ignore[arg-type]
        return out

    def reconstruct(self, shards: Sequence[Optional[bytes]]) -> List[bytes]:
        """Recover *all* ``n`` shard blocks (data and parity) from any ``k``."""
        data = self.decode_data(shards)
        parity: List[Optional[bytes]] = list(shards[self.k :])
        if any(p is None for p in parity):
            fresh = self.encode(data)
            parity = [p if p is not None else fresh[j] for j, p in enumerate(parity)]
        return data + [bytes(p) for p in parity]  # type: ignore[arg-type]

    def verify(self, shards: Sequence[bytes]) -> bool:
        """``True`` iff all ``n`` blocks are present and the parity is consistent."""
        if len(shards) != self.n or any(b is None for b in shards):
            return False
        return self.encode(shards[: self.k]) == [bytes(b) for b in shards[self.k :]]
