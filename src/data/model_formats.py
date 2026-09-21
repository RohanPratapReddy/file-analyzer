"""
Dependency-free binary decoders for ML model / tensor container formats.

These back the DataAnalyzer handlers for ``.tflite`` / ``.ort`` (FlatBuffers),
``.flax`` (msgpack param trees), ``.pb`` (protobuf wire format) and ``.tfrecord``
(length-prefixed ``tf.train.Example`` records). Each decoder reads only structure
and metadata (tensor names / shapes / dtypes, graph node counts, record counts) --
never the raw weight/payload bytes -- and is written against the byte-level file
layout so it works with no third-party runtime installed (numpy/msgpack are used
only as an optional fast path where present).

All parsing is bounded and defensive: a malformed or truncated file yields the
partial structure decoded so far plus a note, rather than raising.
"""
from __future__ import annotations

import ast
import gzip
import json
import struct
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ============================================================================
# Minimal FlatBuffers table reader (used by TFLite and ORT)
# ============================================================================
class FlatBufferReader:
    """
    A tiny read-only FlatBuffers accessor. FlatBuffers stores every table as a
    ``soffset`` (signed int32) pointing back to a *vtable*; the vtable lists, per
    schema field id, the byte offset of that field inside the table (0 = absent).
    Vectors and strings are referenced by ``uoffset`` (unsigned int32, relative).
    This class exposes exactly the primitives the model schemas below need.
    """

    def __init__(self, buf: bytes):
        self.b = buf
        self.n = len(buf)

    # --- scalar reads -------------------------------------------------
    def u8(self, o: int) -> int:
        return self.b[o]

    def i8(self, o: int) -> int:
        return struct.unpack_from("<b", self.b, o)[0]

    def u16(self, o: int) -> int:
        return struct.unpack_from("<H", self.b, o)[0]

    def i16(self, o: int) -> int:
        return struct.unpack_from("<h", self.b, o)[0]

    def u32(self, o: int) -> int:
        return struct.unpack_from("<I", self.b, o)[0]

    def i32(self, o: int) -> int:
        return struct.unpack_from("<i", self.b, o)[0]

    def u64(self, o: int) -> int:
        return struct.unpack_from("<Q", self.b, o)[0]

    def i64(self, o: int) -> int:
        return struct.unpack_from("<q", self.b, o)[0]

    # --- structure navigation ----------------------------------------
    def indirect(self, o: int) -> int:
        """Follow a uoffset stored at ``o`` to the absolute position it targets."""
        return o + self.u32(o)

    def root(self) -> int:
        return self.indirect(0)

    def field_offset(self, table: int, field_id: int) -> int:
        """Absolute offset of a field's value in ``table``, or 0 if not present."""
        vtable = table - self.i32(table)
        if vtable < 0 or vtable + 4 > self.n:
            return 0
        vt_size = self.u16(vtable)
        slot = 4 + field_id * 2
        if slot >= vt_size:
            return 0
        voff = self.u16(vtable + slot)
        return (table + voff) if voff else 0

    def field_table(self, table: int, field_id: int) -> int:
        o = self.field_offset(table, field_id)
        return self.indirect(o) if o else 0

    def field_string(self, table: int, field_id: int) -> Optional[str]:
        o = self.field_offset(table, field_id)
        if not o:
            return None
        s = self.indirect(o)
        ln = self.u32(s)
        return self.b[s + 4:s + 4 + ln].decode("utf-8", "replace")

    def field_u32(self, table: int, field_id: int, default: int = 0) -> int:
        o = self.field_offset(table, field_id)
        return self.u32(o) if o else default

    def field_i64(self, table: int, field_id: int, default: int = 0) -> int:
        o = self.field_offset(table, field_id)
        return self.i64(o) if o else default

    def field_u8(self, table: int, field_id: int, default: int = 0) -> int:
        o = self.field_offset(table, field_id)
        return self.u8(o) if o else default

    def vector(self, table: int, field_id: int) -> Tuple[int, int]:
        """Return ``(elements_start, length)`` for a vector field, or ``(0, 0)``."""
        o = self.field_offset(table, field_id)
        if not o:
            return 0, 0
        v = self.indirect(o)
        return v + 4, self.u32(v)

    def vec_table(self, start: int, i: int) -> int:
        return self.indirect(start + i * 4)

    def vec_i32(self, start: int, i: int) -> int:
        return self.i32(start + i * 4)

    def vec_i64(self, start: int, i: int) -> int:
        return self.i64(start + i * 8)

    def vec_string(self, start: int, i: int) -> str:
        s = self.indirect(start + i * 4)
        ln = self.u32(s)
        return self.b[s + 4:s + 4 + ln].decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# TFLite (.tflite) -- FlatBuffers, file identifier "TFL3"
# ---------------------------------------------------------------------------
_TFLITE_TYPE = {
    0: "float32", 1: "float16", 2: "int32", 3: "uint8", 4: "int64",
    5: "string", 6: "bool", 7: "int16", 8: "complex64", 9: "int8",
    10: "float64", 11: "complex128", 12: "uint64", 13: "resource",
    14: "variant", 15: "uint32", 16: "uint16", 17: "int4",
}


def read_tflite(path: Path, max_tensors: int = 5000) -> Dict[str, Any]:
    """Decode a TensorFlow Lite flatbuffer into version / subgraph / tensor info."""
    data = Path(path).read_bytes()
    out: Dict[str, Any] = {"format": "tflite", "tensors": [], "subgraphs": []}
    if len(data) < 8 or data[4:8] != b"TFL3":
        out["error"] = "missing TFL3 file identifier"
        return out
    fb = FlatBufferReader(data)
    try:
        model = fb.root()
        out["version"] = fb.field_u32(model, 0)
        out["description"] = fb.field_string(model, 3)
        oc_start, oc_len = fb.vector(model, 1)
        out["operator_code_count"] = oc_len
        buf_start, buf_len = fb.vector(model, 4)
        out["buffer_count"] = buf_len

        sg_start, sg_len = fb.vector(model, 2)
        total_tensors = 0
        for si in range(sg_len):
            sg = fb.vec_table(sg_start, si)
            t_start, t_len = fb.vector(sg, 0)
            in_start, in_len = fb.vector(sg, 1)
            out_start, out_len = fb.vector(sg, 2)
            op_start, op_len = fb.vector(sg, 3)
            sg_info = {
                "name": fb.field_string(sg, 4),
                "tensor_count": t_len,
                "input_count": in_len,
                "output_count": out_len,
                "operator_count": op_len,
            }
            out["subgraphs"].append(sg_info)
            for ti in range(t_len):
                if total_tensors >= max_tensors:
                    break
                t = fb.vec_table(t_start, ti)
                sh_start, sh_len = fb.vector(t, 0)
                shape = [fb.vec_i32(sh_start, k) for k in range(sh_len)]
                type_id = fb.field_u8(t, 1)
                out["tensors"].append({
                    "name": fb.field_string(t, 3) or f"subgraph{si}_tensor{ti}",
                    "dtype": _TFLITE_TYPE.get(type_id, f"type{type_id}"),
                    "shape": shape,
                    "subgraph": si,
                })
                total_tensors += 1
        out["tensor_count"] = total_tensors
    except Exception as err:  # bounded: return whatever decoded plus the reason
        out["error"] = f"flatbuffer walk failed: {err}"
    return out


# ---------------------------------------------------------------------------
# ONNX Runtime (.ort) -- FlatBuffers, file identifier "ORTM"
# ---------------------------------------------------------------------------
# InferenceSession { ort_version:string(0); model:Model(1); }
# Model { ir_version:int64(0); opset_import:[OpSetId](1); producer_name:string(2);
#         producer_version:string(3); domain:string(4); model_version:int64(5);
#         doc_string:string(6); graph:Graph(7); metadata_props:[..](8); }
# Graph { initializers:[Tensor](0); node_args:[ValueInfo](1); nodes:[Node](2);
#         max_node_index:uint(3); node_edges:[..](4); inputs:[string](5);
#         outputs:[string](6); sparse_initializers:[..](7); }
# Tensor { name:string(0); doc_string:string(1); dims:[int64](2);
#          data_type:int32(3); raw_data:[uint8](4); string_data:[string](5); }
_ONNX_TYPE = {
    0: "undefined", 1: "float32", 2: "uint8", 3: "int8", 4: "uint16", 5: "int16",
    6: "int32", 7: "int64", 8: "string", 9: "bool", 10: "float16", 11: "float64",
    12: "uint32", 13: "uint64", 14: "complex64", 15: "complex128", 16: "bfloat16",
}


def read_ort(path: Path, max_tensors: int = 5000) -> Dict[str, Any]:
    """Decode an ONNX Runtime (.ort) flatbuffer into model/graph/tensor info."""
    data = Path(path).read_bytes()
    out: Dict[str, Any] = {"format": "ort", "tensors": []}
    if len(data) < 8 or data[4:8] != b"ORTM":
        out["error"] = "missing ORTM file identifier"
        return out
    fb = FlatBufferReader(data)
    try:
        sess = fb.root()
        out["ort_version"] = fb.field_string(sess, 0)
        model = fb.field_table(sess, 1)
        if not model:
            out["error"] = "no Model table"
            return out
        out["ir_version"] = fb.field_i64(model, 0)
        out["producer_name"] = fb.field_string(model, 2)
        out["producer_version"] = fb.field_string(model, 3)
        out["domain"] = fb.field_string(model, 4)
        out["model_version"] = fb.field_i64(model, 5)
        op_start, op_len = fb.vector(model, 1)
        out["opset_count"] = op_len

        graph = fb.field_table(model, 7)
        if not graph:
            out["error"] = "no Graph table"
            return out
        init_start, init_len = fb.vector(graph, 0)
        _, node_len = fb.vector(graph, 2)
        _, in_len = fb.vector(graph, 5)
        _, out_len = fb.vector(graph, 6)
        out["node_count"] = node_len
        out["input_count"] = in_len
        out["output_count"] = out_len
        out["initializer_count"] = init_len

        for i in range(min(init_len, max_tensors)):
            t = fb.vec_table(init_start, i)
            d_start, d_len = fb.vector(t, 2)
            dims = [fb.vec_i64(d_start, k) for k in range(d_len)]
            dtype_id = fb.field_offset(t, 3)
            dtype_id = fb.i32(dtype_id) if dtype_id else 0
            out["tensors"].append({
                "name": fb.field_string(t, 0) or f"initializer{i}",
                "dtype": _ONNX_TYPE.get(dtype_id, f"type{dtype_id}"),
                "shape": dims,
            })
        out["tensor_count"] = len(out["tensors"])
    except Exception as err:
        out["error"] = f"flatbuffer walk failed: {err}"
    return out


# ============================================================================
# Minimal msgpack decoder (used by .flax) with flax ndarray ext support
# ============================================================================
class NDArrayInfo:
    """A decoded flax/numpy array leaf: shape + dtype + byte length only."""
    __slots__ = ("shape", "dtype", "nbytes")

    def __init__(self, shape, dtype, nbytes):
        self.shape = list(shape) if shape is not None else []
        self.dtype = dtype
        self.nbytes = nbytes


# flax._MsgpackExtType: ndarray=1, native_complex=2, npscalar=3
def _decode_flax_ext(code: int, payload: bytes):
    try:
        inner, _ = _mp_unpack(payload, 0)
    except Exception:
        return None
    if code == 1 and isinstance(inner, (list, tuple)) and len(inner) == 3:
        shape, dtype, raw = inner
        nbytes = len(raw) if isinstance(raw, (bytes, bytearray)) else None
        return NDArrayInfo(shape, dtype, nbytes)
    if code == 3:  # numpy scalar: (dtype, bytes)
        if isinstance(inner, (list, tuple)) and len(inner) == 2:
            return NDArrayInfo([], inner[0], len(inner[1]) if isinstance(inner[1], (bytes, bytearray)) else None)
    return inner  # native_complex / unknown -> hand back decoded payload


def _mp_unpack(b: bytes, i: int):
    """Decode one msgpack value at ``b[i:]``; return ``(value, next_index)``."""
    c = b[i]; i += 1
    if c <= 0x7f:
        return c, i
    if c >= 0xe0:
        return c - 0x100, i
    if 0x80 <= c <= 0x8f:
        return _mp_map(b, i, c & 0x0f)
    if 0x90 <= c <= 0x9f:
        return _mp_array(b, i, c & 0x0f)
    if 0xa0 <= c <= 0xbf:
        n = c & 0x1f
        return b[i:i + n].decode("utf-8", "replace"), i + n
    if c == 0xc0:
        return None, i
    if c == 0xc2:
        return False, i
    if c == 0xc3:
        return True, i
    if c in (0xc4, 0xc5, 0xc6):  # bin8/16/32
        sz = {0xc4: 1, 0xc5: 2, 0xc6: 4}[c]
        n = int.from_bytes(b[i:i + sz], "big"); i += sz
        return bytes(b[i:i + n]), i + n
    if c in (0xc7, 0xc8, 0xc9):  # ext8/16/32
        sz = {0xc7: 1, 0xc8: 2, 0xc9: 4}[c]
        n = int.from_bytes(b[i:i + sz], "big"); i += sz
        code = struct.unpack_from("<b", b, i)[0]; i += 1
        payload = bytes(b[i:i + n]); i += n
        return _decode_flax_ext(code, payload), i
    if c == 0xca:
        return struct.unpack_from(">f", b, i)[0], i + 4
    if c == 0xcb:
        return struct.unpack_from(">d", b, i)[0], i + 8
    if c in (0xcc, 0xcd, 0xce, 0xcf):  # uint 8/16/32/64
        sz = {0xcc: 1, 0xcd: 2, 0xce: 4, 0xcf: 8}[c]
        return int.from_bytes(b[i:i + sz], "big"), i + sz
    if c in (0xd0, 0xd1, 0xd2, 0xd3):  # int 8/16/32/64
        sz = {0xd0: 1, 0xd1: 2, 0xd2: 4, 0xd3: 8}[c]
        return int.from_bytes(b[i:i + sz], "big", signed=True), i + sz
    if c in (0xd4, 0xd5, 0xd6, 0xd7, 0xd8):  # fixext 1/2/4/8/16
        n = {0xd4: 1, 0xd5: 2, 0xd6: 4, 0xd7: 8, 0xd8: 16}[c]
        code = struct.unpack_from("<b", b, i)[0]; i += 1
        payload = bytes(b[i:i + n]); i += n
        return _decode_flax_ext(code, payload), i
    if c in (0xd9, 0xda, 0xdb):  # str8/16/32
        sz = {0xd9: 1, 0xda: 2, 0xdb: 4}[c]
        n = int.from_bytes(b[i:i + sz], "big"); i += sz
        return b[i:i + n].decode("utf-8", "replace"), i + n
    if c in (0xdc, 0xdd):  # array16/32
        sz = {0xdc: 2, 0xdd: 4}[c]
        n = int.from_bytes(b[i:i + sz], "big"); i += sz
        return _mp_array(b, i, n)
    if c in (0xde, 0xdf):  # map16/32
        sz = {0xde: 2, 0xdf: 4}[c]
        n = int.from_bytes(b[i:i + sz], "big"); i += sz
        return _mp_map(b, i, n)
    raise ValueError(f"unknown msgpack byte 0x{c:02x}")


def _mp_array(b, i, n):
    out = []
    for _ in range(n):
        v, i = _mp_unpack(b, i)
        out.append(v)
    return out, i


def _mp_map(b, i, n):
    out = {}
    for _ in range(n):
        k, i = _mp_unpack(b, i)
        v, i = _mp_unpack(b, i)
        out[k] = v
    return out, i


def read_flax(path: Path, max_tensors: int = 20000) -> Dict[str, Any]:
    """Decode a flax msgpack checkpoint into a flat list of parameter tensors."""
    data = Path(path).read_bytes()
    out: Dict[str, Any] = {"format": "flax", "tensors": []}
    tree: Any
    try:
        import msgpack  # optional fast path with flax's own ext handling
        try:
            from flax.serialization import msgpack_restore  # type: ignore
            tree = msgpack_restore(data)
            _walk_flax_native(tree, out["tensors"], max_tensors)
            out["tensor_count"] = len(out["tensors"])
            return out
        except Exception:
            pass
    except Exception:
        pass
    try:
        tree, _ = _mp_unpack(data, 0)
    except Exception as err:
        out["error"] = f"msgpack decode failed: {err}"
        return out
    _walk_flax(tree, "", out["tensors"], max_tensors)
    out["tensor_count"] = len(out["tensors"])
    return out


def _walk_flax(node, prefix, tensors, limit):
    if len(tensors) >= limit:
        return
    if isinstance(node, NDArrayInfo):
        tensors.append({"name": prefix or "param", "dtype": node.dtype,
                        "shape": node.shape, "nbytes": node.nbytes})
    elif isinstance(node, dict):
        for k, v in node.items():
            key = k.decode() if isinstance(k, bytes) else str(k)
            _walk_flax(v, f"{prefix}/{key}" if prefix else key, tensors, limit)
    elif isinstance(node, (list, tuple)):
        for idx, v in enumerate(node):
            _walk_flax(v, f"{prefix}[{idx}]", tensors, limit)


def _walk_flax_native(node, tensors, limit, prefix=""):
    """Walk the tree produced by flax's own restore (leaves are numpy arrays)."""
    if len(tensors) >= limit:
        return
    if hasattr(node, "shape") and hasattr(node, "dtype"):
        tensors.append({
            "name": prefix or "param",
            "dtype": str(node.dtype),
            "shape": list(node.shape),
            "nbytes": int(getattr(node, "nbytes", 0)) or None,
        })
    elif isinstance(node, dict):
        for k, v in node.items():
            key = k.decode() if isinstance(k, bytes) else str(k)
            _walk_flax_native(v, tensors, limit, f"{prefix}/{key}" if prefix else key)
    elif isinstance(node, (list, tuple)):
        for idx, v in enumerate(node):
            _walk_flax_native(v, tensors, limit, f"{prefix}[{idx}]")


# ============================================================================
# Protocol Buffers wire format (used by .pb and tf.train.Example in .tfrecord)
# ============================================================================
def _read_varint(b: bytes, i: int) -> Tuple[int, int]:
    shift = 0
    result = 0
    while True:
        byte = b[i]; i += 1
        result |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return result, i
        shift += 7
        if shift > 70:
            raise ValueError("varint too long")


def iter_pb_fields(b: bytes, start: int = 0, end: Optional[int] = None):
    """Yield ``(field_number, wire_type, value, next_index)`` for a protobuf message.

    ``value`` is an int for varint/32/64-bit fields, or a ``(offset, length)`` slice
    for length-delimited fields (wire type 2). Nothing is materialised beyond the
    tag; payloads are handed back as slices for the caller to descend into.
    """
    if end is None:
        end = len(b)
    i = start
    while i < end:
        tag, i = _read_varint(b, i)
        field_no = tag >> 3
        wire = tag & 0x07
        if wire == 0:
            val, i = _read_varint(b, i)
            yield field_no, wire, val, i
        elif wire == 1:
            yield field_no, wire, struct.unpack_from("<Q", b, i)[0], i + 8
            i += 8
        elif wire == 2:
            ln, i = _read_varint(b, i)
            yield field_no, wire, (i, ln), i + ln
            i += ln
        elif wire == 5:
            yield field_no, wire, struct.unpack_from("<I", b, i)[0], i + 4
            i += 4
        else:
            raise ValueError(f"unsupported wire type {wire}")


def pb_field_census(b: bytes) -> Dict[int, Dict[str, Any]]:
    """Top-level field census of a protobuf message: per field-number counts/types."""
    census: Dict[int, Dict[str, Any]] = {}
    for fno, wire, val, _ in iter_pb_fields(b):
        rec = census.setdefault(fno, {"wire_type": wire, "count": 0, "total_bytes": 0})
        rec["count"] += 1
        if wire == 2:
            rec["total_bytes"] += val[1]
    return census


def decode_graphdef(b: bytes, max_nodes: int = 200000) -> Optional[Dict[str, Any]]:
    """
    Interpret ``b`` as a TensorFlow ``GraphDef`` (field 1 = repeated ``NodeDef``,
    with NodeDef.name=1, NodeDef.op=2) or ``SavedModel`` (field 2 = meta_graphs).
    Returns node/op statistics, or ``None`` if it does not look like a graph.
    """
    node_count = 0
    op_hist: Dict[str, int] = {}
    saw_savedmodel = False
    try:
        for fno, wire, val, _ in iter_pb_fields(b):
            if fno == 2 and wire == 2:
                saw_savedmodel = True  # SavedModel.meta_graphs
            if fno == 1 and wire == 2:  # GraphDef.node (repeated NodeDef)
                off, ln = val
                name = op = None
                for nfno, nwire, nval, _ in iter_pb_fields(b, off, off + ln):
                    if nwire != 2:
                        continue
                    noff, nln = nval
                    text = b[noff:noff + nln]
                    if nfno == 1:
                        name = text.decode("utf-8", "replace")
                    elif nfno == 2:
                        op = text.decode("utf-8", "replace")
                if op is not None or name is not None:
                    node_count += 1
                    if op:
                        op_hist[op] = op_hist.get(op, 0) + 1
                    if node_count >= max_nodes:
                        break
    except Exception:
        if node_count == 0:
            return None
    if node_count == 0 and not saw_savedmodel:
        return None
    top_ops = sorted(op_hist.items(), key=lambda kv: (-kv[1], kv[0]))[:20]
    return {
        "node_count": node_count,
        "distinct_ops": len(op_hist),
        "top_ops": top_ops,
        "likely_savedmodel": saw_savedmodel and node_count == 0,
    }


def decode_example_features(b: bytes, off: int, ln: int, max_features: int = 2000):
    """
    Decode a ``tf.train.Example`` (or SequenceExample) message slice into a list of
    ``(feature_name, kind, value_count)``. Example.features=1 -> Features.feature=1
    (map<string,Feature>) -> MapEntry.key=1 / value=2 -> Feature.{bytes|float|int64}.
    """
    _KIND = {1: "bytes_list", 2: "float_list", 3: "int64_list"}
    features: List[Tuple[str, str, int]] = []
    try:
        # Example -> features (field 1)
        feats_off = feats_ln = None
        for fno, wire, val, _ in iter_pb_fields(b, off, off + ln):
            if fno == 1 and wire == 2:
                feats_off, feats_ln = val
                break
        if feats_off is None:
            return features
        # Features -> feature map entries (field 1, repeated)
        for fno, wire, val, _ in iter_pb_fields(b, feats_off, feats_off + feats_ln):
            if fno != 1 or wire != 2:
                continue
            eoff, eln = val
            key = None
            kind = None
            vcount = 0
            for efno, ewire, eval_, _ in iter_pb_fields(b, eoff, eoff + eln):
                if efno == 1 and ewire == 2:  # key
                    koff, kln = eval_
                    key = b[koff:koff + kln].decode("utf-8", "replace")
                elif efno == 2 and ewire == 2:  # value: Feature
                    voff, vln = eval_
                    for ffno, fwire, fval, _ in iter_pb_fields(b, voff, voff + vln):
                        if fwire == 2 and ffno in _KIND:
                            kind = _KIND[ffno]
                            loff, lln = fval
                            # count entries in the *_list submessage (field 1 repeated)
                            vcount = sum(
                                1 for _ in iter_pb_fields(b, loff, loff + lln)
                            )
            if key is not None:
                features.append((key, kind or "unknown", vcount))
                if len(features) >= max_features:
                    break
    except Exception:
        pass
    return features


# ---------------------------------------------------------------------------
# TFRecord (.tfrecord / .tfrecords) -- length-prefixed record framing
# ---------------------------------------------------------------------------
def read_tfrecord(path: Path, max_records: int = 5_000_000,
                  max_scan_bytes: int = 512 * 1024 * 1024) -> Dict[str, Any]:
    """
    Walk a TFRecord stream (``uint64 len`` | ``crc32 len`` | ``data`` | ``crc32 data``)
    to count records and decode the first record's ``tf.train.Example`` features.
    Transparently handles a whole-file gzip wrapper.
    """
    data = Path(path).read_bytes()
    out: Dict[str, Any] = {"format": "tfrecord", "features": []}
    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)
            out["compression"] = "gzip"
        except Exception as err:
            out["error"] = f"gzip decompress failed: {err}"
            return out
    n = len(data)
    i = 0
    count = 0
    first = None
    try:
        while i + 12 <= n and i < max_scan_bytes:
            length = struct.unpack_from("<Q", data, i)[0]
            payload = i + 12
            if payload + length + 4 > n:
                out["truncated"] = True
                break
            if count == 0:
                first = (payload, length)
            count += 1
            i = payload + length + 4
            if count >= max_records:
                out["truncated"] = True
                break
    except Exception as err:
        out["error"] = f"framing failed at byte {i}: {err}"
    out["record_count"] = count
    if first is not None:
        feats = decode_example_features(data, first[0], first[1])
        out["features"] = [{"name": k, "kind": kind, "value_count": vc}
                           for (k, kind, vc) in feats]
        out["feature_count"] = len(feats)
    return out


# ---------------------------------------------------------------------------
# Keras v3 (.keras) -- zip of config.json + metadata.json + model.weights.h5
# ---------------------------------------------------------------------------
def read_keras(path: Path, max_layers: int = 5000) -> Dict[str, Any]:
    """Decode a Keras v3 archive: model architecture (config) + weights presence."""
    out: Dict[str, Any] = {"format": "keras", "layers": [], "tensors": []}
    if not zipfile.is_zipfile(path):
        out["error"] = "not a zip (legacy .keras/.h5 not supported here)"
        return out
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
            out["members"] = sorted(names)
            if "metadata.json" in names:
                try:
                    meta = json.loads(zf.read("metadata.json").decode("utf-8"))
                    out["keras_version"] = meta.get("keras_version")
                    out["date_saved"] = meta.get("date_saved")
                except Exception:
                    pass
            if "config.json" in names:
                try:
                    cfg = json.loads(zf.read("config.json").decode("utf-8"))
                    out["model_class"] = cfg.get("class_name")
                    inner = cfg.get("config", {}) if isinstance(cfg, dict) else {}
                    out["model_name"] = inner.get("name")
                    layers = inner.get("layers", []) if isinstance(inner, dict) else []
                    for ly in layers[:max_layers]:
                        lc = ly.get("config", {}) if isinstance(ly, dict) else {}
                        out["layers"].append({
                            "name": lc.get("name"),
                            "class_name": ly.get("class_name") if isinstance(ly, dict) else None,
                        })
                    out["layer_count"] = len(layers)
                except Exception as err:
                    out["config_error"] = str(err)
            weights = [m for m in names if m.endswith(".h5") or m.endswith(".weights.h5")]
            out["weights_files"] = weights
            if weights:
                try:
                    out["weights_bytes"] = sum(zf.getinfo(m).file_size for m in weights)
                except Exception:
                    pass
                _extract_keras_weights(zf, weights, out, max_layers)
    except Exception as err:
        out["error"] = f"keras archive read failed: {err}"
    return out


def _extract_keras_weights(zf, weights, out, limit):
    """List weight tensors from the bundled HDF5 file when h5py is available."""
    try:
        import h5py  # optional: real per-weight tensor listing
        import io
    except Exception:
        return
    for member in weights:
        try:
            with h5py.File(io.BytesIO(zf.read(member)), "r") as h5:
                def visit(name, obj):
                    if isinstance(obj, h5py.Dataset) and len(out["tensors"]) < limit:
                        out["tensors"].append({
                            "name": name,
                            "dtype": str(obj.dtype),
                            "shape": list(obj.shape),
                            "nbytes": int(obj.nbytes),
                        })
                h5.visititems(visit)
        except Exception:
            continue
    out["tensor_count"] = len(out["tensors"])


# ============================================================================
# GGUF (llama.cpp) -- magic "GGUF"; header + metadata KV table + tensor table.
# Layout (little-endian): magic(4) | version(u32) | tensor_count | kv_count |
# kv_count * KV{ key:gguf_str, value_type:u32, value } |
# tensor_count * TensorInfo{ name:gguf_str, n_dims:u32, dims[n_dims]:u64,
#                            ggml_type:u32, offset:u64 }.
# gguf_str = length:u64 + bytes (u32 on the extinct v1). Counts are u64 on v2/v3.
# We read only the info table -- never the (padded) weight blob that follows it --
# and SKIP large metadata arrays (e.g. token vocabularies) without materialising.
# ============================================================================
# GGUF metadata value types.
_GGUF_T_U8, _GGUF_T_I8, _GGUF_T_U16, _GGUF_T_I16 = 0, 1, 2, 3
_GGUF_T_U32, _GGUF_T_I32, _GGUF_T_F32, _GGUF_T_BOOL = 4, 5, 6, 7
_GGUF_T_STRING, _GGUF_T_ARRAY = 8, 9
_GGUF_T_U64, _GGUF_T_I64, _GGUF_T_F64 = 10, 11, 12

# fixed-width scalar value types -> struct format
_GGUF_SCALAR = {
    _GGUF_T_U8: "<B", _GGUF_T_I8: "<b", _GGUF_T_U16: "<H", _GGUF_T_I16: "<h",
    _GGUF_T_U32: "<I", _GGUF_T_I32: "<i", _GGUF_T_F32: "<f", _GGUF_T_BOOL: "<B",
    _GGUF_T_U64: "<Q", _GGUF_T_I64: "<q", _GGUF_T_F64: "<d",
}

# ggml tensor storage types -> readable dtype names (quantised block types kept
# with their canonical names; unknown ids surface as ggml_type_<n>).
_GGML_TYPE = {
    0: "F32", 1: "F16", 2: "Q4_0", 3: "Q4_1", 6: "Q5_0", 7: "Q5_1",
    8: "Q8_0", 9: "Q8_1", 10: "Q2_K", 11: "Q3_K", 12: "Q4_K", 13: "Q5_K",
    14: "Q6_K", 15: "Q8_K", 16: "IQ2_XXS", 17: "IQ2_XS", 18: "IQ3_XXS",
    19: "IQ1_S", 20: "IQ4_NL", 21: "IQ3_S", 22: "IQ2_S", 23: "IQ4_XS",
    24: "I8", 25: "I16", 26: "I32", 27: "I64", 28: "F64", 29: "IQ1_M",
    30: "BF16",
}

# metadata keys worth surfacing as scalar properties (everything else is skipped;
# arrays are always skipped by content and only their length is noted).
_GGUF_KEEP_KEYS = (
    "general.architecture", "general.name", "general.quantization_version",
    "general.file_type", "general.basename", "general.size_label",
    ".context_length", ".embedding_length", ".block_count",
    ".attention.head_count", ".attention.head_count_kv", ".feed_forward_length",
    ".vocab_size", ".rope.dimension_count", "tokenizer.ggml.model",
)


class _GgufReader:
    def __init__(self, data: bytes, str_len_fmt: str, count_fmt: str):
        self.d = data
        self.i = 0
        self.n = len(data)
        self._slf = str_len_fmt          # "<Q" (v2/v3) or "<I" (v1)
        self._sls = struct.calcsize(str_len_fmt)
        self._cf = count_fmt
        self._cs = struct.calcsize(count_fmt)

    def _need(self, k: int):
        if self.i + k > self.n:
            raise ValueError("truncated GGUF")

    def u32(self) -> int:
        self._need(4); v = struct.unpack_from("<I", self.d, self.i)[0]; self.i += 4
        return v

    def count(self) -> int:
        self._need(self._cs)
        v = struct.unpack_from(self._cf, self.d, self.i)[0]; self.i += self._cs
        return v

    def u64(self) -> int:
        self._need(8); v = struct.unpack_from("<Q", self.d, self.i)[0]; self.i += 8
        return v

    def gstr(self) -> str:
        self._need(self._sls)
        ln = struct.unpack_from(self._slf, self.d, self.i)[0]; self.i += self._sls
        self._need(ln)
        s = self.d[self.i:self.i + ln].decode("utf-8", "replace"); self.i += ln
        return s

    def scalar(self, vtype: int):
        fmt = _GGUF_SCALAR.get(vtype)
        if fmt is None:
            raise ValueError(f"bad scalar type {vtype}")
        sz = struct.calcsize(fmt)
        self._need(sz)
        v = struct.unpack_from(fmt, self.d, self.i)[0]; self.i += sz
        if vtype == _GGUF_T_BOOL:
            return bool(v)
        return v

    def skip_value(self, vtype: int):
        """Advance past a metadata value of any type without materialising it."""
        if vtype == _GGUF_T_STRING:
            self.gstr()
        elif vtype == _GGUF_T_ARRAY:
            elem_t = self.u32()
            cnt = self.count()
            if elem_t == _GGUF_T_STRING:
                for _ in range(cnt):
                    self.gstr()
            elif elem_t == _GGUF_T_ARRAY:
                for _ in range(cnt):
                    self.skip_value(_GGUF_T_ARRAY)
            else:
                fmt = _GGUF_SCALAR.get(elem_t)
                if fmt is None:
                    raise ValueError(f"bad array elem type {elem_t}")
                self.i += struct.calcsize(fmt) * cnt
                self._need(0)
        else:
            self.scalar(vtype)


def read_gguf(path: Path, max_tensors: int = 100000) -> Dict[str, Any]:
    """Decode a GGUF header + metadata KV table + tensor info table.

    Returns version / tensor_count / metadata_kv_count, a small dict of surfaced
    scalar metadata, and one entry per tensor {name, shape, dtype, offset}. Only
    the info table is read; the weight blob and large metadata arrays are skipped.
    """
    data = Path(path).read_bytes()
    out: Dict[str, Any] = {"format": "gguf", "tensors": [], "metadata": {}}
    if len(data) < 24 or data[:4] != b"GGUF":
        out["error"] = "missing GGUF magic"
        return out
    version = struct.unpack_from("<I", data, 4)[0]
    out["version"] = version
    # v1 used u32 counts + u32 string lengths; v2/v3 use u64 for both.
    if version == 1:
        str_fmt, cnt_fmt, hdr = "<I", "<I", 4 + 4 + 4 + 4
    else:
        str_fmt, cnt_fmt, hdr = "<Q", "<Q", 4 + 4 + 8 + 8
    r = _GgufReader(data, str_fmt, cnt_fmt)
    r.i = 4 + 4  # past magic + version
    try:
        tensor_count = r.count()
        kv_count = r.count()
    except Exception as err:
        out["error"] = f"gguf header parse failed: {err}"
        return out
    out["tensor_count"] = int(tensor_count)
    out["metadata_kv_count"] = int(kv_count)
    # --- metadata KV table: capture selected scalars, skip everything else -----
    try:
        for _ in range(kv_count):
            key = r.gstr()
            vtype = r.u32()
            keep = any(key == k or key.endswith(k) for k in _GGUF_KEEP_KEYS)
            if vtype == _GGUF_T_ARRAY:
                save = r.i
                elem_t = r.u32()
                alen = r.count()
                r.i = save
                r.skip_value(vtype)
                if keep:
                    out["metadata"][key] = f"[array elem_type={elem_t} len={alen}]"
            elif keep and vtype != _GGUF_T_STRING:
                out["metadata"][key] = r.scalar(vtype)
            elif keep and vtype == _GGUF_T_STRING:
                out["metadata"][key] = r.gstr()[:256]
            else:
                r.skip_value(vtype)
    except Exception as err:
        out["error"] = f"gguf metadata parse failed after {len(out['metadata'])} keys: {err}"
        return out
    # --- tensor info table -----------------------------------------------------
    try:
        n = min(int(tensor_count), max_tensors)
        for _ in range(n):
            name = r.gstr()
            n_dims = r.u32()
            dims = [r.u64() for _ in range(n_dims)]
            ggml_type = r.u32()
            offset = r.u64()
            # GGUF stores dims fastest-varying-first; reverse to row-major shape.
            shape = [int(x) for x in reversed(dims)]
            out["tensors"].append({
                "name": name,
                "shape": shape,
                "dtype": _GGML_TYPE.get(ggml_type, f"ggml_type_{ggml_type}"),
                "offset": int(offset),
            })
        out["tensors_listed"] = len(out["tensors"])
        if n < int(tensor_count):
            out["truncated"] = True
    except Exception as err:
        out["error"] = f"gguf tensor table parse failed after {len(out['tensors'])} tensors: {err}"
    return out
