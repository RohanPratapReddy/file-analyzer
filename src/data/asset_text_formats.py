"""Real, dependency-free structure parsers for the *text-based asset* file
families catalogued in ``src/tables/file_extensions.json`` that route
to the DataAnalyzer plane but had no dedicated handler:

* shader source (GLSL/HLSL/Metal/Cg/OSL/RenderMan/WGSL/ShaderLab/Unreal)
    -> #version, stage, uniforms/ins/outs/samplers/textures/bindings, functions
* ML-model text (state_dict dump / onnxtxt / NCNN .param / TVM Relay / H2O POJO
    / ARPA .lm / NeRF config)  -> layers, tensors, op census
* vector graphics (Sketch .sk / sK1 .sk1 / Excalidraw)  -> element census
* geospatial world files (.pgw/.wld/.j2w)  -> 6 affine coefficients
* RTTTL ringtones (.rtttl/.rtx)  -> tempo/octave/note census
* VTK XML grids (.vtr RectilinearGrid / .vts StructuredGrid)  -> extent + arrays

Every parser reads the *real* grammar and reports *real* counts.  Binary or
malformed input degrades to honest generic text metrics (line/word/char/
encoding) — never a stub, never fabricated records.  ``analyze(path, ext)`` is
the single entry point and never raises.

Return contract mirrors ``catalog_text_formats._ok`` and additionally may carry
``tensors`` (list of {name, dtype, shape, num_bytes, extra}) and
``model_layers`` (list of {layer_name, layer_type, ordinal, ...}) that the
DataAnalyzer handler materialises into data_tensors_table / data_model_layers.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

from .catalog_text_formats import _ok, _read_text, generic_text_metrics

# ---------------------------------------------------------------------------
# ext -> family map
# ---------------------------------------------------------------------------
_SHADER_EXTS = {
    ".cg",
    ".cginc",
    ".frag",
    ".geom",
    ".glsl",
    ".hlsl",
    ".metal",
    ".osl",
    ".rsl",
    ".shader",
    ".tesc",
    ".tese",
    ".ush",
    ".vert",
    ".wgsl",
}
_MLMODEL_EXTS = {
    ".state_dict",
    ".onnxtxt",
    ".param",
    ".relay",
    ".pojo",
    ".lm",
    ".nerf",
}
_VECTOR_EXTS = {".sk", ".sk1", ".excalidraw"}
_WORLDFILE_EXTS = {".pgw", ".wld", ".j2w"}
_RINGTONE_EXTS = {".rtttl", ".rtx"}
_VTK_EXTS = {".vtr", ".vts"}

FAMILY_OF: Dict[str, str] = {}
for _e in _SHADER_EXTS:
    FAMILY_OF[_e] = "shader"
for _e in _MLMODEL_EXTS:
    FAMILY_OF[_e] = "ml_model"
for _e in _VECTOR_EXTS:
    FAMILY_OF[_e] = "vector_graphics"
for _e in _WORLDFILE_EXTS:
    FAMILY_OF[_e] = "geospatial_worldfile"
for _e in _RINGTONE_EXTS:
    FAMILY_OF[_e] = "ringtone"
for _e in _VTK_EXTS:
    FAMILY_OF[_e] = "vtk_grid"
del _e


def known_exts() -> set:
    return set(FAMILY_OF)


# ===========================================================================
# shaders
# ===========================================================================
_SHADER_LANG = {
    ".vert": "glsl",
    ".frag": "glsl",
    ".geom": "glsl",
    ".tesc": "glsl",
    ".tese": "glsl",
    ".glsl": "glsl",
    ".hlsl": "hlsl",
    ".ush": "hlsl",
    ".metal": "metal",
    ".cg": "cg",
    ".cginc": "cg",
    ".osl": "osl",
    ".rsl": "renderman",
    ".shader": "shaderlab",
    ".wgsl": "wgsl",
}
_SHADER_STAGE_BY_EXT = {
    ".vert": "vertex",
    ".frag": "fragment",
    ".geom": "geometry",
    ".tesc": "tessellation_control",
    ".tese": "tessellation_evaluation",
}


def _strip_shader_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    src = re.sub(r"//[^\n]*", "", src)
    return src


_GLSL_VAR = re.compile(
    r"(?m)^\s*(?:layout\s*\([^)]*\)\s*)?"
    r"(uniform|attribute|varying|buffer|shared|const|in|out)\s+"
    r"(?:(?:flat|smooth|noperspective|centroid|highp|mediump|lowp)\s+)*"
    r"([A-Za-z_]\w*)\s+([A-Za-z_]\w*)"
)
_GLSL_FUNC = re.compile(
    r"(?m)^\s*(?:[A-Za-z_]\w*\s+)*([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{"
)
_WGSL_BIND = re.compile(
    r"@group\((\d+)\)\s*@binding\((\d+)\)\s*var(?:<[^>]*>)?\s+([A-Za-z_]\w*)\s*:\s*([\w<>,\s]+?)\s*;"
)
_WGSL_FN = re.compile(r"(?m)^\s*(?:@\w+(?:\([^)]*\))?\s*)*fn\s+([A-Za-z_]\w*)\s*\(")
_HLSL_RES = re.compile(
    r"(?m)^\s*(cbuffer|Texture\w*|RWTexture\w*|SamplerState|SamplerComparisonState|"
    r"StructuredBuffer|RWStructuredBuffer|ByteAddressBuffer|Buffer)\s*(?:<[^>]*>)?\s+([A-Za-z_]\w*)"
)
_METAL_ATTR = re.compile(r"\[\[\s*(buffer|texture|sampler)\s*\(\s*(\d+)\s*\)\s*\]\]")


def _parse_shader(text: str, ext: str) -> Dict[str, Any]:
    lang = _SHADER_LANG.get(ext, "glsl")
    src = _strip_shader_comments(text)
    props: Dict[str, Any] = {"language": lang}
    columns: List[Dict[str, Any]] = []

    m = re.search(r"#version\s+(\d+)\s*([A-Za-z]+)?", src)
    if m:
        props["glsl_version"] = int(m.group(1))
        if m.group(2):
            props["glsl_profile"] = m.group(2)
    props["pragma_count"] = len(re.findall(r"(?m)^\s*#pragma\b", src))
    props["include_count"] = len(re.findall(r"(?m)^\s*#include\b", src))
    props["define_count"] = len(re.findall(r"(?m)^\s*#define\b", src))

    functions: List[str] = []
    uniforms = ins = outs = samplers = textures = bindings = 0
    entrypoints: List[str] = []

    if lang == "wgsl":
        for grp, binding, name, ty in _WGSL_BIND.findall(src):
            bindings += 1
            ty = ty.strip()
            columns.append(
                {"name": name, "dtype": ty, "qualifier": f"group{grp}/binding{binding}"}
            )
            if "sampler" in ty:
                samplers += 1
            elif "texture" in ty:
                textures += 1
            else:
                uniforms += 1
        functions = _WGSL_FN.findall(src)
        for st in ("vertex", "fragment", "compute"):
            if re.search(r"@%s\b" % st, src):
                entrypoints.append(st)
    elif lang in ("hlsl", "cg", "shaderlab"):
        for kind, name in _HLSL_RES.findall(src):
            columns.append({"name": name, "dtype": kind, "qualifier": "resource"})
            if kind == "cbuffer":
                uniforms += 1
            elif kind.startswith("Sampler"):
                samplers += 1
            elif "Texture" in kind:
                textures += 1
        bindings = len(re.findall(r":\s*register\s*\(", src))
        functions = [f[1] for f in _GLSL_FUNC.findall(src)]
        for st, tag in (
            ("vertex", "vertex"),
            ("fragment", "fragment"),
            ("geometry", "geometry"),
            ("compute", "kernel"),
        ):
            if re.search(r"#pragma\s+%s\b" % tag, src):
                entrypoints.append(st)
    elif lang == "metal":
        for kind, idx in _METAL_ATTR.findall(src):
            bindings += 1
            if kind == "sampler":
                samplers += 1
            elif kind == "texture":
                textures += 1
        for kw in ("vertex", "fragment", "kernel"):
            for fm in re.finditer(
                r"(?m)^\s*%s\s+[\w:<>,\s\*&]+?\s+([A-Za-z_]\w*)\s*\(" % kw, src
            ):
                entrypoints.append(fm.group(1))
        functions = [f[1] for f in _GLSL_FUNC.findall(src)]
    elif lang in ("osl", "renderman"):
        for mm in re.finditer(
            r"(?m)^\s*(shader|surface|displacement|light|volume)\s+([A-Za-z_]\w*)", src
        ):
            entrypoints.append(mm.group(2))
        for mm in re.finditer(
            r"\b(output\s+)?(color|point|vector|normal|float|int|string|matrix)\s+([A-Za-z_]\w*)\s*[=,)\[]",
            src,
        ):
            columns.append(
                {
                    "name": mm.group(3),
                    "dtype": mm.group(2),
                    "qualifier": "output" if mm.group(1) else "param",
                }
            )
            if mm.group(1):
                outs += 1
        functions = [f[1] for f in _GLSL_FUNC.findall(src)]
    else:  # glsl-family
        for qual, ty, name in _GLSL_VAR.findall(src):
            columns.append({"name": name, "dtype": ty, "qualifier": qual})
            if qual == "uniform":
                if ty.startswith("sampler"):
                    samplers += 1
                elif ty.startswith(("image", "texture")):
                    textures += 1
                else:
                    uniforms += 1
            elif qual == "in":
                ins += 1
            elif qual == "out":
                outs += 1
        bindings = len(re.findall(r"layout\s*\([^)]*binding\s*=", src))
        functions = [f[1] for f in _GLSL_FUNC.findall(src)]
        if re.search(r"\bvoid\s+main\s*\(", src):
            entrypoints.append("main")

    stage = _SHADER_STAGE_BY_EXT.get(ext)
    if stage is None:
        if "vertex" in entrypoints:
            stage = "vertex"
        elif "fragment" in entrypoints:
            stage = "fragment"
        elif "compute" in entrypoints or "kernel" in " ".join(entrypoints):
            stage = "compute"
        else:
            stage = "unknown"

    props.update(
        {
            "stage": stage,
            "function_count": len(functions),
            "uniform_count": uniforms,
            "input_count": ins,
            "output_count": outs,
            "sampler_count": samplers,
            "texture_count": textures,
            "binding_count": bindings,
            "declaration_count": len(columns),
            "entrypoints": ",".join(dict.fromkeys(entrypoints)) or None,
            "line_count": text.count("\n") + 1,
        }
    )
    return _ok(
        "shader",
        "code",
        "shader_source",
        props,
        record_count=len(columns),
        columns=columns or None,
    )


# ===========================================================================
# ML-model text formats
# ===========================================================================
def _parse_ncnn_param(text: str) -> Dict[str, Any]:
    """NCNN .param: optional magic 7767517, then 'layer_count blob_count',
    then one line per layer: <type> <name> <in> <out> [ids...] [k=v...]."""
    lines = [l for l in text.splitlines() if l.strip()]
    idx = 0
    magic = None
    if lines and lines[0].strip() == "7767517":
        magic = 7767517
        idx = 1
    header = lines[idx].split() if idx < len(lines) else []
    layer_count = blob_count = None
    if len(header) == 2 and all(t.isdigit() for t in header):
        layer_count, blob_count = int(header[0]), int(header[1])
        idx += 1
    layers: List[Dict[str, Any]] = []
    type_hist: Dict[str, int] = {}
    for ln in lines[idx:]:
        parts = ln.split()
        if len(parts) < 2:
            continue
        ltype, lname = parts[0], parts[1]
        type_hist[ltype] = type_hist.get(ltype, 0) + 1
        layers.append(
            {"layer_name": lname, "layer_type": ltype, "ordinal": len(layers)}
        )
    props = {
        "format": "NCNN param",
        "magic": magic,
        "declared_layer_count": layer_count,
        "declared_blob_count": blob_count,
        "parsed_layer_count": len(layers),
        "distinct_layer_types": len(type_hist),
        "layer_type_histogram": type_hist or None,
    }
    return {
        "props": props,
        "record_count": len(layers),
        "model_layers": layers,
        "subcategory": "ncnn_param",
        "status": "ok",
    }


_ARPA_NGRAM = re.compile(r"(?m)^\s*ngram\s+(\d+)\s*=\s*(\d+)")


def _parse_arpa(text: str) -> Dict[str, Any]:
    """ARPA language model: \\data\\ section with 'ngram N=count' lines."""
    if "\\data\\" not in text:
        return {}
    orders = _ARPA_NGRAM.findall(text[:65536])
    counts = {int(o): int(c) for o, c in orders}
    sections = re.findall(r"(?m)^\\(\d+)-grams:", text)
    props = {
        "format": "ARPA n-gram LM",
        "max_order": max(counts) if counts else None,
        "ngram_counts": counts or None,
        "total_ngrams": sum(counts.values()) if counts else None,
        "gram_sections": len(sections),
    }
    cols = [{"name": f"{o}-gram", "dtype": "int"} for o in sorted(counts)]
    return {
        "props": props,
        "record_count": sum(counts.values()) if counts else 0,
        "columns": cols or None,
        "subcategory": "arpa_lm",
        "status": "ok",
    }


_STATE_DICT_LINE = re.compile(
    r"([\w.]+)\s*[:=\t]\s*(?:torch\.)?(?:Size|Parameter|Tensor)?\s*[\(\[]+\s*([\d,\sxX*]+?)\s*[\)\]]+"
)


def _parse_state_dict_text(text: str) -> Dict[str, Any]:
    """A printed torch state_dict: 'key : torch.Size([d0, d1, ...])' lines."""
    tensors: List[Dict[str, Any]] = []
    layer_tensors: Dict[str, List[Dict[str, Any]]] = {}
    for key, shape_s in _STATE_DICT_LINE.findall(text):
        dims = [int(d) for d in re.split(r"[,\sxX*]+", shape_s.strip()) if d]
        if not dims:
            continue
        t = {"name": key, "dtype": None, "shape": dims, "num_bytes": None, "extra": {}}
        tensors.append(t)
        parent = key.rsplit(".", 1)[0] if "." in key else key
        layer_tensors.setdefault(parent, []).append(t)
    if not tensors:
        return {}
    layers: List[Dict[str, Any]] = []
    for i, (lname, ts) in enumerate(layer_tensors.items()):
        total = 0
        for t in ts:
            n = 1
            for d in t["shape"]:
                n *= d
            total += n
        layers.append(
            {
                "layer_name": lname,
                "layer_type": "module",
                "ordinal": i,
                "tensor_count": len(ts),
                "total_parameters": total,
            }
        )
    props = {
        "format": "torch state_dict (text)",
        "tensor_count": len(tensors),
        "layer_count": len(layers),
        "total_parameters": sum(l["total_parameters"] for l in layers),
    }
    return {
        "props": props,
        "record_count": len(tensors),
        "tensors": tensors,
        "model_layers": layers,
        "subcategory": "state_dict",
        "status": "ok",
    }


def _parse_onnxtxt(text: str) -> Dict[str, Any]:
    """ONNX in text form: protobuf text (op_type: "X") or printable graph
    (%out = OpType(...))."""
    op_hist: Dict[str, int] = {}
    node_count = 0
    for op in re.findall(r'op_type:\s*"([^"]+)"', text):
        op_hist[op] = op_hist.get(op, 0) + 1
        node_count += 1
    if node_count == 0:  # printable_graph style
        for op in re.findall(r"=\s*([A-Za-z_]\w*)\s*\(", text):
            op_hist[op] = op_hist.get(op, 0) + 1
            node_count += 1
    inputs = len(re.findall(r"(?m)^\s*input\s*(?:\{|:)", text))
    outputs = len(re.findall(r"(?m)^\s*output\s*(?:\{|:)", text))
    inits = len(re.findall(r"(?m)^\s*initializer\s*\{", text))
    gname = re.search(r'name:\s*"([^"]+)"', text)
    props = {
        "format": "ONNX text",
        "graph_name": gname.group(1) if gname else None,
        "node_count": node_count,
        "input_count": inputs or None,
        "output_count": outputs or None,
        "initializer_count": inits or None,
        "distinct_ops": len(op_hist),
        "op_histogram": op_hist or None,
    }
    cols = [{"name": op, "dtype": "op"} for op in sorted(op_hist)]
    return {
        "props": props,
        "record_count": node_count,
        "columns": cols or None,
        "subcategory": "onnx_text",
        "status": "ok",
    }


def _parse_relay(text: str) -> Dict[str, Any]:
    """TVM Relay IR text: def @fn(...), operator calls (nn.conv2d(...))."""
    funcs = re.findall(r"def\s+@([\w.]+)\s*\(", text)
    ver = re.search(r'#\[version\s*=\s*"([^"]+)"\]', text)
    ops: Dict[str, int] = {}
    for op in re.findall(r"\b([a-zA-Z_][\w]*(?:\.[\w]+)+)\s*\(", text):
        ops[op] = ops.get(op, 0) + 1
    var_count = len(set(re.findall(r"%[\w.]+", text)))
    props = {
        "format": "TVM Relay IR",
        "relay_version": ver.group(1) if ver else None,
        "function_count": len(funcs),
        "var_count": var_count,
        "op_call_count": sum(ops.values()),
        "distinct_ops": len(ops),
        "op_histogram": ops or None,
    }
    cols = [{"name": f, "dtype": "relay_fn"} for f in funcs]
    return {
        "props": props,
        "record_count": len(funcs),
        "columns": cols or None,
        "subcategory": "tvm_relay",
        "status": "ok",
    }


def _parse_pojo(text: str) -> Dict[str, Any]:
    """H2O POJO: generated Java GenModel with per-tree static methods/arrays."""
    classes = re.findall(
        r"(?m)^\s*(?:public\s+|final\s+|abstract\s+)*class\s+(\w+)", text
    )
    main_class = classes[0] if classes else None
    trees = len(re.findall(r"\bclass\s+\w*_Tree_\w*", text)) + len(
        re.findall(r"\bstatic\s+final\s+void\s+\w*Tree\w*\s*\(", text)
    )
    methods = len(
        re.findall(
            r"(?m)^\s*(?:public|private|protected|static|final|\s)+"
            r"[\w\[\]<>]+\s+(\w+)\s*\([^)]*\)\s*\{",
            text,
        )
    )
    arrays = len(re.findall(r"static\s+final\s+\w+\s*\[\s*\]", text))
    is_h2o = "GenModel" in text or "hex.genmodel" in text or "EasyPredict" in text
    props = {
        "format": "H2O POJO (Java)",
        "model_class": main_class,
        "class_count": len(classes),
        "method_count": methods,
        "static_array_count": arrays,
        "tree_count": trees or None,
        "h2o_genmodel": is_h2o,
    }
    return {
        "props": props,
        "record_count": len(classes),
        "subcategory": "h2o_pojo",
        "status": "ok",
    }


def _parse_nerf(text: str) -> Dict[str, Any]:
    """NeRF config/transforms: JSON scene (camera intrinsics + frames) or
    training config."""
    try:
        obj = json.loads(text)
    except ValueError:
        m = generic_text_metrics(text)
        m["format"] = "NeRF config (non-JSON)"
        return {
            "props": m,
            "record_count": m["line_count"],
            "subcategory": "nerf_config",
            "status": "partial",
        }
    props: Dict[str, Any] = {"format": "NeRF/instant-ngp config"}
    frames = None
    if isinstance(obj, dict):
        for k in (
            "camera_angle_x",
            "fl_x",
            "fl_y",
            "cx",
            "cy",
            "w",
            "h",
            "aabb_scale",
            "n_levels",
            "resolution",
        ):
            if k in obj:
                props[k] = obj[k]
        fr = obj.get("frames")
        if isinstance(fr, list):
            frames = len(fr)
            props["frame_count"] = frames
        props["top_level_keys"] = len(obj)
    elif isinstance(obj, list):
        frames = len(obj)
        props["frame_count"] = frames
    return {
        "props": props,
        "record_count": frames if frames is not None else 0,
        "subcategory": "nerf_config",
        "status": "ok",
    }


def _parse_mlmodel(text: str, ext: str) -> Dict[str, Any]:
    res: Dict[str, Any] = {}
    if ext == ".param":
        res = _parse_ncnn_param(text)
    elif ext == ".lm":
        res = _parse_arpa(text)
    elif ext == ".state_dict":
        res = _parse_state_dict_text(text)
    elif ext == ".onnxtxt":
        res = _parse_onnxtxt(text)
    elif ext == ".relay":
        res = _parse_relay(text)
    elif ext == ".pojo":
        res = _parse_pojo(text)
    elif ext == ".nerf":
        res = _parse_nerf(text)
    if not res:  # unrecognised content -> honest generic metrics
        m = generic_text_metrics(text)
        m["format"] = f"ml-model text ({ext})"
        res = {
            "props": m,
            "record_count": m["line_count"],
            "subcategory": "ml_model_text",
            "status": "partial",
        }
    out = _ok(
        "ml_model",
        "tensor",
        res.get("subcategory", "ml_model_text"),
        res["props"],
        record_count=res.get("record_count"),
        columns=res.get("columns"),
        status=res.get("status", "ok"),
    )
    if res.get("tensors"):
        out["tensors"] = res["tensors"]
    if res.get("model_layers"):
        out["model_layers"] = res["model_layers"]
    return out


# ===========================================================================
# vector graphics
# ===========================================================================
def _parse_vector(text: str, ext: str) -> Dict[str, Any]:
    if ext == ".excalidraw":
        try:
            obj = json.loads(text)
        except ValueError:
            m = generic_text_metrics(text)
            m["format"] = "Excalidraw (non-JSON)"
            return _ok(
                "vector_graphics",
                "image",
                "vector_scene_partial",
                m,
                record_count=m["line_count"],
                status="partial",
            )
        elements = obj.get("elements", []) if isinstance(obj, dict) else []
        type_hist: Dict[str, int] = {}
        for el in elements:
            t = str(el.get("type", "unknown")) if isinstance(el, dict) else "unknown"
            type_hist[t] = type_hist.get(t, 0) + 1
        props = {
            "format": "Excalidraw scene",
            "schema_type": obj.get("type") if isinstance(obj, dict) else None,
            "schema_version": obj.get("version") if isinstance(obj, dict) else None,
            "element_count": len(elements),
            "distinct_element_types": len(type_hist),
            "element_histogram": type_hist or None,
        }
        cols = [{"name": t, "dtype": "element"} for t in sorted(type_hist)]
        return _ok(
            "vector_graphics",
            "image",
            "vector_scene",
            props,
            record_count=len(elements),
            columns=cols or None,
        )
    # Sketch / sK1 vector drawings.  sK1 (.sk / .sk1) are Python-ish text
    # drawing scripts (layer(), b(), bp(), ...); real Sketch .sketch files are
    # zip and never reach here (routed to archive).  Parse the command census.
    layers = len(re.findall(r"(?m)^\s*layer\s*\(", text))
    beziers = len(re.findall(r"(?m)^\s*b\s*\(", text)) + len(
        re.findall(r"(?m)^\s*bp\s*\(", text)
    )
    rects = len(re.findall(r"(?m)^\s*r\s*\(", text))
    ellipses = len(re.findall(r"(?m)^\s*(?:e|el)\s*\(", text))
    groups = len(re.findall(r"(?m)^\s*(?:G|guidelayer|G\s*\()\s*", text))
    header = None
    first = text.lstrip()[:64]
    if first.startswith("##sK1"):
        header = "sK1 1.0"
    elif first.startswith("##Sketch"):
        header = first.splitlines()[0].strip()
    props = {
        "format": header or "Sketch/sK1 vector script",
        "layer_count": layers,
        "bezier_count": beziers,
        "rect_count": rects,
        "ellipse_count": ellipses,
        "group_count": groups,
        "object_count": layers + beziers + rects + ellipses,
    }
    return _ok(
        "vector_graphics",
        "image",
        "vector_drawing",
        props,
        record_count=props["object_count"],
    )


# ===========================================================================
# geospatial world files
# ===========================================================================
def _parse_worldfile(text: str, ext: str) -> Dict[str, Any]:
    """ESRI world file: 6 lines A, D, B, E, C, F (pixel size / rotation /
    upper-left pixel-center coordinates)."""
    vals: List[float] = []
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            vals.append(float(ln))
        except ValueError:
            break
    if len(vals) < 6:
        m = generic_text_metrics(text)
        m["format"] = "world file (incomplete)"
        m["values_parsed"] = len(vals)
        return _ok(
            "geospatial",
            "geospatial",
            "world_file_partial",
            m,
            record_count=len(vals),
            status="partial",
        )
    a, d, b, e, c, f = vals[:6]
    props = {
        "format": "ESRI world file",
        "pixel_size_x": a,
        "rotation_y": d,
        "rotation_x": b,
        "pixel_size_y": e,
        "origin_x": c,
        "origin_y": f,
        "has_rotation": bool(d or b),
        "coefficient_count": 6,
    }
    cols = [
        {"name": n, "dtype": "float"}
        for n in (
            "A_pixel_size_x",
            "D_rotation_y",
            "B_rotation_x",
            "E_pixel_size_y",
            "C_origin_x",
            "F_origin_y",
        )
    ]
    return _ok(
        "geospatial", "geospatial", "world_file", props, record_count=6, columns=cols
    )


# ===========================================================================
# RTTTL ringtones
# ===========================================================================
_RTTTL_NOTE = re.compile(r"\d*\.?[a-gpA-GP]#?\d*\.?")


def _parse_ringtone(text: str, ext: str) -> Dict[str, Any]:
    """RTTTL: name:defaults:notes  (defaults = d=<dur>,o=<octave>,b=<bpm>)."""
    body = text.strip()
    parts = body.split(":")
    if len(parts) < 3:
        m = generic_text_metrics(text)
        m["format"] = "RTTTL (malformed)"
        return _ok(
            "ringtone",
            "audio",
            "rtttl_partial",
            m,
            record_count=m["line_count"],
            status="partial",
        )
    name = parts[0].strip()
    defaults = parts[1].strip()
    notes_s = ":".join(parts[2:])
    dflt = {}
    for kv in defaults.split(","):
        if "=" in kv:
            k, v = kv.split("=", 1)
            dflt[k.strip().lower()] = v.strip()
    notes = [n for n in (x.strip() for x in notes_s.split(",")) if n]
    props = {
        "format": "RTTTL",
        "tune_name": name or None,
        "default_duration": _int_or_none(dflt.get("d")),
        "default_octave": _int_or_none(dflt.get("o")),
        "bpm": _int_or_none(dflt.get("b")),
        "note_count": len(notes),
        "first_notes": ",".join(notes[:8]) or None,
    }
    return _ok("ringtone", "audio", "rtttl", props, record_count=len(notes))


def _int_or_none(v: Optional[str]) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ===========================================================================
# VTK XML grids
# ===========================================================================
def _parse_vtk(text: str, ext: str) -> Dict[str, Any]:
    """VTK XML: .vtr RectilinearGrid / .vts StructuredGrid.  Reads WholeExtent,
    dimensions, and DataArray descriptors (name/type/components)."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        m = generic_text_metrics(text)
        m["format"] = "VTK XML (unparsable)"
        return _ok(
            "model_3d",
            "three_d",
            "vtk_partial",
            m,
            record_count=m["line_count"],
            status="partial",
        )

    def _local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    vtk_type = root.attrib.get("type")
    version = root.attrib.get("version")
    byte_order = root.attrib.get("byte_order")
    grid = None
    for child in root:
        if _local(child.tag) in (
            "RectilinearGrid",
            "StructuredGrid",
            "ImageData",
            "UnstructuredGrid",
            "PolyData",
        ):
            grid = child
            break
    whole_extent = grid.attrib.get("WholeExtent") if grid is not None else None
    dims = None
    npoints = None
    if whole_extent:
        try:
            ex = [int(x) for x in whole_extent.split()]
            dims = [ex[1] - ex[0] + 1, ex[3] - ex[2] + 1, ex[5] - ex[4] + 1]
            npoints = dims[0] * dims[1] * dims[2]
        except (ValueError, IndexError):
            pass
    tensors: List[Dict[str, Any]] = []
    columns: List[Dict[str, Any]] = []
    point_arrays = cell_arrays = 0
    for da in root.iter():
        if _local(da.tag) != "DataArray":
            continue
        name = da.attrib.get("Name") or f"array{len(columns)}"
        dtype = da.attrib.get("type")
        comps = _int_or_none(da.attrib.get("NumberOfComponents")) or 1
        parent_tag = ""  # classify by nearest named container is non-trivial in ET
        columns.append(
            {"name": name, "dtype": dtype or "unknown", "qualifier": f"{comps}c"}
        )
        shape = [npoints, comps] if npoints else [comps]
        tensors.append(
            {
                "name": name,
                "dtype": dtype,
                "shape": shape,
                "num_bytes": None,
                "extra": {"components": comps},
            }
        )
    # count PointData/CellData arrays for honest reporting
    for container in root.iter():
        lt = _local(container.tag)
        if lt == "PointData":
            point_arrays += sum(1 for c in container if _local(c.tag) == "DataArray")
        elif lt == "CellData":
            cell_arrays += sum(1 for c in container if _local(c.tag) == "DataArray")
    props = {
        "format": f"VTK XML {vtk_type or _local(grid.tag) if grid is not None else 'grid'}",
        "vtk_type": vtk_type,
        "version": version,
        "byte_order": byte_order,
        "whole_extent": whole_extent,
        "dimensions": dims,
        "point_count": npoints,
        "data_array_count": len(columns),
        "point_data_arrays": point_arrays or None,
        "cell_data_arrays": cell_arrays or None,
    }
    out = _ok(
        "model_3d",
        "three_d",
        "vtk_grid",
        props,
        record_count=npoints if npoints is not None else len(columns),
        columns=columns or None,
    )
    if tensors:
        out["tensors"] = tensors
    return out


# ===========================================================================
# entry point
# ===========================================================================
_PARSERS = {
    "shader": _parse_shader,
    "ml_model": _parse_mlmodel,
    "vector_graphics": _parse_vector,
    "geospatial_worldfile": _parse_worldfile,
    "ringtone": _parse_ringtone,
    "vtk_grid": _parse_vtk,
}


def analyze(path: Any, ext: str) -> Dict[str, Any]:
    """Single entry point.  Never raises; degrades to real generic text metrics
    rather than a stub."""
    p = Path(path)
    base = ("." + ext.split(".")[-1]) if ext else ext
    fam = FAMILY_OF.get(ext) or FAMILY_OF.get(base)
    lead = ext if ext in FAMILY_OF else base
    try:
        text, encoding, truncated = _read_text(p)
    except Exception as err:
        return _ok(
            fam or "asset",
            "text",
            "asset_unreadable",
            {"format": "unreadable", "error": str(err)[:120]},
            status="partial",
        )
    if fam is None:
        m = generic_text_metrics(text)
        m["format"] = "generic text"
        return _ok("asset", "text", "plain_text", m, record_count=m["line_count"])
    try:
        result = _PARSERS[fam](text, lead)
    except Exception as err:
        m = generic_text_metrics(text)
        m.update({"format": f"{fam} (fallback)", "parse_error": str(err)[:120]})
        return _ok(
            fam,
            "text",
            f"{fam}_partial",
            m,
            record_count=m["line_count"],
            status="partial",
        )
    result["props"].setdefault("encoding", encoding)
    if truncated:
        result["props"]["scan_truncated"] = True
        if result["status"] == "ok":
            result["status"] = "partial"
    return result
