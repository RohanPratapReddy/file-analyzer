# Auto-extracted from code_analyzer.py (verbatim class body).
import ast
import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from ..core.guardrails import scrub


class DataAnalyzer:
    """
    Profiles *data* artifacts (as opposed to source code or schema definitions)
    and emits a normalized, relational description of what each file contains --
    its structure, column/tensor shapes, per-column statistics and inter-column
    relations (correlation) -- **without ever storing the raw payload**.

    The guiding constraint: this is an *analysis*, not a copy. A 100 GB parquet
    file is described by its row count, column list, dtypes, a capped statistical
    sample and pairwise correlations, never by ingesting its contents. Every
    handler therefore reads only file metadata / headers or a bounded sample.

    Coverage (routed by extension via ``docs/file_formats.json``):
      * Tabular -- CSV/TSV/PSV/... , Parquet/ORC/Arrow/Feather, Excel/ODS,
        JSON / JSON-Lines record sets, SQLite databases, Stata/SAS/SPSS.
        -> columns, dtypes, exact-or-sampled row counts, per-column stats
           (null/unique counts, min/max/mean/std, value samples) and
           numeric pairwise correlations.
      * Tensors / models -- .safetensors, .npy/.npz, PyTorch .pt/.pth/.ckpt,
        .gguf, .onnx. -> tensor names, dtypes, shapes, element/byte counts.
      * Images -- raster & vector via Pillow. -> format, mode, dimensions,
        channels, frame counts, embedded metadata.
      * Audio -- WAV/AIFF headers. -> channels, sample rate, bit depth, duration.
      * Video -- containers via OpenCV metadata. -> resolution, fps, frame
        count, duration, codec.
      * Documents -- PDF (pypdf), DOCX (zip+XML), plain text / markdown / rST.
        -> page/paragraph/line/word/char counts and document metadata.
      * Serialization -- pickle / joblib (opcode scan, **no code execution**).
      * Everything else -> a generic descriptor (size + magic bytes + catalog
        classification).

    Output tables (dicts of lists), each row keyed by a stable integer id:
      data_datasets_table    dataset_id, dataset_name, category, subcategory,
                             modality, file_format, format_family, size_bytes,
                             row_count, column_count, record_count,
                             tensor_count, analysis_status, notes,
                             properties[dict], file_id
      data_columns_table     column_id, dataset_id, column_name, ordinal,
                             data_type, inferred_type, null_count,
                             non_null_count, unique_count, min_value,
                             max_value, mean_value, std_value,
                             sample_values[list], extra[dict], file_id
      data_tensors_table     tensor_id, dataset_id, tensor_name, dtype,
                             shape[list], rank, num_elements, num_bytes,
                             extra[dict], file_id
      data_relations_table   relation_id, dataset_id, relation_type,
                             left_column, right_column, value, method,
                             extra[dict], file_id
      data_properties_table  property_id, dataset_id, property_name,
                             property_value, value_type, group_name, file_id
      data_file_index        dfi_id, file_id, entity_kind, entity_id
                             (populated by ``link_repository``)

    IDs are 1-based and disjoint per entity kind. Each entity row starts with a
    LOCAL ``file_id`` (1-based index into the analyzed file list). Calling
    :meth:`link_repository` with the tuple returned by
    ``RepositoryAnalyzer.generate()`` rewrites every ``file_id`` to the matching
    repository ``file_details.file_id`` and populates ``data_file_index`` so the
    data layer plugs straight into ``RepositoryDatabaseGenerator`` beside the
    code-intelligence and schema tables.
    """

    # ---- entity-kind labels used in data_file_index -------------------
    KIND_DATASET = "dataset"
    KIND_COLUMN = "data_column"
    KIND_TENSOR = "tensor"
    KIND_RELATION = "relation"
    KIND_PROPERTY = "property"
    KIND_MODEL_LAYER = "model_layer"

    # ---- bounded-analysis budgets (never store the whole payload) -----
    SAMPLE_ROWS = 10000  # rows pulled into memory for stats/correlation
    MAX_COLUMNS = 4096  # widest table we will profile column-by-column
    MAX_SAMPLE_VALUES = 5  # distinct value samples kept per column
    SAMPLE_VALUE_CHARS = 64  # each sample value truncated to this length
    CORR_MAX_COLS = 60  # numeric cols considered for correlation
    CORR_MIN_ABS = 0.30  # only keep |r| >= this
    CORR_MAX_RELATIONS = 500  # cap correlation rows per dataset
    MAX_JSON_BYTES = 64 * 1024 * 1024  # full-load ceiling for .json
    MAX_TEXT_SCAN_BYTES = 32 * 1024 * 1024  # byte budget for text word counts
    MAX_PICKLE_OPS = 200000  # opcode-scan ceiling for pickle files
    MAX_DB_TABLES = 500  # tables profiled per embedded sqlite database
    MAX_STRUCT_SCAN_BYTES = 512 * 1024 * 1024  # streamed line/record-count ceiling
    MAX_STRUCT_TEXT_BYTES = (
        128 * 1024 * 1024
    )  # full-text load ceiling (XML/JSON structs)
    MAX_GEOM_VERTS = (
        5_000_000  # vertices sampled for a bounding box (count stays exact)
    )

    # ---- curated extension routing (checked before catalog fallback) --
    _EXT_DELIM = {
        ".csv": ",",
        ".tsv": "\t",
        ".tab": "\t",
        ".psv": "|",
        ".ssv": " ",
        ".scsv": ";",
        ".dsv": None,
        ".dat": None,
        ".prn": None,
        ".rec": None,
    }
    _EXT_PARQUET = {".parquet", ".pqt", ".parq"}
    _EXT_ORC = {".orc"}
    _EXT_ARROW = {".arrow", ".ipc", ".feather"}
    _EXT_EXCEL = {".xls", ".xlsx", ".xlsm", ".xltx", ".xltm", ".ods"}
    _EXT_JSON_REC = {".json", ".jsonl", ".ndjson"}
    _EXT_SQLITE = {".db", ".db3", ".sqlite", ".sqlite3", ".s3db"}
    _EXT_STAT = {".dta", ".sav", ".por", ".sas7bdat", ".xpt"}
    _EXT_SAFETENSORS = {".safetensors"}
    _EXT_NPY = {".npy"}
    _EXT_NPZ = {".npz"}
    _EXT_TORCH = {".pt", ".pth", ".ckpt", ".pt2"}
    _EXT_GGUF = {".gguf"}
    _EXT_ONNX = {".onnx"}
    # ONNX Runtime ordinal format is a FlatBuffers container ("ORTM"), NOT the
    # ONNX protobuf -- it needs its own decoder, so it is kept out of _EXT_ONNX.
    _EXT_ORT = {".ort"}
    # TensorFlow Lite -- FlatBuffers ("TFL3") model graphs.
    _EXT_TFLITE = {".tflite", ".lite"}
    # Keras v3 archives (zip of config.json/metadata.json/model.weights.h5).
    _EXT_KERAS = {".keras"}
    # Flax / JAX msgpack parameter checkpoints.
    _EXT_FLAX = {".flax", ".msgpack"}
    # TFRecord example streams (length-prefixed tf.train.Example protobufs).
    _EXT_TFRECORD = {".tfrecord", ".tfrecords", ".tfrec"}
    # Raw Protocol Buffers payloads (TF GraphDef / SavedModel / generic).
    _EXT_PB = {".pb", ".pbtxt", ".graphdef"}
    _EXT_WAV = {".wav", ".wave", ".bwf"}
    # Common raster/vector image containers Pillow can open lazily. Catalog
    # category=="image" also routes here; this set makes image handling work
    # even when the docs catalog is absent.
    _EXT_IMAGE = {
        ".png",
        ".jpg",
        ".jpeg",
        ".jpe",
        ".jfif",
        ".bmp",
        ".dib",
        ".gif",
        ".tif",
        ".tiff",
        ".webp",
        ".ppm",
        ".pgm",
        ".pbm",
        ".pnm",
        ".tga",
        ".ico",
        ".icns",
        ".jp2",
        ".j2k",
        ".jpf",
        ".jpx",
        ".heic",
        ".heif",
        ".avif",
        ".dds",
        ".im",
        ".pcx",
        ".sgi",
        ".xbm",
        ".xpm",
        ".msp",
    }
    # Compressed / non-WAV audio. WAV is handled separately (deep PCM parse);
    # these get header-based probing in _handle_audio.
    _EXT_AUDIO = {
        ".mp3",
        ".flac",
        ".ogg",
        ".oga",
        ".opus",
        ".m4a",
        ".m4b",
        ".aac",
        ".wma",
        ".aiff",
        ".aif",
        ".aifc",
        ".ape",
        ".wv",
        ".wvc",
        ".ac3",
        ".dts",
        ".amr",
        ".mka",
        ".ra",
        ".au",
        ".snd",
        ".caf",
        ".mid",
        ".midi",
        ".tta",
        ".mpc",
        ".spx",
        ".shn",
        ".dsf",
        ".dff",
        ".tak",
        ".w64",
    }
    _EXT_PDF = {".pdf"}
    _EXT_DOCX = {".docx", ".docm", ".dotx"}
    _EXT_VIDEO = {
        ".mp4",
        ".m4v",
        ".mov",
        ".qt",
        ".mkv",
        ".webm",
        ".avi",
        ".flv",
        ".wmv",
        ".mpg",
        ".mpeg",
        ".m2ts",
        ".mts",
        ".ts",
        ".3gp",
        ".ogv",
    }
    _EXT_TEXT = {
        ".txt",
        ".text",
        ".md",
        ".markdown",
        ".mdown",
        ".mkd",
        ".mdx",
        ".rst",
        ".adoc",
        ".asciidoc",
        ".org",
        ".log",
        ".nfo",
        ".rtf",
    }
    _EXT_PICKLE = {".pkl", ".pickle", ".p", ".joblib", ".dill", ".cloudpickle"}
    # 3D / geometry meshes and point clouds -> vertex/face/point counts + bbox.
    _EXT_MESH = {
        ".obj",
        ".mtl",
        ".off",
        ".gltf",
        ".usda",
        ".dae",
        ".x3d",
        ".stl",
        ".ply",
        ".xyz",
        ".pts",
        ".msh",
        ".vtu",
        ".vtp",
        ".vti",
    }
    # Vector geospatial -> feature/geometry counts + CRS + bbox. (.gml is
    # ambiguous with graph-GML and is routed through a content sniff.)
    _EXT_GEO = {
        ".geojson",
        ".topojson",
        ".kml",
        ".gpx",
        ".osm",
        ".wkt",
        ".prj",
    }
    # Config / serialization -> key counts + sections.
    _EXT_CONFIG = {
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".properties",
        ".env",
        ".hcl",
        ".tf",
        ".tfvars",
        ".jsonnet",
        ".libsonnet",
    }
    # Graph / network -> node/edge counts. (.gml -> sniff; shared with _EXT_GEO.)
    _EXT_GRAPH = {
        ".graphml",
        ".gexf",
        ".dot",
        ".gv",
        ".net",
        ".edgelist",
        ".mtx",
        ".mm",
    }
    # Bio / chem sequence & structure -> record/sequence counts.
    _EXT_BIO = {
        ".fasta",
        ".fa",
        ".fna",
        ".ffn",
        ".faa",
        ".frn",
        ".fastq",
        ".fq",
        ".sam",
        ".vcf",
        ".bed",
        ".gff",
        ".gff3",
        ".gtf",
        ".mol",
        ".sdf",
        ".pdb",
    }
    # Geography-vs-Graph Modeling Language collision -> disambiguated by content.
    _EXT_GML = {".gml"}
    # Geospatial raster (GDAL-family). Real header parsers: GeoTIFF (TIFF-IFD +
    # GeoKeyDirectory), ESRI/Arc ASCII grid, GDAL .vrt XML, classic NetCDF.
    # (.tif/.tiff stay in _EXT_IMAGE and get a GeoTIFF sniff inside _handle_image.)
    _EXT_GEORASTER = {
        ".vrt",
        ".asc",
        ".grd",
        ".dem",
        ".ddf",
        ".bil",
        ".bip",
        ".bsq",
        ".flt",
        ".dt0",
        ".dt1",
        ".dt2",
        ".nc",
        ".cdf",
        ".nc4",
    }
    # Medical imaging. Real header parsers: DICOM (technical tags only, no PII),
    # NIfTI-1/2, NRRD, FreeSurfer MGH/MGZ.  (.nii.gz routes to archive via .gz.)
    _EXT_MEDICAL = {
        ".dcm",
        ".dicom",
        ".ima",
        ".nii",
        ".nrrd",
        ".nhdr",
        ".mgh",
        ".mgz",
        ".img",
        ".hdr",
    }
    # Camera raw (rawpy-family). TIFF-based raws share the IFD reader; RAF/CR3/X3F
    # have their own container magics.
    _EXT_RAW = {
        ".cr2",
        ".cr3",
        ".crw",
        ".nef",
        ".nrw",
        ".arw",
        ".sr2",
        ".srf",
        ".dng",
        ".raf",
        ".rw2",
        ".orf",
        ".pef",
        ".ptx",
        ".srw",
        ".3fr",
        ".dcr",
        ".kdc",
        ".mrw",
        ".x3f",
        ".iiq",
        ".mef",
        ".rwl",
        ".erf",
        ".mos",
        ".fff",
        ".gpr",
        ".raw",
    }
    # Point-cloud volumes (open3d/laspy-family). PCD, ASPRS LAS/LAZ, ASTM E57.
    _EXT_POINTCLOUD = {".pcd", ".las", ".laz", ".e57"}

    # Catalogued *text* families with real grammars but no prior handler:
    # subtitles, playlists, RDF/Turtle, SPARQL, iCalendar/vCard, email, LDIF,
    # notebooks, JSON/YAML/XML/HTML/CSS variants, EDI/HL7/X12, bio/molecular
    # text, chess, sensor logs, Gerber, LP/MPS/CNF, sparse matrices, ARFF/libsvm,
    # DIF/SYLK, STEP/IGES/DXF, PostScript, TeX/BibTeX.  Real structure parsers
    # live in catalog_text_formats.py.
    from .catalog_text_formats import known_exts as _catalog_text_known

    _EXT_CATALOG_TEXT = frozenset(_catalog_text_known())
    del _catalog_text_known

    # Catalogued *binary* families: documented-header parsers (FITS, SEG-Y/SAC/
    # miniSEED, GRIB/BUFR, tracker modules, chiptunes, MAT/RDS/ROOT, MD
    # trajectories, TDMS/IBW, pcap/pcapng, git PACK, hprof/JFR, gcov, regf/lnk/
    # evtx/prefetch, Avro/BSON, HDF5, Zarr) plus honest forensic profiling for
    # opaque/proprietary/encrypted artifacts.  Lives in catalog_binary_formats.py.
    from .catalog_binary_formats import known_exts as _catalog_bin_known

    _EXT_CATALOG_BINARY = frozenset(_catalog_bin_known())
    del _catalog_bin_known

    # Catalogued text-based *asset* families with real grammars but no prior
    # handler: shader source (GLSL/HLSL/Metal/Cg/OSL/RSL/WGSL/ShaderLab), ML
    # model text (state_dict dump / onnxtxt / NCNN .param / TVM Relay / H2O
    # POJO / ARPA .lm / NeRF), vector drawings (Sketch/sK1/Excalidraw),
    # geospatial world files, RTTTL ringtones, VTK XML grids.  Real structure
    # parsers live in asset_text_formats.py.
    from .asset_text_formats import known_exts as _asset_known

    _EXT_CATALOG_ASSETS = frozenset(_asset_known())
    del _asset_known

    def __init__(
        self,
        file_paths: List[Union[str, Path]],
        catalog_path: Optional[Union[str, Path]] = None,
        dump_file_path: str = "data_analysis.json",
        dump_file_type: str = "memory",
        *,
        media_metrics: bool = False,
        media_models: bool = False,
        media_models_dir: Optional[Union[str, Path]] = None,
        repo_root: Optional[Union[str, Path]] = None,
    ):
        self.file_paths = [Path(p) for p in file_paths]
        self.dump_file_path = dump_file_path
        self.dump_file_type = dump_file_type.lower()

        # Opt-in deep media analysis: extract weight-free perceptual/DSP metrics
        # (and, if media_models, small downloaded detectors) from media files.
        # Default models dir is tabgen/models/ so a tester can delete it after a run.
        self._media_metrics = bool(media_metrics)
        self._media_models = bool(media_models)
        self._repo_root = repo_root
        if media_models_dir is not None:
            self._media_models_dir = Path(media_models_dir)
        else:
            self._media_models_dir = Path(__file__).resolve().parents[3] / "models"
        self._media_ext = None  # lazily-built MediaMetricExtractor
        self._media_ext_ready = False

        self.data_datasets_table: List[Dict[str, Any]] = []
        self.data_columns_table: List[Dict[str, Any]] = []
        self.data_tensors_table: List[Dict[str, Any]] = []
        self.data_relations_table: List[Dict[str, Any]] = []
        self.data_properties_table: List[Dict[str, Any]] = []
        self.data_model_layers_table: List[Dict[str, Any]] = []
        self.data_file_index: List[Dict[str, Any]] = []

        # per-kind id counters (disjoint)
        self._ids = {
            k: 0
            for k in (
                "dataset",
                "column",
                "tensor",
                "relation",
                "property",
                "model_layer",
                "dfi",
            )
        }

        # extension -> (category, subcategory) routing catalog
        if catalog_path is None:
            # This module lives at tabgen/readers/file_analyzer/data/data_analyzer.py.
            # The master extension catalog now ships inside the package at
            # file_analyzer/tables/file_extensions.json (data/ -> file_analyzer/); the
            # legacy media taxonomy under docs/ is kept as a fallback.
            pkg = Path(__file__).resolve().parents[1]  # file_analyzer/
            docs = Path(__file__).resolve().parents[3] / "docs"
            for candidate in (
                pkg / "tables" / "file_extensions.json",
                docs / "file_formats.json",
                docs / "done" / "file_formats.json",
            ):
                if candidate.is_file():
                    catalog_path = candidate
                    break
            else:
                catalog_path = pkg / "tables" / "file_extensions.json"
        self._catalog_path = Path(catalog_path)
        self._ext_index: Dict[str, Tuple[str, str]] = {}
        self._load_catalog()

    # ------------------------------------------------------------------
    # id helpers
    # ------------------------------------------------------------------
    def _next(self, kind: str) -> int:
        self._ids[kind] += 1
        return self._ids[kind]

    # ------------------------------------------------------------------
    # catalog loading + extension routing
    # ------------------------------------------------------------------
    # master file_extensions.json extension_type -> routing media-category.
    # Only image/audio/video/three_d drive the media handlers; every other
    # type falls back to the byte-level format_class (text vs binary).
    _TYPE_TO_CATEGORY = {
        "image_raster": "image",
        "image_raw": "image",
        "image_vector": "image",
        "medical_imaging": "image",
        "audio": "audio",
        "video": "video",
        "model_3d": "three_d",
    }

    def _load_catalog(self) -> None:
        try:
            with open(self._catalog_path, "r", encoding="utf-8") as f:
                catalog = json.load(f)
        except (OSError, ValueError):
            catalog = {}
        # Master schema: {"metadata": {...}, "extensions": [ {record}, ... ]}
        if isinstance(catalog, dict) and isinstance(catalog.get("extensions"), list):
            for rec in catalog["extensions"]:
                name = str(rec.get("extension_name", "")).lower()
                if not name:
                    continue
                etype = str(rec.get("extension_type", ""))
                fmt = str(rec.get("format_class", "")).lower()
                category = self._TYPE_TO_CATEGORY.get(
                    etype, "text" if fmt == "text" else "binary"
                )
                subcategory = str(rec.get("extension_subdomain") or etype or "unknown")
                # first occurrence wins -> deterministic classification
                self._ext_index.setdefault(name, (category, subcategory))
            return
        # Legacy media taxonomy: {category: {subcategory: [exts]}}
        for category, subs in catalog.items():
            if category == "schema" or not isinstance(subs, dict):
                continue
            for subcategory, exts in subs.items():
                if not isinstance(exts, list):
                    continue
                for ext in exts:
                    key = str(ext).lower()
                    # first occurrence wins -> deterministic classification
                    self._ext_index.setdefault(key, (category, subcategory))

    def _ext_of(self, path: Path) -> str:
        """Return the most specific catalog extension for ``path``.

        Tries progressively shorter compound suffixes (``.tar.gz`` -> ``.gz``)
        so multi-dot data extensions resolve to their catalog entry; falls back
        to the final simple suffix (lower-cased) even if unknown.
        """
        name = path.name.lower()
        parts = name.split(".")
        for i in range(1, len(parts)):
            candidate = "." + ".".join(parts[i:])
            if candidate in self._ext_index or candidate in self._known_exts():
                return candidate
        return ("." + parts[-1]) if len(parts) > 1 else ""

    def _known_exts(self) -> set:
        if not hasattr(self, "_known_ext_cache"):
            known = set()
            for grp in (
                self._EXT_DELIM.keys(),
                self._EXT_PARQUET,
                self._EXT_ORC,
                self._EXT_ARROW,
                self._EXT_EXCEL,
                self._EXT_JSON_REC,
                self._EXT_SQLITE,
                self._EXT_STAT,
                self._EXT_SAFETENSORS,
                self._EXT_NPY,
                self._EXT_NPZ,
                self._EXT_TORCH,
                self._EXT_GGUF,
                self._EXT_ONNX,
                self._EXT_ORT,
                self._EXT_TFLITE,
                self._EXT_KERAS,
                self._EXT_FLAX,
                self._EXT_TFRECORD,
                self._EXT_PB,
                self._EXT_WAV,
                self._EXT_IMAGE,
                self._EXT_AUDIO,
                self._EXT_PDF,
                self._EXT_DOCX,
                self._EXT_VIDEO,
                self._EXT_TEXT,
                self._EXT_PICKLE,
                self._EXT_MESH,
                self._EXT_GEO,
                self._EXT_CONFIG,
                self._EXT_GRAPH,
                self._EXT_BIO,
                self._EXT_GML,
                self._EXT_GEORASTER,
                self._EXT_MEDICAL,
                self._EXT_RAW,
                self._EXT_POINTCLOUD,
                self._EXT_CATALOG_TEXT,
                self._EXT_CATALOG_BINARY,
                self._EXT_CATALOG_ASSETS,
            ):
                known.update(grp)
            self._known_ext_cache = known
        return self._known_ext_cache

    def _classify(self, ext: str) -> Tuple[str, str]:
        return self._ext_index.get(ext, ("unknown", "unknown"))

    def _dispatch(self, ext: str):
        base = ext
        # compound suffixes (.csv.gz) dispatch on their leading data ext
        lead = "." + ext.split(".")[1] if ext.count(".") >= 2 else ext
        for candidate in (base, lead):
            if candidate in self._EXT_DELIM:
                return self._handle_tabular_delimited
        if base in self._EXT_PARQUET or lead in self._EXT_PARQUET:
            return self._handle_parquet
        if base in self._EXT_ORC:
            return self._handle_orc
        if base in self._EXT_ARROW:
            return self._handle_arrow
        if base in self._EXT_EXCEL:
            return self._handle_excel
        if base in self._EXT_JSON_REC:
            return self._handle_json
        if base in self._EXT_SQLITE:
            return self._handle_sqlite
        if base in self._EXT_STAT:
            return self._handle_stat
        if base in self._EXT_SAFETENSORS:
            return self._handle_safetensors
        if base in self._EXT_NPY:
            return self._handle_npy
        if base in self._EXT_NPZ:
            return self._handle_npz
        if base in self._EXT_TORCH:
            return self._handle_torch
        if base in self._EXT_GGUF:
            return self._handle_gguf
        if base in self._EXT_ONNX:
            return self._handle_onnx
        if base in self._EXT_ORT:
            return self._handle_ort
        if base in self._EXT_TFLITE:
            return self._handle_tflite
        if base in self._EXT_KERAS:
            return self._handle_keras
        if base in self._EXT_FLAX:
            return self._handle_flax
        if base in self._EXT_TFRECORD or lead in self._EXT_TFRECORD:
            return self._handle_tfrecord
        if base in self._EXT_PB:
            return self._handle_pb
        if base in self._EXT_WAV:
            return self._handle_wav
        if base in self._EXT_IMAGE:
            return self._handle_image
        if base in self._EXT_AUDIO:
            return self._handle_audio
        if base in self._EXT_PDF:
            return self._handle_pdf
        if base in self._EXT_DOCX:
            return self._handle_docx
        if base in self._EXT_VIDEO or lead in self._EXT_VIDEO:
            return self._handle_video
        if base in self._EXT_PICKLE:
            return self._handle_pickle
        if base in self._EXT_TEXT:
            return self._handle_text
        # scientific / imaging containers (dependency-free header parsers)
        if base in self._EXT_RAW or lead in self._EXT_RAW:
            return self._handle_camera_raw
        if base in self._EXT_MEDICAL or lead in self._EXT_MEDICAL:
            return self._handle_medical
        if base in self._EXT_GEORASTER or lead in self._EXT_GEORASTER:
            return self._handle_georaster
        if base in self._EXT_POINTCLOUD or lead in self._EXT_POINTCLOUD:
            return self._handle_pointcloud
        # structured data/geometry/graph/config/bio families (0-handler exts)
        if base in self._EXT_GML or lead in self._EXT_GML:
            return self._handle_gml_dispatch
        if base in self._EXT_MESH or lead in self._EXT_MESH:
            return self._handle_mesh
        if base in self._EXT_GEO or lead in self._EXT_GEO:
            return self._handle_geospatial
        if base in self._EXT_CONFIG or lead in self._EXT_CONFIG:
            return self._handle_config
        if base in self._EXT_GRAPH or lead in self._EXT_GRAPH:
            return self._handle_graph
        if base in self._EXT_BIO or lead in self._EXT_BIO:
            return self._handle_bio
        # catalogued text-based asset families (shaders, ML-model text, vector
        # drawings, world files, ringtones, VTK grids) — specific grammars, so
        # checked before the generic catalog-text handler
        if base in self._EXT_CATALOG_ASSETS or lead in self._EXT_CATALOG_ASSETS:
            return self._handle_catalog_assets
        # catalogued text families with real grammars but no prior handler
        # (checked after every specific handler above, so existing ones win)
        if base in self._EXT_CATALOG_TEXT or lead in self._EXT_CATALOG_TEXT:
            return self._handle_catalog_text
        # catalogued binary families (documented headers or honest forensics)
        if base in self._EXT_CATALOG_BINARY or lead in self._EXT_CATALOG_BINARY:
            return self._handle_catalog_binary
        # catalog-driven fallbacks
        category, _sub = self._classify(base)
        if category == "image":
            return self._handle_image
        if category == "audio":
            return self._handle_audio
        if category == "video":
            return self._handle_video
        if category == "text":
            return self._handle_text
        return self._handle_generic

    # ==================================================================
    # Public API
    # ==================================================================
    def analyze(self) -> Dict[str, List[Dict[str, Any]]]:
        for local_fid, path in enumerate(self.file_paths, start=1):
            p = Path(path)
            try:
                self._analyze_file(p, local_fid)
            except Exception as err:  # never let one bad file abort the batch
                print(f"Warning: DataAnalyzer failed on {p.name}: {err}")
                continue
        result = self.get_tables()
        if self.dump_file_type != "memory":
            self._export(result)
        return result

    def get_tables(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            "data_datasets_table": self.data_datasets_table,
            "data_columns_table": self.data_columns_table,
            "data_tensors_table": self.data_tensors_table,
            "data_relations_table": self.data_relations_table,
            "data_properties_table": self.data_properties_table,
            "data_model_layers_table": self.data_model_layers_table,
            "data_file_index": self.data_file_index,
        }

    def _analyze_file(self, path: Path, local_fid: int) -> None:
        ext = self._ext_of(path)
        category, subcategory = self._classify(ext)
        handler = self._dispatch(ext)
        start = len(self.data_datasets_table)
        handler(path, ext, category, subcategory, local_fid)
        # opt-in: attach weight-free perceptual/DSP metrics (+ optional detector)
        # to any media dataset the handler just produced for this file.
        if self._media_metrics:
            for ds in self.data_datasets_table[start:]:
                mod = ds.get("modality")
                if mod in ("image", "audio", "video"):
                    self._emit_media_metrics(ds, path, mod, local_fid)

    # ==================================================================
    # Row builders
    # ==================================================================
    def _add_dataset(
        self,
        path: Path,
        ext: str,
        category: str,
        subcategory: str,
        modality: str,
        local_fid: int,
        status: str = "ok",
        notes: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        try:
            size = path.stat().st_size
        except OSError:
            size = None
        row = {
            "dataset_id": self._next("dataset"),
            "dataset_name": path.name,
            "category": category,
            "subcategory": subcategory,
            "modality": modality,
            "file_format": ext.lstrip(".") or None,
            "format_family": category,
            "size_bytes": size,
            "row_count": None,
            "column_count": None,
            "record_count": None,
            "tensor_count": None,
            "analysis_status": status,
            "notes": notes,
            "properties": properties or {},
            "file_id": local_fid,
        }
        self.data_datasets_table.append(row)
        return row

    def _add_column(
        self,
        dataset_id: int,
        name: str,
        ordinal: int,
        data_type: str,
        inferred_type: str,
        null_count: Optional[int],
        non_null_count: Optional[int],
        unique_count: Optional[int],
        min_value: Any,
        max_value: Any,
        mean_value: Optional[float],
        std_value: Optional[float],
        sample_values: List[Any],
        extra: Dict[str, Any],
        local_fid: int,
    ) -> int:
        cid = self._next("column")
        self.data_columns_table.append(
            {
                "column_id": cid,
                "dataset_id": dataset_id,
                "column_name": name,
                "ordinal": ordinal,
                "data_type": data_type,
                "inferred_type": inferred_type,
                "null_count": null_count,
                "non_null_count": non_null_count,
                "unique_count": unique_count,
                "min_value": None if min_value is None else str(min_value)[:256],
                "max_value": None if max_value is None else str(max_value)[:256],
                "mean_value": mean_value,
                "std_value": std_value,
                "sample_values": sample_values,
                "extra": extra or {},
                "file_id": local_fid,
            }
        )
        return cid

    def _add_tensor(
        self,
        dataset_id: int,
        name: str,
        dtype: Optional[str],
        shape: List[int],
        num_bytes: Optional[int],
        extra: Dict[str, Any],
        local_fid: int,
        role: Optional[str] = None,
        layer_name: Optional[str] = None,
    ) -> int:
        shape = list(shape) if shape is not None else []
        num_elem = 1
        for d in shape:
            try:
                num_elem *= int(d)
            except (TypeError, ValueError):
                num_elem = None
                break
        if not shape:
            num_elem = 0 if shape == [] else num_elem
        tid = self._next("tensor")
        self.data_tensors_table.append(
            {
                "tensor_id": tid,
                "dataset_id": dataset_id,
                "tensor_name": name,
                "dtype": dtype,
                "shape": shape,
                "rank": len(shape),
                "num_elements": num_elem,
                "num_bytes": num_bytes,
                # role/layer are populated for model artefacts by _emit_model_layers;
                # None for plain data tensors (npy/raster/point-cloud/...).
                "role": role,
                "layer_name": layer_name,
                "extra": extra or {},
                "file_id": local_fid,
            }
        )
        return tid

    def _add_model_layer(
        self,
        dataset_id: int,
        layer_name: str,
        layer_type: str,
        ordinal: int,
        depth: int,
        tensor_count: int,
        param_tensor_count: int,
        buffer_tensor_count: int,
        total_parameters: Optional[int],
        total_buffer_elements: Optional[int],
        total_bytes: Optional[int],
        dtypes: List[str],
        param_shapes: Dict[str, Any],
        roles: Dict[str, str],
        local_fid: int,
    ) -> int:
        mlid = self._next("model_layer")
        self.data_model_layers_table.append(
            {
                "model_layer_id": mlid,
                "dataset_id": dataset_id,
                "layer_name": layer_name,
                "layer_type": layer_type,
                "ordinal": ordinal,
                "depth": depth,
                "tensor_count": tensor_count,
                "param_tensor_count": param_tensor_count,
                "buffer_tensor_count": buffer_tensor_count,
                "total_parameters": total_parameters,
                "total_buffer_elements": total_buffer_elements,
                "total_bytes": total_bytes,
                "dtypes": dtypes,
                "param_shapes": param_shapes,
                "roles": roles,
                "file_id": local_fid,
            }
        )
        return mlid

    def _add_relation(
        self,
        dataset_id: int,
        relation_type: str,
        left_column: Optional[str],
        right_column: Optional[str],
        value: Optional[float],
        method: Optional[str],
        local_fid: int,
        extra: Optional[Dict[str, Any]] = None,
    ) -> int:
        rid = self._next("relation")
        self.data_relations_table.append(
            {
                "relation_id": rid,
                "dataset_id": dataset_id,
                "relation_type": relation_type,
                "left_column": left_column,
                "right_column": right_column,
                "value": value,
                "method": method,
                "extra": extra or {},
                "file_id": local_fid,
            }
        )
        return rid

    def _add_property(
        self, dataset_id: int, name: str, value: Any, group_name: str, local_fid: int
    ) -> int:
        pid = self._next("property")
        vtype = type(value).__name__
        if isinstance(value, (dict, list)):
            value = json.dumps(value)[:4096]
        elif value is not None:
            value = str(value)[:4096]
        self.data_properties_table.append(
            {
                "property_id": pid,
                "dataset_id": dataset_id,
                "property_name": name,
                "property_value": value,
                "value_type": vtype,
                "group_name": group_name,
                "file_id": local_fid,
            }
        )
        return pid

    def _add_properties(
        self, dataset_id: int, props: Dict[str, Any], group_name: str, local_fid: int
    ) -> None:
        for k, v in props.items():
            if v is None:
                continue
            self._add_property(dataset_id, k, v, group_name, local_fid)

    # ------------------------------------------------------------------
    # model layer/parameter analysis (weights / buffers, per-layer, per-type)
    # ------------------------------------------------------------------
    # Trailing state-dict leaf names whose *parent* is the owning layer/module,
    # each mapped to the parameter role it denotes.
    _PARAM_LEAF_ROLES = {
        "weight": "weight",
        "bias": "bias",
        "weight_g": "weight",
        "weight_v": "weight",
        "gamma": "weight",
        "beta": "bias",
        "in_proj_weight": "weight",
        "in_proj_bias": "bias",
        "q_proj_weight": "weight",
        "k_proj_weight": "weight",
        "v_proj_weight": "weight",
        "lora_a": "weight",
        "lora_b": "weight",
        "running_mean": "buffer",
        "running_var": "buffer",
        "num_batches_tracked": "buffer",
        "inv_freq": "buffer",
        "position_ids": "buffer",
        "token_type_ids": "buffer",
        "causal_mask": "buffer",
        "masked_bias": "buffer",
        "rotary_emb.inv_freq": "buffer",
        "scale": "quant_param",
        "zero_point": "quant_param",
        "weight_scale": "quant_param",
        "weight_zero_point": "quant_param",
        "_packed_params": "quant_param",
    }
    _BUFFER_ROLES = {"buffer"}
    _PARAM_ROLES = {"weight", "bias", "quant_param", "embedding", "other_param"}

    def _classify_param(self, tensor_name: str) -> Tuple[str, str]:
        """(layer_name, role) for a model tensor name.

        Splits the owning module path from the trailing parameter leaf so
        e.g. ``model.layers.0.self_attn.q_proj.weight`` -> layer
        ``model.layers.0.self_attn.q_proj`` with role ``weight``. A name with no
        recognised leaf is treated as a single-tensor layer (role ``other_param``).
        """
        name = tensor_name.strip("/").replace("/", ".")
        leaf = name.rsplit(".", 1)[-1].lower() if "." in name else name.lower()
        role = self._PARAM_LEAF_ROLES.get(leaf)
        if role is None and name.rsplit(".", 1)[-1].lower().endswith(
            ("_scale", "_zero_point")
        ):
            role = "quant_param"
        if role is not None and "." in name:
            layer = name.rsplit(".", 1)[0]
        elif role is not None:
            layer = name  # leaf with no parent path
        else:
            role = "other_param"
            layer = name
        # embeddings are parameters but semantically their own kind
        if role == "weight" and self._infer_layer_type(layer, None) == "Embedding":
            role = "embedding"
        return layer, role

    _LTYPE_TOKENS = (
        (
            "Embedding",
            (
                "embed",
                "wte",
                "wpe",
                "tok_emb",
                "word_embeddings",
                "position_embeddings",
                "embeddings",
            ),
        ),
        ("Convolution", ("conv", "patch_embed.proj", "downsample", "upsample")),
        (
            "Normalization",
            (
                "layernorm",
                "layer_norm",
                "rmsnorm",
                "rms_norm",
                "batchnorm",
                "batch_norm",
                "groupnorm",
                "group_norm",
                "ln_f",
                "ln1",
                "ln2",
                "ln_1",
                "ln_2",
                ".norm",
                "_norm",
                "norm.",
                "input_layernorm",
                "post_attention_layernorm",
            ),
        ),
        (
            "Attention",
            (
                "attn",
                "attention",
                "q_proj",
                "k_proj",
                "v_proj",
                "o_proj",
                "out_proj",
                "qkv",
                "query",
                "key",
                "value",
                "in_proj",
            ),
        ),
        (
            "Linear/MLP",
            (
                "mlp",
                "ffn",
                "feed_forward",
                "gate_proj",
                "up_proj",
                "down_proj",
                "fc1",
                "fc2",
                "fc_",
                "dense",
                "linear",
                "proj",
                "lm_head",
                "classifier",
                "head",
            ),
        ),
    )

    def _infer_layer_type(self, layer_name: str, primary_shape) -> str:
        low = layer_name.lower()
        for ltype, toks in self._LTYPE_TOKENS:
            for t in toks:
                if t in low:
                    return ltype
        # fall back to weight rank when the name is uninformative
        if primary_shape is not None:
            r = len(primary_shape)
            if r >= 4:
                return "Convolution"
            if r == 2:
                return "Linear/MLP"
            if r == 1:
                return "Normalization"
        return "Other"

    @staticmethod
    def _param_bucket(n: Optional[int]) -> str:
        """Human label for the order-of-magnitude bucket a layer's parameter
        count falls in (``"0"``, ``"1-9"``, ``"10-99"``, ``"1K-9K"``, ...).
        Buckets are monotonic in ``n`` so inserting in ascending ``n`` order
        yields an already-sorted histogram."""
        if not isinstance(n, int) or n <= 0:
            return "0"
        e = len(str(n)) - 1  # floor(log10(n)), exact for ints (no float error)

        def fmt(x: int) -> str:
            if x >= 1_000_000_000:
                return f"{x // 1_000_000_000}B"
            if x >= 1_000_000:
                return f"{x // 1_000_000}M"
            if x >= 1_000:
                return f"{x // 1_000}K"
            return str(x)

        return f"{fmt(10 ** e)}-{fmt(10 ** (e + 1) - 1)}"

    def _emit_model_layers(
        self, ds: Dict[str, Any], local_fid: int, framework: str, tensor_start: int
    ) -> None:
        """Group the tensors this handler just emitted into per-layer rows and a
        dataset-level per-type summary. Also back-fills ``role``/``layer_name`` on
        the tensor rows. Operates on ``data_tensors_table[tensor_start:]`` (all of
        which belong to ``ds``)."""
        rows = self.data_tensors_table[tensor_start:]
        if not rows:
            return
        # preserve first-seen order of layers
        order: List[str] = []
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for tr in rows:
            layer, role = self._classify_param(tr.get("tensor_name") or "")
            tr["role"] = role
            tr["layer_name"] = layer
            if layer not in groups:
                groups[layer] = []
                order.append(layer)
            groups[layer].append(tr)

        total_params = 0
        total_buffers = 0
        total_pbytes = 0
        param_tensors = 0
        buffer_tensors = 0
        dtype_hist: Dict[str, int] = {}
        ltype_hist: Dict[str, int] = {}
        ltype_params: Dict[str, int] = {}
        layer_param_counts: List[int] = []
        largest = (None, -1)

        for ordinal, layer in enumerate(order):
            trs = groups[layer]
            # primary shape = the weight/embedding tensor's shape if present
            primary = None
            for tr in trs:
                if tr.get("role") in ("weight", "embedding"):
                    primary = tr.get("shape")
                    break
            ltype = self._infer_layer_type(layer, primary)
            l_params = 0
            l_buffers = 0
            l_bytes = 0
            has_bytes = False
            p_tensors = 0
            b_tensors = 0
            dtypes: List[str] = []
            pshapes: Dict[str, Any] = {}
            roles: Dict[str, str] = {}
            for tr in trs:
                leaf = (tr.get("tensor_name") or "").rsplit(".", 1)[-1]
                role = tr.get("role")
                ne = tr.get("num_elements")
                dt = tr.get("dtype")
                if dt:
                    dtype_hist[dt] = dtype_hist.get(dt, 0) + 1
                    if dt not in dtypes:
                        dtypes.append(dt)
                pshapes[leaf] = tr.get("shape")
                roles[leaf] = role
                if role in self._BUFFER_ROLES:
                    b_tensors += 1
                    buffer_tensors += 1
                    if isinstance(ne, int):
                        l_buffers += ne
                        total_buffers += ne
                else:
                    p_tensors += 1
                    param_tensors += 1
                    if isinstance(ne, int):
                        l_params += ne
                        total_params += ne
                nb = tr.get("num_bytes")
                if isinstance(nb, int):
                    l_bytes += nb
                    total_pbytes += nb
                    has_bytes = True
            self._add_model_layer(
                ds["dataset_id"],
                layer,
                ltype,
                ordinal,
                layer.count(".") + 1,
                len(trs),
                p_tensors,
                b_tensors,
                l_params or None,
                l_buffers or None,
                l_bytes if has_bytes else None,
                dtypes,
                pshapes,
                roles,
                local_fid,
            )
            ltype_hist[ltype] = ltype_hist.get(ltype, 0) + 1
            ltype_params[ltype] = ltype_params.get(ltype, 0) + l_params
            layer_param_counts.append(l_params)
            if l_params > largest[1]:
                largest = (layer, l_params)

        # per-layer parameter-count histogram (order-of-magnitude buckets).
        # Iterate ascending so the resulting dict is bucket-sorted.
        pcount_hist: Dict[str, int] = {}
        for lp in sorted(layer_param_counts):
            b = self._param_bucket(lp)
            pcount_hist[b] = pcount_hist.get(b, 0) + 1

        # dataset-level per-type rollup
        summary = {
            "framework": framework,
            "layer_count": len(order),
            "parameter_tensor_count": param_tensors,
            "buffer_tensor_count": buffer_tensors,
            "total_parameters": total_params or None,
            "total_buffer_elements": total_buffers or None,
            "total_parameter_bytes": total_pbytes or None,
            "distinct_dtypes": len(dtype_hist),
            "dtype_histogram": dtype_hist or None,
            "layer_type_histogram": ltype_hist or None,
            "parameters_by_layer_type": {k: v for k, v in ltype_params.items() if v}
            or None,
            "parameter_count_histogram": pcount_hist or None,
            "largest_layer": largest[0],
            "largest_layer_parameters": largest[1] if largest[1] >= 0 else None,
        }
        self._add_properties(ds["dataset_id"], summary, "model_summary", local_fid)
        # keep the dataset's headline params in a first-class-ish field too
        if total_params:
            ds["properties"] = dict(ds.get("properties") or {})
            ds["properties"]["total_parameters"] = total_params
            ds["properties"]["layer_count"] = len(order)

    # ------------------------------------------------------------------
    # deep media metrics (opt-in): weight-free perceptual/DSP metrics + models
    # ------------------------------------------------------------------
    def _media_extractor(self):
        """Lazily build the MediaMetricExtractor once; None if unavailable."""
        if self._media_ext_ready:
            return self._media_ext
        self._media_ext_ready = True
        try:
            from .media_metrics import MediaMetricExtractor

            self._media_ext = MediaMetricExtractor(
                repo_root=self._repo_root,
                models_dir=self._media_models_dir,
            )
        except Exception:
            self._media_ext = None
        return self._media_ext

    def _emit_media_metrics(
        self, ds: Dict[str, Any], path: Path, kind: str, local_fid: int
    ) -> None:
        """Run weight-free metric extraction (and optional detector) for a media
        file and emit the results as property rows. Never raises."""
        if not self._media_metrics:
            return
        ext = self._media_extractor()
        if ext is None:
            return
        dsid = ds["dataset_id"]
        try:
            if kind == "image":
                m = ext.image_metrics(path)
                if m:
                    self._add_properties(dsid, m, "vision_dynamics", local_fid)
                if self._media_models:
                    d = ext.detect_objects(path)
                    if d:
                        self._add_properties(dsid, d, "object_detection", local_fid)
            elif kind == "audio":
                m = ext.audio_metrics(path)
                if m:
                    self._add_properties(dsid, m, "acoustic_dynamics", local_fid)
            elif kind == "video":
                m = ext.video_metrics(path)
                if m:
                    self._add_properties(dsid, m, "vision_dynamics", local_fid)
        except Exception as err:  # profiling must never break on media metrics
            ds.setdefault("notes", None)
            ds["notes"] = (ds.get("notes") or "") + f" [media_metrics: {err}]"

    # ==================================================================
    # Shared dataframe profiler (metadata/stats only -- no payload kept)
    # ==================================================================
    def _profile_dataframe(
        self,
        df,
        ds_row: Dict[str, Any],
        local_fid: int,
        exact_rows: Optional[int] = None,
    ) -> None:
        import numpy as np  # local import: optional dependency

        dataset_id = ds_row["dataset_id"]
        cols = list(df.columns)[: self.MAX_COLUMNS]
        ds_row["column_count"] = len(df.columns)
        if exact_rows is not None:
            ds_row["row_count"] = exact_rows
        for ordinal, name in enumerate(cols, start=1):
            series = df[name]
            n = int(len(series))
            try:
                non_null = int(series.notna().sum())
            except Exception:
                non_null = None
            null_count = (n - non_null) if non_null is not None else None
            dtype = str(series.dtype)
            inferred = self._infer_type(series)
            uniq = None
            try:
                uniq = int(series.nunique(dropna=True))
            except Exception:
                pass
            minv = maxv = meanv = stdv = None
            try:
                if np.issubdtype(series.dtype, np.number):
                    s = series.dropna()
                    if len(s):
                        minv = float(s.min())
                        maxv = float(s.max())
                        meanv = float(s.mean())
                        stdv = float(s.std()) if len(s) > 1 else 0.0
            except Exception:
                pass
            samples = self._sample_values(series)
            extra = {
                "stats_from_sample": exact_rows is None or n < (exact_rows or 0),
                "sample_n": n,
            }
            self._add_column(
                dataset_id,
                str(name),
                ordinal,
                dtype,
                inferred,
                null_count,
                non_null,
                uniq,
                minv,
                maxv,
                meanv,
                stdv,
                samples,
                extra,
                local_fid,
            )
        self._emit_correlations(df, dataset_id, local_fid)

    def _infer_type(self, series) -> str:
        try:
            import pandas as pd

            if pd.api.types.is_bool_dtype(series):
                return "boolean"
            if pd.api.types.is_integer_dtype(series):
                return "integer"
            if pd.api.types.is_float_dtype(series):
                return "float"
            if pd.api.types.is_datetime64_any_dtype(series):
                return "datetime"
            if pd.api.types.is_categorical_dtype(series):
                return "categorical"
            if pd.api.types.is_object_dtype(series):
                return "string"
        except Exception:
            pass
        return "unknown"

    def _sample_values(self, series) -> List[str]:
        # Sample distinct column values to illustrate a column's shape. These are
        # real cell contents, so each is scrubbed of secrets/PII (a column may
        # hold emails, card numbers or tokens) and length-capped before storage.
        out: List[str] = []
        try:
            seen = series.dropna().unique()
        except Exception:
            return out
        for v in seen[: self.MAX_SAMPLE_VALUES]:
            out.append(scrub(str(v), max_len=self.SAMPLE_VALUE_CHARS))
        return out

    def _emit_correlations(self, df, dataset_id: int, local_fid: int) -> None:
        import math

        try:
            import numpy as np

            num = df.select_dtypes(include=[np.number])
        except Exception:
            return
        cols = list(num.columns)[: self.CORR_MAX_COLS]
        if len(cols) < 2:
            return
        try:
            corr = num[cols].corr(numeric_only=True)
        except TypeError:
            corr = num[cols].corr()
        except Exception:
            return
        pairs = []
        for i in range(len(cols)):
            for j in range(i + 1, len(cols)):
                try:
                    r = corr.iloc[i, j]
                except Exception:
                    continue
                if r is None or (isinstance(r, float) and math.isnan(r)):
                    continue
                if abs(r) >= self.CORR_MIN_ABS:
                    pairs.append((abs(r), str(cols[i]), str(cols[j]), float(r)))
        pairs.sort(reverse=True)
        for _, a, b, r in pairs[: self.CORR_MAX_RELATIONS]:
            self._add_relation(
                dataset_id,
                "pearson_correlation",
                a,
                b,
                round(r, 6),
                "pearson",
                local_fid,
            )

    # ------------------------------------------------------------------
    # low-level helpers
    # ------------------------------------------------------------------
    def _read_magic(self, path: Path, n: int = 16) -> bytes:
        try:
            with open(path, "rb") as f:
                return f.read(n)
        except OSError:
            return b""

    def _compression_of(self, ext: str) -> Optional[str]:
        for suffix, comp in (
            (".gz", "gzip"),
            (".bz2", "bz2"),
            (".zst", "zstd"),
            (".zstd", "zstd"),
            (".xz", "xz"),
        ):
            if ext.endswith(suffix):
                return comp
        return None

    # ==================================================================
    # Tabular handlers
    # ==================================================================
    def _handle_tabular_delimited(self, path, ext, category, subcategory, local_fid):
        import csv as _csv

        base = ext.split(".")[1] if ext.count(".") >= 2 else ext
        base = "." + base if not base.startswith(".") else base
        delim = self._EXT_DELIM.get(base) or self._EXT_DELIM.get(ext)
        comp = self._compression_of(ext)
        ds = self._add_dataset(
            path,
            ext,
            category or "data",
            subcategory or "tabular_delimited",
            "tabular",
            local_fid,
        )
        # sniff delimiter if unknown and file is uncompressed
        if delim is None and comp is None:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    head = f.read(65536)
                delim = _csv.Sniffer().sniff(head, delimiters=",\t;|").delimiter
            except Exception:
                delim = ","
        elif delim is None:
            delim = ","
        # exact row count (data rows) -- streamed, uncompressed only
        exact = None
        if comp is None:
            try:
                with open(
                    path, "r", encoding="utf-8", errors="replace", newline=""
                ) as f:
                    total = sum(1 for _ in f)
                exact = max(total - 1, 0)  # minus header
            except Exception:
                exact = None
        try:
            import pandas as pd

            df = pd.read_csv(
                path,
                sep=delim,
                nrows=self.SAMPLE_ROWS,
                compression=(comp or "infer"),
                on_bad_lines="skip",
                engine="python",
            )
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"header/stat read failed: {err}"
            self._add_property(ds["dataset_id"], "delimiter", delim, "parse", local_fid)
            if exact is not None:
                ds["row_count"] = exact
            return
        self._add_property(ds["dataset_id"], "delimiter", delim, "parse", local_fid)
        self._profile_dataframe(df, ds, local_fid, exact_rows=exact)
        if exact is not None:
            ds["row_count"] = exact

    def _handle_parquet(self, path, ext, category, subcategory, local_fid):
        ds = self._add_dataset(
            path,
            ext,
            category or "data",
            subcategory or "columnar_and_lakehouse",
            "tabular",
            local_fid,
        )
        try:
            import pyarrow.parquet as pq
        except Exception as err:
            ds["analysis_status"] = "unavailable"
            ds["notes"] = f"pyarrow missing: {err}"
            return
        pf = pq.ParquetFile(path)
        meta = pf.metadata
        ds["row_count"] = int(meta.num_rows)
        ds["column_count"] = int(meta.num_columns)
        self._add_properties(
            ds["dataset_id"],
            {
                "num_row_groups": meta.num_row_groups,
                "format_version": getattr(meta, "format_version", None),
                "created_by": getattr(meta, "created_by", None),
            },
            "parquet",
            local_fid,
        )
        # sample one batch for stats/correlation (bounded)
        try:
            batch = next(pf.iter_batches(batch_size=self.SAMPLE_ROWS))
            df = batch.to_pandas()
            self._profile_dataframe(df, ds, local_fid, exact_rows=int(meta.num_rows))
            ds["column_count"] = int(meta.num_columns)
        except StopIteration:
            self._schema_only_columns(pf.schema_arrow, ds, local_fid)
        except Exception as err:
            self._schema_only_columns(pf.schema_arrow, ds, local_fid)
            ds["notes"] = f"sample failed: {err}"

    def _handle_orc(self, path, ext, category, subcategory, local_fid):
        ds = self._add_dataset(
            path,
            ext,
            category or "data",
            subcategory or "columnar_and_lakehouse",
            "tabular",
            local_fid,
        )
        try:
            import pyarrow.orc as orc
        except Exception as err:
            ds["analysis_status"] = "unavailable"
            ds["notes"] = f"pyarrow.orc missing: {err}"
            return
        of = orc.ORCFile(path)
        ds["row_count"] = int(of.nrows)
        try:
            tbl = of.read(columns=None)  # ORC lacks batch iterator; cap after read
            df = tbl.slice(0, self.SAMPLE_ROWS).to_pandas()
            self._profile_dataframe(df, ds, local_fid, exact_rows=int(of.nrows))
        except Exception as err:
            self._schema_only_columns(of.schema, ds, local_fid)
            ds["notes"] = f"sample failed: {err}"

    def _handle_arrow(self, path, ext, category, subcategory, local_fid):
        ds = self._add_dataset(
            path,
            ext,
            category or "data",
            subcategory or "columnar_and_lakehouse",
            "tabular",
            local_fid,
        )
        try:
            import pyarrow as pa
            import pyarrow.feather as feather
        except Exception as err:
            ds["analysis_status"] = "unavailable"
            ds["notes"] = f"pyarrow missing: {err}"
            return
        try:
            reader = pa.ipc.open_file(path)
            schema = reader.schema
            nrows = reader.num_record_batches and sum(
                reader.get_batch(i).num_rows for i in range(reader.num_record_batches)
            )
            df = reader.get_batch(0).to_pandas() if reader.num_record_batches else None
        except Exception:
            try:
                tbl = feather.read_table(path)
                schema = tbl.schema
                nrows = tbl.num_rows
                df = tbl.slice(0, self.SAMPLE_ROWS).to_pandas()
            except Exception as err:
                ds["analysis_status"] = "partial"
                ds["notes"] = f"arrow read failed: {err}"
                return
        if df is not None:
            self._profile_dataframe(df, ds, local_fid, exact_rows=nrows)
        else:
            self._schema_only_columns(schema, ds, local_fid)
            ds["row_count"] = nrows

    def _schema_only_columns(self, arrow_schema, ds_row, local_fid):
        """Emit columns from an arrow schema when no sample could be read."""
        try:
            names = arrow_schema.names
            types = [str(arrow_schema.field(n).type) for n in names]
        except Exception:
            return
        ds_row["column_count"] = len(names)
        for ordinal, (name, typ) in enumerate(zip(names, types), start=1):
            self._add_column(
                ds_row["dataset_id"],
                str(name),
                ordinal,
                typ,
                "unknown",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                [],
                {"schema_only": True},
                local_fid,
            )

    def _handle_excel(self, path, ext, category, subcategory, local_fid):
        ds = self._add_dataset(
            path,
            ext,
            category or "data",
            subcategory or "spreadsheet_workbooks",
            "tabular",
            local_fid,
        )
        if ext == ".ods":
            try:
                import pandas as pd

                df = pd.read_excel(path, nrows=self.SAMPLE_ROWS, engine="odf")
                self._profile_dataframe(df, ds, local_fid)
                return
            except Exception as err:
                ds["analysis_status"] = "unavailable"
                ds["notes"] = f"odf engine missing: {err}"
                return
        try:
            from openpyxl import load_workbook
        except Exception as err:
            ds["analysis_status"] = "unavailable"
            ds["notes"] = f"openpyxl missing: {err}"
            return
        wb = load_workbook(path, read_only=True, data_only=True)
        self._add_property(
            ds["dataset_id"], "sheet_names", wb.sheetnames, "workbook", local_fid
        )
        self._add_property(
            ds["dataset_id"], "sheet_count", len(wb.sheetnames), "workbook", local_fid
        )
        ws = wb.active
        rows_iter = ws.iter_rows(values_only=True)
        try:
            header = next(rows_iter)
        except StopIteration:
            header = ()
        sample = []
        for i, r in enumerate(rows_iter):
            if i >= self.SAMPLE_ROWS:
                break
            sample.append(r)
        try:
            import pandas as pd

            colnames = [
                str(h) if h is not None else f"col_{i}"
                for i, h in enumerate(header, start=1)
            ]
            df = pd.DataFrame(sample, columns=colnames if colnames else None)
            ds["row_count"] = int(ws.max_row - 1) if ws.max_row else 0
            self._profile_dataframe(
                df, ds, local_fid, exact_rows=(ws.max_row - 1) if ws.max_row else 0
            )
        except Exception as err:
            ds["column_count"] = len(header)
            ds["notes"] = f"profile failed: {err}"
        finally:
            wb.close()

    def _handle_json(self, path, ext, category, subcategory, local_fid):
        modality = "tabular"
        ds = self._add_dataset(
            path,
            ext,
            category or "data",
            subcategory or "serialization_text",
            modality,
            local_fid,
        )
        if ext in (".jsonl", ".ndjson"):
            self._handle_jsonl(path, ds, local_fid)
            return
        # plain .json
        try:
            size = path.stat().st_size
        except OSError:
            size = None
        if size is not None and size > self.MAX_JSON_BYTES:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"json too large to load ({size} bytes); header-only"
            ds["modality"] = "structured"
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                obj = json.load(f)
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"json parse failed: {err}"
            return
        if isinstance(obj, list):
            ds["record_count"] = len(obj)
            records = [r for r in obj[: self.SAMPLE_ROWS] if isinstance(r, dict)]
            if records:
                try:
                    import pandas as pd

                    df = pd.DataFrame(records)
                    self._profile_dataframe(df, ds, local_fid, exact_rows=len(obj))
                except Exception as err:
                    ds["notes"] = f"record profile failed: {err}"
            else:
                ds["modality"] = "structured"
                self._add_property(
                    ds["dataset_id"],
                    "element_type",
                    type(obj[0]).__name__ if obj else "empty",
                    "json",
                    local_fid,
                )
        elif isinstance(obj, dict):
            # dict-of-lists (columnar) -> tabular; otherwise a config/record tree.
            # Require EVERY value to be an equal-length list (>=2 cols) so a
            # config object that merely contains a list is not mistaken for data.
            list_vals = {k: v for k, v in obj.items() if isinstance(v, list)}
            if (
                len(list_vals) >= 2
                and len(list_vals) == len(obj)
                and len({len(v) for v in list_vals.values()}) == 1
            ):
                try:
                    import pandas as pd

                    df = pd.DataFrame(list_vals)
                    self._profile_dataframe(df, ds, local_fid, exact_rows=len(df))
                except Exception as err:
                    ds["notes"] = f"columnar profile failed: {err}"
            else:
                ds["modality"] = "structured"
                self._add_properties(
                    ds["dataset_id"],
                    {
                        "top_level_keys": list(obj.keys())[:100],
                        "key_count": len(obj),
                    },
                    "json",
                    local_fid,
                )
        else:
            ds["modality"] = "scalar"
            self._add_property(
                ds["dataset_id"], "value_type", type(obj).__name__, "json", local_fid
            )

    def _handle_jsonl(self, path, ds, local_fid):
        records = []
        total = 0
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    total += 1
                    if len(records) < self.SAMPLE_ROWS:
                        line = line.strip()
                        if line:
                            try:
                                rec = json.loads(line)
                                if isinstance(rec, dict):
                                    records.append(rec)
                            except ValueError:
                                pass
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"jsonl read failed: {err}"
            return
        ds["record_count"] = total
        if records:
            try:
                import pandas as pd

                df = pd.DataFrame(records)
                self._profile_dataframe(df, ds, local_fid, exact_rows=total)
            except Exception as err:
                ds["notes"] = f"record profile failed: {err}"

    def _handle_sqlite(self, path, ext, category, subcategory, local_fid):
        # one dataset row PER TABLE in the embedded database (metadata only).
        magic = self._read_magic(path, 16)
        if not magic.startswith(b"SQLite format 3"):
            self._handle_generic(path, ext, category, subcategory, local_fid)
            return
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except Exception:
            self._handle_generic(path, ext, category, subcategory, local_fid)
            return
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
            tables = [r[0] for r in cur.fetchall()][: self.MAX_DB_TABLES]
            for tname in tables:
                ds = self._add_dataset(
                    path,
                    ext,
                    category or "data",
                    "databases_and_dumps",
                    "database_table",
                    local_fid,
                )
                ds["dataset_name"] = f"{path.name}::{tname}"
                self._add_property(
                    ds["dataset_id"], "table_name", tname, "sqlite", local_fid
                )
                try:
                    cur.execute(f'PRAGMA table_info("{tname}")')
                    cols = cur.fetchall()  # cid,name,type,notnull,dflt,pk
                    ds["column_count"] = len(cols)
                    for ordinal, c in enumerate(cols, start=1):
                        _cid, cname, ctype, notnull, dflt, pk = c
                        extra = {
                            "not_null": bool(notnull),
                            "primary_key": bool(pk),
                            "default": dflt,
                        }
                        self._add_column(
                            ds["dataset_id"],
                            str(cname),
                            ordinal,
                            str(ctype),
                            "unknown",
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            [],
                            extra,
                            local_fid,
                        )
                    cur.execute(f'SELECT COUNT(*) FROM "{tname}"')
                    ds["row_count"] = int(cur.fetchone()[0])
                except Exception as err:
                    ds["analysis_status"] = "partial"
                    ds["notes"] = f"table introspection failed: {err}"
        finally:
            conn.close()

    def _handle_stat(self, path, ext, category, subcategory, local_fid):
        ds = self._add_dataset(
            path,
            ext,
            category or "data",
            subcategory or "statistical_software",
            "tabular",
            local_fid,
        )
        try:
            import pandas as pd
        except Exception as err:
            ds["analysis_status"] = "unavailable"
            ds["notes"] = f"pandas missing: {err}"
            return
        try:
            if ext == ".dta":
                itr = pd.read_stata(path, iterator=True)
                df = itr.read(self.SAMPLE_ROWS)
                try:
                    ds["row_count"] = int(itr.nobs)
                except Exception:
                    # pandas >= 2 removed StataReader.nobs. If the sample read
                    # did not reach the cap, it consumed the whole file, so the
                    # frame length is the exact row count; otherwise leave it
                    # unset rather than report a truncated (wrong) total.
                    if len(df) < self.SAMPLE_ROWS:
                        ds["row_count"] = int(len(df))
                itr.close()
            elif ext in (".sas7bdat", ".xpt"):
                itr = pd.read_sas(path, chunksize=self.SAMPLE_ROWS)
                df = next(itr)
                itr.close()
            else:  # .sav/.por -> needs pyreadstat
                df = pd.read_spss(path)
                if len(df) > self.SAMPLE_ROWS:
                    df = df.head(self.SAMPLE_ROWS)
            self._profile_dataframe(df, ds, local_fid, exact_rows=ds.get("row_count"))
        except Exception as err:
            ds["analysis_status"] = "unavailable"
            ds["notes"] = f"reader unavailable/failed: {err}"

    # ==================================================================
    # Tensor / model handlers (header parsing -- never load weights)
    # ==================================================================
    def _handle_safetensors(self, path, ext, category, subcategory, local_fid):
        import struct

        ds = self._add_dataset(
            path,
            ext,
            category or "tensor_and_model",
            subcategory or "raw_arrays_and_tensors",
            "tensor",
            local_fid,
        )
        t0 = len(self.data_tensors_table)
        try:
            with open(path, "rb") as f:
                header_len = struct.unpack("<Q", f.read(8))[0]
                header = json.loads(f.read(header_len).decode("utf-8"))
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"safetensors header parse failed: {err}"
            return
        meta = header.pop("__metadata__", None)
        if isinstance(meta, dict):
            self._add_properties(
                ds["dataset_id"],
                {f"meta.{k}": v for k, v in list(meta.items())[:50]},
                "safetensors",
                local_fid,
            )
        count = 0
        for name, info in header.items():
            if not isinstance(info, dict):
                continue
            shape = info.get("shape", [])
            dtype = info.get("dtype")
            offs = info.get("data_offsets") or [0, 0]
            nbytes = None
            try:
                nbytes = int(offs[1]) - int(offs[0])
            except Exception:
                pass
            self._add_tensor(
                ds["dataset_id"], name, dtype, shape, nbytes, {}, local_fid
            )
            count += 1
        ds["tensor_count"] = count
        self._emit_model_layers(ds, local_fid, "safetensors", t0)

    def _handle_npy(self, path, ext, category, subcategory, local_fid):
        ds = self._add_dataset(
            path,
            ext,
            category or "tensor_and_model",
            subcategory or "raw_arrays_and_tensors",
            "tensor",
            local_fid,
        )
        info = self._parse_npy_header(path)
        if info is None:
            ds["analysis_status"] = "partial"
            ds["notes"] = "not a valid .npy header"
            return
        dtype, shape, fortran = info
        self._add_tensor(
            ds["dataset_id"],
            path.stem,
            dtype,
            shape,
            None,
            {"fortran_order": fortran},
            local_fid,
        )
        ds["tensor_count"] = 1

    def _handle_npz(self, path, ext, category, subcategory, local_fid):
        import zipfile

        ds = self._add_dataset(
            path,
            ext,
            category or "tensor_and_model",
            subcategory or "raw_arrays_and_tensors",
            "tensor",
            local_fid,
        )
        try:
            zf = zipfile.ZipFile(path)
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"npz open failed: {err}"
            return
        count = 0
        try:
            for member in zf.namelist():
                if not member.endswith(".npy"):
                    continue
                aname = member[:-4]
                info = self._parse_npy_header_bytes(zf.open(member))
                if info is None:
                    continue
                dtype, shape, fortran = info
                self._add_tensor(
                    ds["dataset_id"],
                    aname,
                    dtype,
                    shape,
                    None,
                    {"fortran_order": fortran},
                    local_fid,
                )
                count += 1
        finally:
            zf.close()
        ds["tensor_count"] = count

    def _parse_npy_header(self, path):
        try:
            with open(path, "rb") as f:
                return self._parse_npy_header_bytes(f)
        except OSError:
            return None

    def _parse_npy_header_bytes(self, fobj):
        import struct

        try:
            magic = fobj.read(6)
            if magic != b"\x93NUMPY":
                return None
            major, minor = struct.unpack("<BB", fobj.read(2))
            if major == 1:
                hlen = struct.unpack("<H", fobj.read(2))[0]
            else:
                hlen = struct.unpack("<I", fobj.read(4))[0]
            header = fobj.read(hlen).decode("latin1")
            d = ast.literal_eval(header)
            descr = d.get("descr")
            shape = list(d.get("shape", ()))
            fortran = bool(d.get("fortran_order", False))
            return descr, shape, fortran
        except Exception:
            return None

    def _handle_torch(self, path, ext, category, subcategory, local_fid):
        import zipfile

        ds = self._add_dataset(
            path,
            ext,
            category or "tensor_and_model",
            subcategory or "pytorch",
            "tensor",
            local_fid,
        )
        t0 = len(self.data_tensors_table)
        # Preferred: mmap load of weights only (no RAM materialisation, no exec
        # of arbitrary globals under weights_only).
        loaded = False
        try:
            import torch

            try:
                obj = torch.load(path, map_location="cpu", mmap=True, weights_only=True)
            except TypeError:  # older torch without mmap kwarg
                obj = torch.load(path, map_location="cpu", weights_only=True)
            self._walk_torch_obj(obj, ds, local_fid)
            loaded = True
        except Exception:
            loaded = False
        if loaded:
            self._emit_model_layers(ds, local_fid, "pytorch", t0)
            return
        # Fallback: inspect the zip container without unpickling.
        if zipfile.is_zipfile(path):
            try:
                zf = zipfile.ZipFile(path)
                members = zf.namelist()
                data_members = [
                    m for m in members if "/data/" in m or m.endswith("data.pkl")
                ]
                self._add_properties(
                    ds["dataset_id"],
                    {
                        "container": "zip",
                        "member_count": len(members),
                        "data_member_count": len(data_members),
                    },
                    "pytorch",
                    local_fid,
                )
                zf.close()
                ds["analysis_status"] = "partial"
                ds["notes"] = "torch unavailable; container inspected only"
            except Exception as err:
                ds["analysis_status"] = "partial"
                ds["notes"] = f"torch container inspect failed: {err}"
        else:
            ds["analysis_status"] = "partial"
            ds["notes"] = "legacy (non-zip) torch pickle; torch unavailable"

    def _walk_torch_obj(self, obj, ds, local_fid, prefix=""):
        count = 0

        def is_tensor(x):
            return hasattr(x, "shape") and hasattr(x, "dtype") and hasattr(x, "numel")

        def walk(o, pfx):
            nonlocal count
            if is_tensor(o):
                try:
                    shape = list(o.shape)
                    dtype = str(o.dtype)
                    nbytes = int(o.numel() * o.element_size())
                except Exception:
                    shape, dtype, nbytes = [], None, None
                self._add_tensor(
                    ds["dataset_id"],
                    pfx or "tensor",
                    dtype,
                    shape,
                    nbytes,
                    {},
                    local_fid,
                )
                count += 1
            elif isinstance(o, dict):
                for k, v in o.items():
                    walk(v, f"{pfx}.{k}" if pfx else str(k))
            elif isinstance(o, (list, tuple)):
                for i, v in enumerate(o):
                    walk(v, f"{pfx}[{i}]")

        walk(obj, prefix)
        ds["tensor_count"] = count

    def _handle_gguf(self, path, ext, category, subcategory, local_fid):
        from .model_formats import read_gguf

        ds = self._add_dataset(
            path,
            ext,
            category or "tensor_and_model",
            subcategory or "llm_quantized_and_serving",
            "tensor",
            local_fid,
        )
        t0 = len(self.data_tensors_table)
        info = read_gguf(path)
        if info.get("error") and not info.get("tensors"):
            ds["analysis_status"] = "partial"
            ds["notes"] = f"gguf: {info['error']}"
            return
        self._add_properties(
            ds["dataset_id"],
            {
                "gguf_version": info.get("version"),
                "tensor_count": info.get("tensor_count"),
                "metadata_kv_count": info.get("metadata_kv_count"),
                "tensors_listed": info.get("tensors_listed"),
                "truncated": info.get("truncated"),
            },
            "gguf",
            local_fid,
        )
        # surfaced scalar metadata (architecture / dims / head counts / ...)
        if info.get("metadata"):
            self._add_properties(
                ds["dataset_id"], info["metadata"], "gguf_metadata", local_fid
            )
        count = 0
        for t in info.get("tensors", []):
            self._add_tensor(
                ds["dataset_id"],
                t["name"],
                t.get("dtype"),
                t.get("shape", []),
                None,
                {"offset": t.get("offset")},
                local_fid,
            )
            count += 1
        ds["tensor_count"] = int(info.get("tensor_count") or count)
        self._emit_model_layers(ds, local_fid, "gguf", t0)
        if info.get("error"):
            ds["analysis_status"] = "partial"
            ds["notes"] = f"gguf partial: {info['error']}"

    def _handle_onnx(self, path, ext, category, subcategory, local_fid):
        ds = self._add_dataset(
            path,
            ext,
            category or "tensor_and_model",
            subcategory or "onnx_and_interchange",
            "model",
            local_fid,
        )
        t0 = len(self.data_tensors_table)
        try:
            import onnx

            model = onnx.load(path, load_external_data=False)
            g = model.graph
            self._add_properties(
                ds["dataset_id"],
                {
                    "ir_version": model.ir_version,
                    "producer_name": model.producer_name,
                    "opset": [op.version for op in model.opset_import][:8],
                    "input_count": len(g.input),
                    "output_count": len(g.output),
                    "node_count": len(g.node),
                    "initializer_count": len(g.initializer),
                },
                "onnx",
                local_fid,
            )
            count = 0
            from onnx import TensorProto  # numeric data_type -> readable name

            for init in g.initializer:
                shape = list(init.dims)
                try:
                    dtname = TensorProto.DataType.Name(init.data_type)
                except Exception:
                    dtname = str(init.data_type)
                self._add_tensor(
                    ds["dataset_id"], init.name, dtname, shape, None, {}, local_fid
                )
                count += 1
            ds["tensor_count"] = count
            self._emit_model_layers(ds, local_fid, "onnx", t0)
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"onnx unavailable/failed: {err}"

    def _handle_ort(self, path, ext, category, subcategory, local_fid):
        """ONNX Runtime (.ort): FlatBuffers InferenceSession -> Model/Graph."""
        from .model_formats import read_ort

        ds = self._add_dataset(
            path,
            ext,
            category or "tensor_and_model",
            subcategory or "onnx_and_interchange",
            "model",
            local_fid,
        )
        t0 = len(self.data_tensors_table)
        info = read_ort(path)
        if info.get("error") and not info.get("tensors"):
            ds["analysis_status"] = "partial"
            ds["notes"] = f"ort parse: {info['error']}"
            return
        self._add_properties(
            ds["dataset_id"],
            {
                "ort_version": info.get("ort_version"),
                "ir_version": info.get("ir_version"),
                "producer_name": info.get("producer_name"),
                "producer_version": info.get("producer_version"),
                "domain": info.get("domain"),
                "model_version": info.get("model_version"),
                "opset_count": info.get("opset_count"),
                "node_count": info.get("node_count"),
                "input_count": info.get("input_count"),
                "output_count": info.get("output_count"),
                "initializer_count": info.get("initializer_count"),
            },
            "ort",
            local_fid,
        )
        count = 0
        for t in info.get("tensors", []):
            self._add_tensor(
                ds["dataset_id"],
                t["name"],
                t.get("dtype"),
                t.get("shape", []),
                None,
                {},
                local_fid,
            )
            count += 1
        ds["tensor_count"] = count
        self._emit_model_layers(ds, local_fid, "onnxruntime", t0)
        if info.get("error"):
            ds["analysis_status"] = "partial"
            ds["notes"] = f"ort partial: {info['error']}"

    def _handle_tflite(self, path, ext, category, subcategory, local_fid):
        """TensorFlow Lite (.tflite): FlatBuffers Model -> subgraphs -> tensors."""
        from .model_formats import read_tflite

        ds = self._add_dataset(
            path,
            ext,
            category or "tensor_and_model",
            subcategory or "mobile_and_edge",
            "model",
            local_fid,
        )
        t0 = len(self.data_tensors_table)
        info = read_tflite(path)
        if info.get("error") and not info.get("tensors"):
            ds["analysis_status"] = "partial"
            ds["notes"] = f"tflite parse: {info['error']}"
            return
        self._add_properties(
            ds["dataset_id"],
            {
                "schema_version": info.get("version"),
                "description": info.get("description"),
                "subgraph_count": len(info.get("subgraphs", [])),
                "operator_code_count": info.get("operator_code_count"),
                "buffer_count": info.get("buffer_count"),
                "tensor_count": info.get("tensor_count"),
            },
            "tflite",
            local_fid,
        )
        for i, sg in enumerate(info.get("subgraphs", [])):
            self._add_properties(
                ds["dataset_id"],
                {
                    f"subgraph{i}.name": sg.get("name"),
                    f"subgraph{i}.tensor_count": sg.get("tensor_count"),
                    f"subgraph{i}.operator_count": sg.get("operator_count"),
                    f"subgraph{i}.input_count": sg.get("input_count"),
                    f"subgraph{i}.output_count": sg.get("output_count"),
                },
                "tflite_subgraphs",
                local_fid,
            )
        count = 0
        for t in info.get("tensors", []):
            self._add_tensor(
                ds["dataset_id"],
                t["name"],
                t.get("dtype"),
                t.get("shape", []),
                None,
                {"subgraph": t.get("subgraph")},
                local_fid,
            )
            count += 1
        ds["tensor_count"] = count
        self._emit_model_layers(ds, local_fid, "tflite", t0)
        if info.get("error"):
            ds["analysis_status"] = "partial"
            ds["notes"] = f"tflite partial: {info['error']}"

    def _handle_keras(self, path, ext, category, subcategory, local_fid):
        """Keras v3 (.keras): zip config/metadata architecture + weight tensors."""
        from .model_formats import read_keras

        ds = self._add_dataset(
            path,
            ext,
            category or "tensor_and_model",
            subcategory or "keras_and_tensorflow",
            "model",
            local_fid,
        )
        t0 = len(self.data_tensors_table)
        info = read_keras(path)
        if info.get("error"):
            ds["analysis_status"] = "partial"
            ds["notes"] = f"keras: {info['error']}"
            return
        self._add_properties(
            ds["dataset_id"],
            {
                "keras_version": info.get("keras_version"),
                "date_saved": info.get("date_saved"),
                "model_class": info.get("model_class"),
                "model_name": info.get("model_name"),
                "layer_count": info.get("layer_count"),
                "weights_files": ",".join(info.get("weights_files", [])) or None,
                "weights_bytes": info.get("weights_bytes"),
            },
            "keras",
            local_fid,
        )
        # architecture: one column row per layer (name + class)
        for ordinal, ly in enumerate(info.get("layers", [])):
            self._add_column(
                ds["dataset_id"],
                ly.get("name") or f"layer{ordinal}",
                ordinal,
                ly.get("class_name") or "Layer",
                "layer",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                [],
                {"class_name": ly.get("class_name")},
                local_fid,
            )
        ds["column_count"] = len(info.get("layers", []))
        ds["record_count"] = info.get("layer_count")
        # weight tensors, when h5py was available to read model.weights.h5
        count = 0
        for t in info.get("tensors", []):
            self._add_tensor(
                ds["dataset_id"],
                t["name"],
                t.get("dtype"),
                t.get("shape", []),
                t.get("nbytes"),
                {},
                local_fid,
            )
            count += 1
        ds["tensor_count"] = count
        self._emit_model_layers(ds, local_fid, "keras", t0)
        if not info.get("tensors") and info.get("weights_files"):
            self._add_property(
                ds["dataset_id"],
                "weights_note",
                "weights present; h5py unavailable for tensor listing",
                "keras",
                local_fid,
            )

    def _handle_flax(self, path, ext, category, subcategory, local_fid):
        """Flax/JAX (.flax/.msgpack): msgpack param tree -> parameter tensors."""
        from .model_formats import read_flax

        ds = self._add_dataset(
            path,
            ext,
            category or "tensor_and_model",
            subcategory or "jax_and_flax",
            "model",
            local_fid,
        )
        t0 = len(self.data_tensors_table)
        info = read_flax(path)
        if info.get("error"):
            ds["analysis_status"] = "partial"
            ds["notes"] = f"flax: {info['error']}"
            return
        count = 0
        total_params = 0
        total_bytes = 0
        for t in info.get("tensors", []):
            shape = t.get("shape", [])
            self._add_tensor(
                ds["dataset_id"],
                t["name"],
                t.get("dtype"),
                shape,
                t.get("nbytes"),
                {},
                local_fid,
            )
            count += 1
            n = 1
            for d in shape:
                try:
                    n *= int(d)
                except (TypeError, ValueError):
                    n = 0
                    break
            total_params += n
            if t.get("nbytes"):
                total_bytes += t["nbytes"]
        ds["tensor_count"] = count
        self._add_properties(
            ds["dataset_id"],
            {
                "parameter_tensor_count": count,
                "total_parameters": total_params or None,
                "total_parameter_bytes": total_bytes or None,
            },
            "flax",
            local_fid,
        )
        self._emit_model_layers(ds, local_fid, "flax", t0)
        if count == 0:
            ds["analysis_status"] = "partial"
            ds["notes"] = "msgpack decoded but no ndarray parameters found"

    def _handle_tfrecord(self, path, ext, category, subcategory, local_fid):
        """TFRecord (.tfrecord): count records + decode first Example's features."""
        from .model_formats import read_tfrecord

        ds = self._add_dataset(
            path,
            ext,
            category or "tensor_and_model",
            subcategory or "tfrecord_examples",
            "records",
            local_fid,
        )
        info = read_tfrecord(path)
        if info.get("error") and not info.get("record_count"):
            ds["analysis_status"] = "partial"
            ds["notes"] = f"tfrecord: {info['error']}"
            return
        ds["record_count"] = info.get("record_count")
        self._add_properties(
            ds["dataset_id"],
            {
                "record_count": info.get("record_count"),
                "feature_count": info.get("feature_count"),
                "compression": info.get("compression"),
                "truncated": info.get("truncated"),
            },
            "tfrecord",
            local_fid,
        )
        # each decoded feature of the first example -> a column (schema sketch)
        for ordinal, feat in enumerate(info.get("features", [])):
            self._add_column(
                ds["dataset_id"],
                feat["name"],
                ordinal,
                feat.get("kind", "unknown"),
                "feature",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                [],
                {"value_count": feat.get("value_count")},
                local_fid,
            )
        ds["column_count"] = info.get("feature_count")
        if info.get("error"):
            ds["analysis_status"] = "partial"
            ds["notes"] = f"tfrecord partial: {info['error']}"

    def _handle_pb(self, path, ext, category, subcategory, local_fid):
        """Protobuf (.pb/.graphdef/.pbtxt): GraphDef/SavedModel graph statistics."""
        from .model_formats import decode_graphdef, pb_field_census

        ds = self._add_dataset(
            path,
            ext,
            category or "tensor_and_model",
            subcategory or "protobuf_graphs",
            "model",
            local_fid,
        )
        try:
            data = path.read_bytes()
        except OSError as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"read failed: {err}"
            return
        # .pbtxt is text-format protobuf: no binary wire structure to walk.
        if ext.endswith("pbtxt") or self._looks_textproto(data):
            self._handle_pbtxt(ds, data, local_fid)
            return
        graph = None
        try:
            graph = decode_graphdef(data)
        except Exception:
            graph = None
        if graph is not None:
            self._add_properties(
                ds["dataset_id"],
                {
                    "kind": (
                        "SavedModel" if graph.get("likely_savedmodel") else "GraphDef"
                    ),
                    "node_count": graph.get("node_count"),
                    "distinct_ops": graph.get("distinct_ops"),
                    "likely_savedmodel": graph.get("likely_savedmodel"),
                },
                "graphdef",
                local_fid,
            )
            for op, n in graph.get("top_ops", []):
                self._add_property(
                    ds["dataset_id"], f"op.{op}", n, "graphdef_ops", local_fid
                )
            ds["record_count"] = graph.get("node_count")
        else:
            # Unknown protobuf schema: emit an honest top-level field census.
            try:
                census = pb_field_census(data)
            except Exception as err:
                ds["analysis_status"] = "partial"
                ds["notes"] = f"protobuf wire parse failed: {err}"
                return
            self._add_properties(
                ds["dataset_id"],
                {
                    "kind": "protobuf",
                    "top_level_field_count": len(census),
                },
                "protobuf",
                local_fid,
            )
            for fno, rec in sorted(census.items()):
                self._add_property(
                    ds["dataset_id"],
                    f"field_{fno}",
                    f"wire={rec['wire_type']} count={rec['count']} bytes={rec['total_bytes']}",
                    "protobuf_fields",
                    local_fid,
                )

    @staticmethod
    def _looks_textproto(data: bytes) -> bool:
        head = data[:512]
        if b"\x00" in head:
            return False
        try:
            text = head.decode("utf-8")
        except UnicodeDecodeError:
            return False
        # textproto uses "key: value" and "block {" lines
        return (":" in text or "{" in text) and all(
            (32 <= b or b in (9, 10, 13)) for b in head
        )

    def _handle_pbtxt(self, ds, data, local_fid):
        """Text-format protobuf: count top-level messages/fields structurally."""
        try:
            text = data.decode("utf-8", "replace")
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"pbtxt decode failed: {err}"
            return
        block_names: Dict[str, int] = {}
        scalar_fields = 0
        depth = 0
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.endswith("{"):
                key = line[:-1].strip().rstrip(":").strip()
                if depth == 0 and key:
                    block_names[key] = block_names.get(key, 0) + 1
                depth += 1
            elif line == "}":
                depth = max(0, depth - 1)
            elif ":" in line and depth == 0:
                scalar_fields += 1
        self._add_properties(
            ds["dataset_id"],
            {
                "kind": "textproto",
                "top_level_block_count": sum(block_names.values()),
                "top_level_scalar_fields": scalar_fields,
            },
            "textproto",
            local_fid,
        )
        for name, n in sorted(block_names.items()):
            self._add_property(
                ds["dataset_id"], f"block.{name}", n, "textproto_blocks", local_fid
            )
        ds["record_count"] = sum(block_names.values())

    # ==================================================================
    # Media handlers
    # ==================================================================
    def _handle_image(self, path, ext, category, subcategory, local_fid):
        ds = self._add_dataset(
            path,
            ext,
            category or "image",
            subcategory or "raster_common",
            "image",
            local_fid,
        )
        try:
            from PIL import Image
        except Exception as err:
            ds["analysis_status"] = "unavailable"
            ds["notes"] = f"Pillow missing: {err}"
            return
        try:
            with Image.open(path) as im:  # lazy: does not decode pixels
                props = {
                    "format": im.format,
                    "mode": im.mode,
                    "width": im.width,
                    "height": im.height,
                    "channels": len(im.getbands()),
                    "bands": ",".join(im.getbands()),
                    "is_animated": bool(getattr(im, "is_animated", False)),
                    "n_frames": int(getattr(im, "n_frames", 1)),
                }
                info = im.info or {}
                if "dpi" in info:
                    props["dpi"] = str(info.get("dpi"))
                self._add_properties(ds["dataset_id"], props, "image", local_fid)
                ds["record_count"] = props["n_frames"]
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"image open failed: {err}"
        # GeoTIFF sniff: a TIFF that carries a GeoKeyDirectory is a georeferenced
        # raster -> attach CRS / geotransform / bbox as a geospatial property group.
        base = ("." + ext.split(".")[-1]) if ext else ext
        if base in (".tif", ".tiff"):
            try:
                from .science_formats import read_geotiff_extras

                geo = read_geotiff_extras(path)
                if geo:
                    geo["driver"] = "geotiff"
                    self._add_properties(ds["dataset_id"], geo, "geospatial", local_fid)
                    ds["subcategory"] = "geospatial_raster"
            except Exception:
                pass  # ordinary (non-geo) TIFF

    def _handle_wav(self, path, ext, category, subcategory, local_fid):
        import wave

        ds = self._add_dataset(
            path,
            ext,
            category or "audio",
            subcategory or "uncompressed_pcm",
            "audio",
            local_fid,
        )
        try:
            with wave.open(str(path), "rb") as w:
                nch = w.getnchannels()
                sw = w.getsampwidth()
                fr = w.getframerate()
                nframes = w.getnframes()
                duration = (nframes / fr) if fr else None
                self._add_properties(
                    ds["dataset_id"],
                    {
                        "channels": nch,
                        "sample_width_bytes": sw,
                        "bit_depth": sw * 8,
                        "sample_rate_hz": fr,
                        "frame_count": nframes,
                        "duration_seconds": round(duration, 4) if duration else None,
                    },
                    "audio",
                    local_fid,
                )
                ds["record_count"] = nframes
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"wav header parse failed: {err}"

    def _handle_audio(self, path, ext, category, subcategory, local_fid):
        """Probe non-WAV audio. Uses soundfile/mutagen if present, else parses
        headers directly (FLAC STREAMINFO, MPEG audio frame, AIFF COMM, Sun AU)
        so common formats yield real sample_rate/channels/duration with no
        third-party dependency. Everything at least classifies as audio."""
        ds = self._add_dataset(
            path,
            ext,
            category or "audio",
            subcategory or "compressed_lossy",
            "audio",
            local_fid,
        )
        # 1) soundfile — most accurate when available (libsndfile)
        try:
            import soundfile as sf  # noqa

            info = sf.info(str(path))
            dur = (info.frames / info.samplerate) if info.samplerate else None
            self._add_properties(
                ds["dataset_id"],
                {
                    "channels": info.channels,
                    "sample_rate_hz": info.samplerate,
                    "frame_count": info.frames,
                    "duration_seconds": round(dur, 4) if dur else None,
                    "codec": info.subtype or info.format,
                    "probe": "soundfile",
                },
                "audio",
                local_fid,
            )
            ds["record_count"] = int(info.frames)
            return
        except Exception:
            pass
        # 2) mutagen — tag/stream metadata for compressed formats
        try:
            import mutagen  # noqa

            mf = mutagen.File(str(path))
            if mf is not None and getattr(mf, "info", None) is not None:
                mi = mf.info
                dur = getattr(mi, "length", None)
                props = {"probe": "mutagen"}
                for src, dst in (
                    ("sample_rate", "sample_rate_hz"),
                    ("channels", "channels"),
                    ("bitrate", "bitrate_bps"),
                    ("bits_per_sample", "bit_depth"),
                ):
                    v = getattr(mi, src, None)
                    if v:
                        props[dst] = v
                if dur:
                    props["duration_seconds"] = round(dur, 4)
                props["codec"] = type(mi).__module__.split(".")[-1]
                self._add_properties(ds["dataset_id"], props, "audio", local_fid)
                return
        except Exception:
            pass
        # 3) stdlib header parsing (no dependencies)
        try:
            props = self._audio_header_probe(path, ext)
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"audio header parse failed: {err}"
            return
        if props:
            props.setdefault("probe", "header")
            self._add_properties(ds["dataset_id"], props, "audio", local_fid)
            if "frame_count" in props:
                ds["record_count"] = props["frame_count"]
        else:
            # classified as audio but no decoder/parser matched this codec
            ds["analysis_status"] = "partial"
            ds["notes"] = (
                "audio classified; no header parser for this codec "
                "(install soundfile/mutagen for deep metadata)"
            )
            self._add_properties(
                ds["dataset_id"],
                {"codec_hint": ext.lstrip("."), "probe": "classify_only"},
                "audio",
                local_fid,
            )

    @staticmethod
    def _ieee80(b):
        """Decode a 10-byte IEEE-754 80-bit extended float (AIFF sample rate)."""
        import struct

        sign = -1 if (b[0] & 0x80) else 1
        exp = ((b[0] & 0x7F) << 8) | b[1]
        mant = struct.unpack(">Q", b[2:10])[0]
        if exp == 0 and mant == 0:
            return 0.0
        return sign * mant * (2.0 ** (exp - 16383 - 63))

    @staticmethod
    def _audio_header_probe(path, ext):
        """Return a props dict for FLAC / MPEG audio / AIFF / AU using only the
        standard library; {} if the byte signature is unrecognized."""
        import struct

        with open(path, "rb") as f:
            head = f.read(12)
        # ---- exotic containers: dependency-free parsers in science_formats ----
        from .science_formats import (
            read_ape,
            read_caf,
            read_ogg,
            read_tta,
            read_wavpack,
        )

        _exotic = {
            b"caff": read_caf,
            b"OggS": read_ogg,
            b"wvpk": read_wavpack,
            b"TTA1": read_tta,
            b"MAC ": read_ape,
        }
        _fn = _exotic.get(head[:4])
        if _fn is not None:
            try:
                return _fn(path)
            except Exception:
                pass
        # ---- FLAC: 'fLaC' then METADATA_BLOCK STREAMINFO ----
        if head[:4] == b"fLaC":
            with open(path, "rb") as f:
                f.read(4)
                _bh = f.read(4)  # block header
                info = f.read(34)  # STREAMINFO body
            if len(info) >= 18:
                sr = (info[10] << 12) | (info[11] << 4) | (info[12] >> 4)
                ch = ((info[12] >> 1) & 0x07) + 1
                bps = (((info[12] & 1) << 4) | (info[13] >> 4)) + 1
                total = (
                    ((info[13] & 0x0F) << 32)
                    | (info[14] << 24)
                    | (info[15] << 16)
                    | (info[16] << 8)
                    | info[17]
                )
                dur = (total / sr) if sr else None
                return {
                    "codec": "flac",
                    "sample_rate_hz": sr,
                    "channels": ch,
                    "bit_depth": bps,
                    "frame_count": total,
                    "duration_seconds": round(dur, 4) if dur else None,
                }
        # ---- AIFF / AIFF-C: 'FORM'....'AIFF'/'AIFC', parse COMM chunk ----
        if head[:4] == b"FORM" and head[8:12] in (b"AIFF", b"AIFC"):
            with open(path, "rb") as f:
                f.seek(12)  # past FORM/size/formType
                for _ in range(64):  # scan chunk headers
                    ch_hdr = f.read(8)
                    if len(ch_hdr) < 8:
                        break
                    cid, csize = ch_hdr[:4], struct.unpack(">I", ch_hdr[4:8])[0]
                    if cid == b"COMM":
                        body = f.read(csize)
                        nch = struct.unpack(">h", body[0:2])[0]
                        nf = struct.unpack(">I", body[2:6])[0]
                        ssize = struct.unpack(">h", body[6:8])[0]
                        sr = int(DataAnalyzer._ieee80(body[8:18]))
                        dur = (nf / sr) if sr else None
                        return {
                            "codec": "aiff",
                            "sample_rate_hz": sr,
                            "channels": nch,
                            "bit_depth": ssize,
                            "frame_count": nf,
                            "duration_seconds": round(dur, 4) if dur else None,
                        }
                    f.seek(csize + (csize & 1), 1)  # chunks are 2-byte aligned
        # ---- Sun/NeXT AU: '.snd' ----
        if head[:4] == b".snd":
            with open(path, "rb") as f:
                hdr = f.read(24)
            if len(hdr) >= 24:
                _magic, _off, data_size, enc, sr, ch = struct.unpack(">6I", hdr[:24])
                return {
                    "codec": "au",
                    "sample_rate_hz": sr,
                    "channels": ch,
                    "encoding_id": enc,
                }
        # ---- MPEG audio (mp3/mp2): skip ID3v2, read first frame header ----
        with open(path, "rb") as f:
            raw = f.read(10)
            if raw[:3] == b"ID3":
                size = (
                    ((raw[6] & 0x7F) << 21)
                    | ((raw[7] & 0x7F) << 14)
                    | ((raw[8] & 0x7F) << 7)
                    | (raw[9] & 0x7F)
                )
                f.seek(10 + size)
            else:
                f.seek(0)
            buf = f.read(4096)
        i = buf.find(b"\xff")
        _BR = {  # V1L3 bitrate table (kbps), index by 4-bit field
            1: [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0],
        }
        _SR = {
            0: [44100, 48000, 32000],
            3: [44100, 48000, 32000],
            2: [22050, 24000, 16000],
            1: [11025, 12000, 8000],
        }
        while i != -1 and i + 4 <= len(buf):
            if buf[i] == 0xFF and (buf[i + 1] & 0xE0) == 0xE0:
                b1, b2 = buf[i + 1], buf[i + 2]
                ver = (b1 >> 3) & 0x03  # 3=MPEG1,2=MPEG2,0=MPEG2.5
                layer = (b1 >> 1) & 0x03  # 1=L3
                br_i = (b2 >> 4) & 0x0F
                sr_i = (b2 >> 2) & 0x03
                ch_mode = (buf[i + 3] >> 6) & 0x03
                if br_i not in (0, 15) and sr_i != 3 and ver in _SR:
                    sr = _SR[ver][sr_i]
                    br = _BR[1][br_i] * 1000
                    return {
                        "codec": "mp3" if layer == 1 else "mpeg_audio",
                        "sample_rate_hz": sr,
                        "bitrate_bps": br,
                        "channels": 1 if ch_mode == 3 else 2,
                        "mpeg_version": {3: 1, 2: 2, 0: 2.5}.get(ver),
                    }
            i = buf.find(b"\xff", i + 1)
        return {}

    def _handle_video(self, path, ext, category, subcategory, local_fid):
        ds = self._add_dataset(
            path,
            ext,
            category or "video",
            subcategory or "containers_common",
            "video",
            local_fid,
        )
        try:
            import cv2
        except Exception as err:
            ds["analysis_status"] = "unavailable"
            ds["notes"] = f"opencv missing: {err}"
            return
        try:
            cap = cv2.VideoCapture(str(path))
            if not cap.isOpened():
                ds["analysis_status"] = "partial"
                ds["notes"] = "video could not be opened"
                cap.release()
                return
            fps = cap.get(cv2.CAP_PROP_FPS)
            frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            fourcc_int = int(cap.get(cv2.CAP_PROP_FOURCC))
            fourcc = "".join(
                chr((fourcc_int >> (8 * i)) & 0xFF) for i in range(4)
            ).strip("\x00")
            duration = (frames / fps) if fps else None
            cap.release()
            self._add_properties(
                ds["dataset_id"],
                {
                    "width": width,
                    "height": height,
                    "fps": round(fps, 4) if fps else None,
                    "frame_count": frames,
                    "duration_seconds": round(duration, 3) if duration else None,
                    "codec_fourcc": fourcc or None,
                },
                "video",
                local_fid,
            )
            ds["record_count"] = frames
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"video probe failed: {err}"

    # ==================================================================
    # Document handlers
    # ==================================================================
    def _handle_pdf(self, path, ext, category, subcategory, local_fid):
        ds = self._add_dataset(
            path,
            ext,
            category or "text",
            subcategory or "page_description_and_print",
            "document",
            local_fid,
        )
        try:
            from pypdf import PdfReader
        except Exception as err:
            ds["analysis_status"] = "unavailable"
            ds["notes"] = f"pypdf missing: {err}"
            return
        try:
            reader = PdfReader(path)
            npages = len(reader.pages)
            ds["record_count"] = npages
            props = {"page_count": npages, "encrypted": bool(reader.is_encrypted)}
            meta = reader.metadata or {}
            for k in ("title", "author", "subject", "creator", "producer"):
                v = getattr(meta, k, None)
                if v:
                    props[k] = str(v)[:256]
            self._add_properties(ds["dataset_id"], props, "pdf", local_fid)
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"pdf parse failed: {err}"

    def _handle_docx(self, path, ext, category, subcategory, local_fid):
        import zipfile

        ds = self._add_dataset(
            path,
            ext,
            category or "text",
            subcategory or "word_processing",
            "document",
            local_fid,
        )
        try:
            zf = zipfile.ZipFile(path)
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"docx open failed: {err}"
            return
        try:
            try:
                xml = zf.read("word/document.xml").decode("utf-8", errors="replace")
            except KeyError:
                ds["analysis_status"] = "partial"
                ds["notes"] = "no word/document.xml (not a Word docx?)"
                return
            paragraphs = xml.count("<w:p ") + xml.count("<w:p>")
            texts = re.findall(r"<w:t[^>]*>(.*?)</w:t>", xml, re.S)
            joined = " ".join(texts)
            word_count = len(joined.split())
            char_count = len(joined)
            props = {
                "paragraph_count": paragraphs,
                "word_count": word_count,
                "char_count": char_count,
            }
            try:
                core = zf.read("docProps/core.xml").decode("utf-8", errors="replace")
                for tag in ("dc:title", "dc:creator", "dc:subject"):
                    m = re.search(rf"<{tag}>(.*?)</{tag}>", core, re.S)
                    if m and m.group(1).strip():
                        props[tag.replace(":", "_")] = m.group(1).strip()[:256]
            except KeyError:
                pass
            self._add_properties(ds["dataset_id"], props, "docx", local_fid)
        finally:
            zf.close()

    def _handle_text(self, path, ext, category, subcategory, local_fid):
        ds = self._add_dataset(
            path,
            ext,
            category or "text",
            subcategory or "plain_and_lightweight_markup",
            "text",
            local_fid,
        )
        lines = words = chars = 0
        scanned = 0
        truncated = False
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    lines += 1
                    chars += len(line)
                    words += len(line.split())
                    scanned += len(line.encode("utf-8", errors="ignore"))
                    if scanned >= self.MAX_TEXT_SCAN_BYTES:
                        truncated = True
                        break
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"text scan failed: {err}"
            return
        ds["record_count"] = lines
        self._add_properties(
            ds["dataset_id"],
            {
                "line_count": lines,
                "word_count": words,
                "char_count": chars,
                "scan_truncated": truncated,
            },
            "text",
            local_fid,
        )

    def _handle_pickle(self, path, ext, category, subcategory, local_fid):
        import pickletools

        ds = self._add_dataset(
            path,
            ext,
            category or "data",
            subcategory or "serialization_binary",
            "serialized",
            local_fid,
        )
        globals_seen = {}
        opcodes = 0
        proto = None
        try:
            with open(path, "rb") as f:
                for opcode, arg, _pos in pickletools.genops(f):
                    opcodes += 1
                    if opcode.name == "PROTO":
                        proto = arg
                    elif opcode.name in ("GLOBAL", "STACK_GLOBAL") and arg:
                        key = str(arg).replace("\n", ".")[:128]
                        globals_seen[key] = globals_seen.get(key, 0) + 1
                    if opcodes >= self.MAX_PICKLE_OPS:
                        break
        except Exception as err:
            # joblib/dill or compressed pickle: opcode scan not possible
            ds["analysis_status"] = "partial"
            ds["notes"] = f"opcode scan unavailable (compressed/wrapped?): {err}"
            return
        self._add_properties(
            ds["dataset_id"],
            {
                "pickle_protocol": proto,
                "opcode_count": opcodes,
                "opcode_scan_truncated": opcodes >= self.MAX_PICKLE_OPS,
                "distinct_globals": len(globals_seen),
            },
            "pickle",
            local_fid,
        )
        for gname, cnt in list(sorted(globals_seen.items(), key=lambda kv: -kv[1]))[
            :50
        ]:
            self._add_property(
                ds["dataset_id"], f"global::{gname}", cnt, "pickle_globals", local_fid
            )

    def _handle_generic(self, path, ext, category, subcategory, local_fid):
        modality = "binary"
        if category == "text":
            modality = "text"
        ds = self._add_dataset(path, ext, category, subcategory, modality, local_fid)
        magic = self._read_magic(path, 16)
        if magic:
            self._add_property(
                ds["dataset_id"], "magic_hex", magic.hex(), "binary", local_fid
            )
        ds["analysis_status"] = "generic"

    # ==================================================================
    # Catalogued text/binary families (real grammar / documented-header
    # parsers in catalog_text_formats.py & catalog_binary_formats.py).
    # ==================================================================
    def _handle_catalog_text(self, path, ext, category, subcategory, local_fid):
        """Real structure parse for a catalogued text family (subtitles, RDF,
        iCalendar, notebooks, EDI/HL7, Gerber, STEP, BibTeX, ...).  Degrades to
        genuine text metrics on malformed input, never a stub."""
        from . import catalog_text_formats as ctf

        base = ("." + ext.split(".")[-1]) if ext else ext
        lead = ext if ext in ctf.FAMILY_OF else base
        result = ctf.analyze(path, lead)
        ds = self._add_dataset(
            path,
            ext,
            category or "data",
            result["subcategory"],
            result["modality"],
            local_fid,
            status=result["status"],
            notes=f"catalog-text:{result['family']}",
        )
        if result.get("record_count") is not None:
            ds["record_count"] = result["record_count"]
        props = result["props"]
        self._add_properties(ds["dataset_id"], props, result["family"], local_fid)
        cols = result.get("columns")
        if cols:
            ds["column_count"] = len(cols)
            for i, col in enumerate(cols):
                self._add_column(
                    ds["dataset_id"],
                    str(col.get("name", f"col{i}")),
                    i,
                    str(col.get("dtype", "unknown")),
                    "declared",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    [],
                    {},
                    local_fid,
                )

    def _handle_catalog_assets(self, path, ext, category, subcategory, local_fid):
        """Real structure parse for a catalogued text-based asset family
        (shader source, ML-model text, vector drawing, world file, ringtone,
        VTK grid).  Emits columns/tensors/model_layers as the family yields
        them.  Degrades to genuine text metrics on malformed input, never a
        stub."""
        from . import asset_text_formats as atf

        base = ("." + ext.split(".")[-1]) if ext else ext
        lead = ext if ext in atf.FAMILY_OF else base
        result = atf.analyze(path, lead)
        ds = self._add_dataset(
            path,
            ext,
            category or "data",
            result["subcategory"],
            result["modality"],
            local_fid,
            status=result["status"],
            notes=f"asset:{result['family']}",
        )
        if result.get("record_count") is not None:
            ds["record_count"] = result["record_count"]
        self._add_properties(
            ds["dataset_id"], result["props"], result["family"], local_fid
        )
        cols = result.get("columns")
        if cols:
            ds["column_count"] = len(cols)
            for i, col in enumerate(cols):
                self._add_column(
                    ds["dataset_id"],
                    str(col.get("name", f"col{i}")),
                    i,
                    str(col.get("dtype", "unknown")),
                    "declared",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    [],
                    {"qualifier": col["qualifier"]} if col.get("qualifier") else {},
                    local_fid,
                )
        tensors = result.get("tensors")
        if tensors:
            ds["tensor_count"] = len(tensors)
            for t in tensors:
                self._add_tensor(
                    ds["dataset_id"],
                    str(t.get("name", "tensor")),
                    t.get("dtype"),
                    t.get("shape") or [],
                    t.get("num_bytes"),
                    t.get("extra") or {},
                    local_fid,
                )
        layers = result.get("model_layers")
        if layers:
            for lyr in layers:
                self._add_model_layer(
                    ds["dataset_id"],
                    str(lyr.get("layer_name", "layer")),
                    str(lyr.get("layer_type", "layer")),
                    int(lyr.get("ordinal", 0)),
                    int(lyr.get("depth", 0)),
                    int(lyr.get("tensor_count", 0)),
                    int(lyr.get("param_tensor_count", 0)),
                    int(lyr.get("buffer_tensor_count", 0)),
                    lyr.get("total_parameters"),
                    lyr.get("total_buffer_elements"),
                    lyr.get("total_bytes"),
                    lyr.get("dtypes") or [],
                    lyr.get("param_shapes") or {},
                    lyr.get("roles") or {},
                    local_fid,
                )

    def _handle_catalog_binary(self, path, ext, category, subcategory, local_fid):
        """Documented-header parse (FITS/SEG-Y/pcap/tracker/...) when the format
        is readable, else honest forensic metadata (size/sha256/magic/entropy/
        printable-ratio) with structural_parse=False.  Never fabricates or
        stores payload."""
        from . import catalog_binary_formats as cbf

        base = ("." + ext.split(".")[-1]) if ext else ext
        lead = ext if (ext in cbf._DOCUMENTED or ext in cbf._FORENSIC_SUB) else base
        result = cbf.analyze(path, lead)
        ds = self._add_dataset(
            path,
            ext,
            category or "data",
            result["subcategory"],
            result["modality"],
            local_fid,
            status=result["status"],
            notes=f"catalog-binary:{result['family']}",
        )
        if result.get("record_count") is not None:
            ds["record_count"] = result["record_count"]
        self._add_properties(
            ds["dataset_id"], result["props"], result["family"], local_fid
        )

    # ==================================================================
    # Scientific / imaging containers (dependency-free header parsers;
    # optional GDAL / pydicom / nibabel / rawpy / open3d acceleration)
    # ==================================================================
    def _handle_georaster(self, path, ext, category, subcategory, local_fid):
        """Geospatial raster metadata: dimensions, CRS/EPSG, geotransform, bbox.
        Parses GDAL .vrt XML, ESRI/Arc ASCII grids and classic NetCDF headers
        directly; uses GDAL only if it happens to be importable."""
        from . import science_formats as sf

        base = ("." + ext.split(".")[-1]) if ext else ext
        ds = self._add_dataset(
            path,
            ext,
            category or "geospatial",
            subcategory or "geospatial_raster",
            "geospatial",
            local_fid,
        )
        # optional GDAL fast path
        try:
            from osgeo import gdal  # noqa

            gdal.UseExceptions()
            g = gdal.Open(str(path))
            if g is not None:
                info = {
                    "driver": g.GetDriver().ShortName,
                    "width": g.RasterXSize,
                    "height": g.RasterYSize,
                    "band_count": g.RasterCount,
                }
                proj = g.GetProjection()
                if proj:
                    info["crs"] = proj[:200]
                gt = g.GetGeoTransform()
                if gt:
                    info["origin"] = [gt[0], gt[3]]
                    info["pixel_scale"] = [gt[1], abs(gt[5])]
                    xs = [gt[0], gt[0] + gt[1] * g.RasterXSize]
                    ys = [gt[3], gt[3] + gt[5] * g.RasterYSize]
                    info["bbox"] = [min(xs), min(ys), max(xs), max(ys)]
                info["probe"] = "gdal"
                self._emit_raster(ds, info, local_fid)
                return
        except Exception:
            pass
        try:
            if base == ".vrt":
                info = sf.read_vrt(path)
            elif base in (".nc", ".cdf", ".nc4"):
                info = sf.read_netcdf_classic(path)
                self._emit_netcdf(ds, info, local_fid)
                return
            else:
                info = sf.read_esri_ascii_grid(path)
            info.setdefault("probe", "header")
            self._emit_raster(ds, info, local_fid)
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"georaster header parse failed: {err}"
            m = self._read_magic(path, 16)
            if m:
                self._add_property(
                    ds["dataset_id"], "magic_hex", m.hex(), "binary", local_fid
                )

    def _emit_raster(self, ds, info, local_fid):
        """Shared raster emitter: geospatial props (+ a tensor when H/W known)."""
        w, h = info.get("width"), info.get("height")
        bands = info.get("band_count")
        self._add_properties(ds["dataset_id"], info, "geospatial", local_fid)
        if w and h:
            shape = [h, w] if not bands else [bands, h, w]
            self._add_tensor(
                ds["dataset_id"],
                "raster",
                info.get("data_type"),
                shape,
                None,
                {"driver": info.get("driver")},
                local_fid,
            )
            ds["tensor_count"] = 1
            ds["record_count"] = w * h

    def _emit_netcdf(self, ds, info, local_fid):
        self._add_properties(
            ds["dataset_id"],
            {
                "driver": info.get("driver"),
                "version": info.get("version"),
                "dimension_count": info.get("dimension_count"),
                "variable_count": info.get("variable_count"),
                "probe": "header",
            },
            "geospatial",
            local_fid,
        )
        for d in info.get("dimensions", [])[:200]:
            self._add_property(
                ds["dataset_id"],
                "dim::" + str(d["name"]),
                d["size"],
                "netcdf_dimensions",
                local_fid,
            )
        n = 0
        for v in info.get("variables", []):
            self._add_tensor(
                ds["dataset_id"],
                v["name"],
                v.get("dtype"),
                v.get("shape", []),
                None,
                {"dims": v.get("dims", [])},
                local_fid,
            )
            n += 1
        ds["tensor_count"] = n
        ds["record_count"] = info.get("variable_count")

    def _handle_medical(self, path, ext, category, subcategory, local_fid):
        """Medical imaging metadata. DICOM technical tags only (never patient
        identity or pixel data); NIfTI / NRRD / MGH volumes -> shape+dtype+voxel.
        Uses pydicom / nibabel when importable, else parses headers directly."""
        from . import science_formats as sf

        base = ("." + ext.split(".")[-1]) if ext else ext
        ds = self._add_dataset(
            path,
            ext,
            category or "image",
            subcategory or "medical_imaging",
            "medical",
            local_fid,
        )
        try:
            if base in (".dcm", ".dicom", ".ima"):
                info = self._medical_dicom(path, sf)
                grp = "dicom"
            elif base in (".nii",):
                info = self._medical_nifti(path, sf)
                grp = "nifti"
            elif base in (".nrrd", ".nhdr"):
                info = sf.read_nrrd(path)
                grp = "nrrd"
            elif base in (".mgh", ".mgz"):
                info = self._medical_nibabel_or(path, sf.read_mgh)
                grp = "mgh"
            elif base in (".hdr", ".img"):
                info = self._medical_nibabel_or(path, sf.read_nifti)
                grp = "analyze"
            else:
                info = sf.read_dicom(path)
                grp = "dicom"
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"medical header parse failed: {err}"
            return
        self._add_properties(ds["dataset_id"], info, grp, local_fid)
        # volume shape -> tensor
        shape = info.get("shape")
        if not shape and info.get("rows") and info.get("columns"):
            frames = info.get("number_of_frames") or 1
            shape = (
                [frames, info["rows"], info["columns"]]
                if frames and frames > 1
                else [info["rows"], info["columns"]]
            )
        if shape:
            self._add_tensor(
                ds["dataset_id"],
                "volume",
                info.get("dtype"),
                shape,
                None,
                {"modality": info.get("modality")},
                local_fid,
            )
            ds["tensor_count"] = 1
            n = 1
            for d in shape:
                try:
                    n *= int(d)
                except (TypeError, ValueError):
                    n = None
                    break
            ds["record_count"] = n

    def _medical_dicom(self, path, sf):
        try:
            import pydicom

            dcm = pydicom.dcmread(str(path), stop_before_pixels=True, force=True)
            info = {}
            # technical, non-identifying tags only
            for attr, key in (
                ("Modality", "modality"),
                ("Manufacturer", "manufacturer"),
                ("Rows", "rows"),
                ("Columns", "columns"),
                ("BitsAllocated", "bits_allocated"),
                ("PixelRepresentation", "pixel_representation"),
                ("SamplesPerPixel", "samples_per_pixel"),
                ("PhotometricInterpretation", "photometric_interpretation"),
                ("NumberOfFrames", "number_of_frames"),
                ("SeriesDescription", "series_description"),
            ):
                v = getattr(dcm, attr, None)
                if v is not None:
                    info[key] = (
                        int(v)
                        if key
                        in (
                            "rows",
                            "columns",
                            "bits_allocated",
                            "pixel_representation",
                            "samples_per_pixel",
                            "number_of_frames",
                        )
                        else str(v)[:128]
                    )
            info["dtype"] = self._dicom_dtype(info)
            info["probe"] = "pydicom"
            return info
        except Exception:
            info = sf.read_dicom(path)
            info["dtype"] = self._dicom_dtype(info)
            return info

    @staticmethod
    def _dicom_dtype(info):
        ba = info.get("bits_allocated")
        if not ba:
            return None
        signed = info.get("pixel_representation") == 1
        return ("int%d" if signed else "uint%d") % ba

    def _medical_nifti(self, path, sf):
        info = self._medical_nibabel_or(path, sf.read_nifti)
        return info

    @staticmethod
    def _medical_nibabel_or(path, fallback):
        try:
            import nibabel as nib

            img = nib.load(str(path))
            hdr = img.header
            zooms = [round(float(z), 6) for z in hdr.get_zooms()]
            return {
                "format": type(img).__name__,
                # cast away numpy scalar types so rows stay JSON-serializable
                "shape": [int(x) for x in img.shape],
                "dtype": str(hdr.get_data_dtype()),
                "voxel_sizes": zooms,
                "probe": "nibabel",
            }
        except Exception:
            return fallback(path)

    def _handle_camera_raw(self, path, ext, category, subcategory, local_fid):
        """Camera-raw metadata (make/model/dimensions/CFA) from TIFF-IFD raws and
        RAF/CR3/X3F containers. Uses rawpy only if importable; parses otherwise."""
        from . import science_formats as sf

        ds = self._add_dataset(
            path,
            ext,
            category or "image",
            subcategory or "camera_raw",
            "image",
            local_fid,
        )
        # optional rawpy fast path (exact sensor dimensions)
        try:
            import rawpy

            with rawpy.imread(str(path)) as r:
                s = r.sizes
                info = {
                    "width": s.raw_width,
                    "height": s.raw_height,
                    "processed_width": s.width,
                    "processed_height": s.height,
                    "colors": r.num_colors,
                    "probe": "rawpy",
                }
                self._add_properties(ds["dataset_id"], info, "camera_raw", local_fid)
                self._add_tensor(
                    ds["dataset_id"],
                    "sensor",
                    "uint16",
                    [s.raw_height, s.raw_width],
                    None,
                    {"cfa": True},
                    local_fid,
                )
                ds["tensor_count"] = 1
                ds["record_count"] = s.raw_width * s.raw_height
                return
        except Exception:
            pass
        try:
            info = sf.read_camera_raw(path, ext)
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"raw header parse failed: {err}"
            return
        info.setdefault("probe", "header")
        self._add_properties(ds["dataset_id"], info, "camera_raw", local_fid)
        w, h = info.get("width"), info.get("height")
        if w and h:
            self._add_tensor(
                ds["dataset_id"],
                "ifd0_image",
                None,
                [h, w],
                None,
                {"note": "IFD0 may be an embedded preview"},
                local_fid,
            )
            ds["tensor_count"] = 1
            ds["record_count"] = w * h

    def _handle_pointcloud(self, path, ext, category, subcategory, local_fid):
        """Point-cloud volume metadata: point counts, fields, bounding box.
        Parses PCD / ASPRS LAS-LAZ / ASTM E57 headers directly (no point payload
        is iterated); uses laspy / open3d only if importable."""
        from . import science_formats as sf

        base = ("." + ext.split(".")[-1]) if ext else ext
        ds = self._add_dataset(
            path,
            ext,
            category or "geometry",
            subcategory or "point_cloud",
            "geometry",
            local_fid,
        )
        try:
            if base == ".pcd":
                info = sf.read_pcd(path)
                self._emit_geometry(
                    ds,
                    local_fid,
                    points=info.get("point_count"),
                    attributes=info.get("fields"),
                    props={
                        k: v
                        for k, v in info.items()
                        if k
                        in (
                            "format",
                            "encoding",
                            "pcd_version",
                            "width",
                            "height",
                            "field_types",
                            "field_count",
                        )
                    },
                )
                return
            if base in (".las", ".laz"):
                info = self._pointcloud_las(path, sf)
            elif base == ".e57":
                info = sf.read_e57(path)
            else:
                info = sf.read_pcd(path)
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"point-cloud header parse failed: {err}"
            return
        bbox = info.get("bbox")  # [minx,miny,minz,maxx,maxy,maxz]
        props = {
            k: v
            for k, v in info.items()
            if k
            in (
                "format",
                "las_version",
                "e57_version",
                "point_format",
                "compressed",
                "scale",
                "offset",
                "scan_count",
                "point_record_length",
                "crs",
                "probe",
            )
        }
        self._emit_geometry(
            ds,
            local_fid,
            points=info.get("point_count"),
            bbox=bbox if bbox and len(bbox) == 6 else None,
            props=props,
        )

    def _pointcloud_las(self, path, sf):
        try:
            import laspy

            with laspy.open(str(path)) as fh:
                h = fh.header
                mins, maxs = list(h.mins), list(h.maxs)
                return {
                    "format": "laz" if str(path).lower().endswith(".laz") else "las",
                    "las_version": "%d.%d" % (h.version.major, h.version.minor),
                    "point_format": h.point_format.id,
                    "point_count": h.point_count,
                    "scale": list(h.scales),
                    "offset": list(h.offsets),
                    "bbox": [mins[0], mins[1], mins[2], maxs[0], maxs[1], maxs[2]],
                    "probe": "laspy",
                }
        except Exception:
            return sf.read_las(path)

    # ==================================================================
    # Structured-data helpers (geometry / geo / graph shared primitives)
    # ==================================================================
    def _read_text_head(self, path: Path, max_bytes: int) -> str:
        """Read up to ``max_bytes`` of ``path`` decoded as UTF-8 (lossy)."""
        try:
            with open(path, "rb") as fh:
                raw = fh.read(max_bytes)
        except OSError:
            return ""
        return raw.decode("utf-8", "replace")

    @staticmethod
    def _data_line_gen(fh, comment: str = "#"):
        """Yield stripped, non-blank, non-comment lines from an open handle."""
        for line in fh:
            s = line.strip()
            if not s or (comment and s.startswith(comment)):
                continue
            yield s

    @staticmethod
    def _new_bbox():
        return [None, None, None, None, None, None]  # minx,miny,minz,maxx,maxy,maxz

    @staticmethod
    def _bbox_add(bb, x, y, z=None):
        vals = (x, y, z)
        for i in range(3):
            v = vals[i]
            if v is None:
                continue
            if bb[i] is None or v < bb[i]:
                bb[i] = v
            if bb[i + 3] is None or v > bb[i + 3]:
                bb[i + 3] = v

    @staticmethod
    def _bb2_new():
        return [None, None, None, None]  # minx, miny, maxx, maxy

    @staticmethod
    def _bb2_add(bb, x, y):
        if x is not None:
            if bb[0] is None or x < bb[0]:
                bb[0] = x
            if bb[2] is None or x > bb[2]:
                bb[2] = x
        if y is not None:
            if bb[1] is None or y < bb[1]:
                bb[1] = y
            if bb[3] is None or y > bb[3]:
                bb[3] = y

    def _emit_geometry(
        self,
        ds,
        local_fid,
        *,
        vertices=None,
        faces=None,
        points=None,
        edges=None,
        cells=None,
        bbox=None,
        attributes=None,
        props=None,
    ):
        primary = next(
            (v for v in (vertices, points, cells, faces) if v is not None), None
        )
        if primary is not None:
            ds["record_count"] = primary
        p: Dict[str, Any] = {}
        if vertices is not None:
            p["vertex_count"] = vertices
        if faces is not None:
            p["face_count"] = faces
        if points is not None:
            p["point_count"] = points
        if edges is not None:
            p["edge_count"] = edges
        if cells is not None:
            p["cell_count"] = cells
        if attributes:
            p["attribute_count"] = len(attributes)
            p["attributes"] = list(attributes)[:100]
        if bbox and any(v is not None for v in bbox):
            p["bbox_min"] = [bbox[0], bbox[1], bbox[2]]
            p["bbox_max"] = [bbox[3], bbox[4], bbox[5]]
        if props:
            p.update(props)
        self._add_properties(ds["dataset_id"], p, "geometry", local_fid)

    def _emit_geo(
        self,
        ds,
        local_fid,
        *,
        features=None,
        geometries=None,
        crs=None,
        bbox=None,
        geom_types=None,
        props=None,
    ):
        if features is not None:
            ds["record_count"] = features
        elif geometries is not None:
            ds["record_count"] = geometries
        p: Dict[str, Any] = {}
        if features is not None:
            p["feature_count"] = features
        if geometries is not None:
            p["geometry_count"] = geometries
        if crs:
            p["crs"] = crs
        if geom_types:
            p["geometry_types"] = geom_types
        if bbox and any(v is not None for v in bbox):
            p["bbox"] = list(bbox)
        if props:
            p.update(props)
        self._add_properties(ds["dataset_id"], p, "geospatial", local_fid)

    def _emit_graph(
        self,
        ds,
        local_fid,
        *,
        nodes=None,
        edges=None,
        directed=None,
        attributes=None,
        props=None,
    ):
        if nodes is not None:
            ds["record_count"] = nodes
        p: Dict[str, Any] = {}
        if nodes is not None:
            p["node_count"] = nodes
        if edges is not None:
            p["edge_count"] = edges
        if directed is not None:
            p["directed"] = directed
        if attributes:
            p["attribute_count"] = len(attributes)
            p["attributes"] = list(attributes)[:100]
        if props:
            p.update(props)
        self._add_properties(ds["dataset_id"], p, "graph", local_fid)

    def _emit_config(
        self,
        ds,
        local_fid,
        *,
        keys=None,
        sections=None,
        section_names=None,
        fmt=None,
        props=None,
    ):
        if keys is not None:
            ds["record_count"] = keys
        p: Dict[str, Any] = {}
        if keys is not None:
            p["key_count"] = keys
        if sections is not None:
            p["section_count"] = sections
        if section_names:
            p["sections"] = list(section_names)[:200]
        if fmt:
            p["config_format"] = fmt
        if props:
            p.update(props)
        self._add_properties(ds["dataset_id"], p, "config", local_fid)

    def _emit_bio(self, ds, local_fid, *, records=None, sequences=None, props=None):
        primary = records if records is not None else sequences
        if primary is not None:
            ds["record_count"] = primary
        p: Dict[str, Any] = {}
        if records is not None:
            p["record_count"] = records
        if sequences is not None:
            p["sequence_count"] = sequences
        if props:
            p.update(props)
        self._add_properties(ds["dataset_id"], p, "bioinformatics", local_fid)

    # ==================================================================
    # 3D / geometry handlers  (vertex/face/point counts, bbox, attributes)
    # ==================================================================
    def _handle_mesh(self, path, ext, category, subcategory, local_fid):
        base = ("." + ext.split(".")[-1]) if ext else ext
        ds = self._add_dataset(
            path,
            ext,
            category or "geometry",
            subcategory or "mesh_3d",
            "geometry",
            local_fid,
        )
        parser = {
            ".obj": self._mesh_obj,
            ".off": self._mesh_off,
            ".ply": self._mesh_ply,
            ".stl": self._mesh_stl,
            ".xyz": self._mesh_pointcloud,
            ".pts": self._mesh_pointcloud,
            ".gltf": self._mesh_gltf,
            ".msh": self._mesh_gmsh,
            ".vtu": self._mesh_vtk_xml,
            ".vtp": self._mesh_vtk_xml,
            ".vti": self._mesh_vtk_xml,
            ".dae": self._mesh_collada,
            ".x3d": self._mesh_x3d,
            ".usda": self._mesh_usd,
            ".mtl": self._mesh_mtl,
        }.get(base)
        if parser is None:
            ds["analysis_status"] = "generic"
            return
        try:
            parser(path, ds, local_fid)
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"mesh parse failed: {err}"

    def _mesh_obj(self, path, ds, local_fid):
        v = f = vn = vt = vp = groups = objects = 0
        usemtl = set()
        bb = self._new_bbox()
        scanned = 0
        trunc = False
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                scanned += len(line)
                if scanned > self.MAX_STRUCT_SCAN_BYTES:
                    trunc = True
                    break
                if not line or line[0] == "#":
                    continue
                t = line.split()
                if not t:
                    continue
                k = t[0]
                if k == "v":
                    v += 1
                    try:
                        self._bbox_add(
                            bb,
                            float(t[1]),
                            float(t[2]),
                            float(t[3]) if len(t) > 3 else None,
                        )
                    except (ValueError, IndexError):
                        pass
                elif k == "f":
                    f += 1
                elif k == "vn":
                    vn += 1
                elif k == "vt":
                    vt += 1
                elif k == "vp":
                    vp += 1
                elif k == "g":
                    groups += 1
                elif k == "o":
                    objects += 1
                elif k == "usemtl" and len(t) > 1:
                    usemtl.add(t[1])
        attrs = []
        if vn:
            attrs.append("normals")
        if vt:
            attrs.append("texcoords")
        if vp:
            attrs.append("parameter_space")
        self._emit_geometry(
            ds,
            local_fid,
            vertices=v,
            faces=f,
            bbox=bb,
            attributes=attrs or None,
            props={
                "normal_count": vn or None,
                "texcoord_count": vt or None,
                "group_count": groups or None,
                "object_count": objects or None,
                "material_refs": len(usemtl) or None,
                "scan_truncated": trunc,
            },
        )

    def _mesh_off(self, path, ds, local_fid):
        bb = self._new_bbox()
        nverts = nfaces = nedges = None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = self._data_line_gen(fh)
            header = next(lines, "OFF")
            parts = header.split()
            magic = bool(parts) and parts[0].endswith("OFF")
            if magic and len(parts) >= 4:
                counts = parts[1:4]
            elif magic:
                counts = (next(lines, "")).split()[:3]
            else:
                counts = parts[:3]
            try:
                nverts = int(counts[0])
                nfaces = int(counts[1])
                nedges = int(counts[2])
            except (ValueError, IndexError):
                pass
            if nverts:
                for _ in range(min(nverts, self.MAX_GEOM_VERTS)):
                    vl = next(lines, None)
                    if vl is None:
                        break
                    c = vl.split()
                    try:
                        self._bbox_add(
                            bb,
                            float(c[0]),
                            float(c[1]),
                            float(c[2]) if len(c) > 2 else None,
                        )
                    except (ValueError, IndexError):
                        pass
        self._emit_geometry(
            ds, local_fid, vertices=nverts, faces=nfaces, edges=nedges or None, bbox=bb
        )

    def _mesh_ply(self, path, ds, local_fid):
        bb = self._new_bbox()
        fmt = None
        elements = []  # [name, count]
        vprops = []
        cur = None
        with open(path, "rb") as fh:
            while True:
                raw = fh.readline()
                if not raw:
                    break
                s = raw.decode("ascii", "replace").strip()
                if s == "end_header":
                    break
                t = s.split()
                if not t:
                    continue
                if t[0] == "format" and len(t) > 1:
                    fmt = t[1]
                elif t[0] == "element" and len(t) >= 3:
                    cur = t[1]
                    try:
                        elements.append([t[1], int(t[2])])
                    except ValueError:
                        elements.append([t[1], None])
                elif t[0] == "property" and cur == "vertex":
                    vprops.append(t[-1])
            vcount = next((c for n, c in elements if n == "vertex"), None)
            fcount = next((c for n, c in elements if n == "face"), None)
            ecount = next((c for n, c in elements if n == "edge"), None)
            if fmt == "ascii" and vcount:
                try:
                    ix = vprops.index("x")
                    iy = vprops.index("y")
                    iz = vprops.index("z") if "z" in vprops else None
                except ValueError:
                    ix, iy = 0, 1
                    iz = 2 if len(vprops) > 2 else None
                for _ in range(min(vcount, self.MAX_GEOM_VERTS)):
                    raw = fh.readline()
                    if not raw:
                        break
                    c = raw.split()
                    try:
                        z = float(c[iz]) if iz is not None and len(c) > iz else None
                        self._bbox_add(bb, float(c[ix]), float(c[iy]), z)
                    except (ValueError, IndexError):
                        pass
        self._emit_geometry(
            ds,
            local_fid,
            vertices=vcount,
            faces=fcount,
            edges=ecount or None,
            bbox=bb,
            attributes=vprops or None,
            props={"ply_format": fmt, "elements": {n: c for n, c in elements}},
        )

    def _mesh_stl(self, path, ds, local_fid):
        import struct

        bb = self._new_bbox()
        head = self._read_magic(path, 84)
        is_ascii = head[:5].lower() == b"solid"
        if is_ascii and b"facet" not in head.lower():
            # some binary writers also start with "solid"; confirm with a wider read
            with open(path, "rb") as fh:
                probe = fh.read(512).lower()
            if b"facet" not in probe and b"normal" not in probe:
                is_ascii = False
        if is_ascii:
            facets = verts = 0
            scanned = 0
            trunc = False
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    scanned += len(line)
                    if scanned > self.MAX_STRUCT_SCAN_BYTES:
                        trunc = True
                        break
                    s = line.strip()
                    if s.startswith("facet"):
                        facets += 1
                    elif s.startswith("vertex"):
                        verts += 1
                        c = s.split()
                        try:
                            self._bbox_add(bb, float(c[1]), float(c[2]), float(c[3]))
                        except (ValueError, IndexError):
                            pass
            self._emit_geometry(
                ds,
                local_fid,
                vertices=verts,
                faces=facets,
                bbox=bb,
                props={"stl_format": "ascii", "scan_truncated": trunc},
            )
        else:
            with open(path, "rb") as fh:
                fh.seek(80)
                cnt_raw = fh.read(4)
                if len(cnt_raw) < 4:
                    ds["analysis_status"] = "partial"
                    ds["notes"] = "binary STL truncated header"
                    return
                ntri = struct.unpack("<I", cnt_raw)[0]
                for _ in range(min(ntri, self.MAX_GEOM_VERTS)):
                    rec = fh.read(50)
                    if len(rec) < 50:
                        break
                    vals = struct.unpack("<12fH", rec)
                    for kk in range(3):
                        self._bbox_add(
                            bb, vals[3 + 3 * kk], vals[4 + 3 * kk], vals[5 + 3 * kk]
                        )
            self._emit_geometry(
                ds,
                local_fid,
                vertices=ntri * 3,
                faces=ntri,
                bbox=bb,
                props={"stl_format": "binary"},
            )

    def _mesh_pointcloud(self, path, ds, local_fid):
        bb = self._new_bbox()
        pts = maxcols = 0
        scanned = 0
        trunc = False
        first = True
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                scanned += len(line)
                if scanned > self.MAX_STRUCT_SCAN_BYTES:
                    trunc = True
                    break
                s = line.strip()
                if not s or s.startswith("#") or s.startswith("//"):
                    continue
                c = s.split()
                if first:
                    first = False
                    if len(c) == 1:  # .pts leading point count
                        try:
                            int(c[0])
                            continue
                        except ValueError:
                            pass
                try:
                    x = float(c[0])
                    y = float(c[1])
                    z = float(c[2]) if len(c) > 2 else None
                except (ValueError, IndexError):
                    continue
                self._bbox_add(bb, x, y, z)
                pts += 1
                if len(c) > maxcols:
                    maxcols = len(c)
        self._emit_geometry(
            ds,
            local_fid,
            points=pts,
            bbox=bb,
            props={
                "columns_per_point": maxcols or None,
                "has_color": maxcols >= 6,
                "scan_truncated": trunc,
            },
        )

    def _mesh_gltf(self, path, ds, local_fid):
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        if size > self.MAX_JSON_BYTES:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"gltf too large to load ({size} bytes)"
            return
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
        meshes = doc.get("meshes", []) or []
        accessors = doc.get("accessors", []) or []
        nodes = doc.get("nodes", []) or []
        materials = doc.get("materials", []) or []
        bb = self._new_bbox()
        vcount = prim_count = 0
        attr_names = set()
        for m in meshes:
            for prim in m.get("primitives", []) or []:
                prim_count += 1
                attrs = prim.get("attributes", {}) or {}
                attr_names.update(attrs.keys())
                pos = attrs.get("POSITION")
                if isinstance(pos, int) and 0 <= pos < len(accessors):
                    acc = accessors[pos]
                    try:
                        vcount += int(acc.get("count", 0) or 0)
                    except (ValueError, TypeError):
                        pass
                    mn, mx = acc.get("min"), acc.get("max")
                    if (
                        isinstance(mn, list)
                        and len(mn) >= 3
                        and isinstance(mx, list)
                        and len(mx) >= 3
                    ):
                        try:
                            self._bbox_add(bb, float(mn[0]), float(mn[1]), float(mn[2]))
                            self._bbox_add(bb, float(mx[0]), float(mx[1]), float(mx[2]))
                        except (ValueError, TypeError):
                            pass
        asset = doc.get("asset", {}) or {}
        self._emit_geometry(
            ds,
            local_fid,
            vertices=vcount or None,
            bbox=bb,
            attributes=sorted(attr_names) or None,
            props={
                "mesh_count": len(meshes),
                "primitive_count": prim_count,
                "accessor_count": len(accessors),
                "node_count": len(nodes),
                "material_count": len(materials),
                "gltf_version": asset.get("version"),
                "generator": asset.get("generator"),
            },
        )

    def _mesh_gmsh(self, path, ds, local_fid):
        nnodes = nelems = None
        version = None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            it = iter(fh)
            for line in it:
                s = line.strip()
                if s == "$MeshFormat":
                    ver = next(it, "").strip().split()
                    if ver:
                        version = ver[0]
                elif s == "$Nodes":
                    nxt = next(it, "").strip().split()
                    try:
                        nnodes = int(nxt[0]) if len(nxt) == 1 else int(nxt[1])
                    except (ValueError, IndexError):
                        pass
                elif s == "$Elements":
                    nxt = next(it, "").strip().split()
                    try:
                        nelems = int(nxt[0]) if len(nxt) == 1 else int(nxt[1])
                    except (ValueError, IndexError):
                        pass
        self._emit_geometry(
            ds,
            local_fid,
            vertices=nnodes,
            cells=nelems,
            props={"gmsh_version": version},
        )

    def _mesh_vtk_xml(self, path, ds, local_fid):
        text = self._read_text_head(path, self.MAX_STRUCT_TEXT_BYTES)

        def _sum(attr):
            vals = re.findall(rf'{attr}="(\d+)"', text)
            return sum(int(v) for v in vals) if vals else None

        points = _sum("NumberOfPoints")
        cells = _sum("NumberOfCells")
        verts = _sum("NumberOfVerts")
        polys = _sum("NumberOfPolys")
        lines = _sum("NumberOfLines")
        strips = _sum("NumberOfStrips")
        attrs = sorted(set(re.findall(r'<DataArray[^>]*\bName="([^"]+)"', text)))
        m_type = re.search(r'<VTKFile[^>]*\btype="(\w+)"', text)
        whole = re.search(r'WholeExtent="([^"]+)"', text)
        self._emit_geometry(
            ds,
            local_fid,
            points=points,
            cells=cells,
            vertices=verts,
            attributes=attrs or None,
            props={
                "vtk_type": m_type.group(1) if m_type else None,
                "poly_count": polys,
                "line_count": lines,
                "strip_count": strips,
                "whole_extent": whole.group(1) if whole else None,
            },
        )

    def _mesh_collada(self, path, ds, local_fid):
        text = self._read_text_head(path, self.MAX_STRUCT_TEXT_BYTES)
        geoms = len(re.findall(r"<geometry\b", text))
        floatcounts = [
            int(x) for x in re.findall(r'<float_array[^>]*\bcount="(\d+)"', text)
        ]
        faces = (
            sum(
                int(x)
                for x in (
                    re.findall(r'<triangles[^>]*\bcount="(\d+)"', text)
                    + re.findall(r'<polylist[^>]*\bcount="(\d+)"', text)
                    + re.findall(r'<polygons[^>]*\bcount="(\d+)"', text)
                )
            )
            or None
        )
        # a positions <source> float_array holds 3 floats per vertex; the largest
        # array is the position stream -> approximate vertex count.
        verts = (max(floatcounts) // 3) if floatcounts else None
        self._emit_geometry(
            ds,
            local_fid,
            vertices=verts,
            faces=faces,
            props={
                "geometry_count": geoms,
                "vertex_count_estimated": True,
                "float_array_max": max(floatcounts) if floatcounts else None,
            },
        )

    def _mesh_x3d(self, path, ds, local_fid):
        text = self._read_text_head(path, self.MAX_STRUCT_TEXT_BYTES)
        ifs = len(re.findall(r"<IndexedFaceSet\b", text))
        coords_attrs = re.findall(r'<Coordinate[^>]*\bpoint="([^"]*)"', text)
        bb = self._new_bbox()
        vcount = 0
        for pa in coords_attrs:
            nums = pa.replace(",", " ").split()
            for i in range(0, len(nums) - 2, 3):
                try:
                    self._bbox_add(
                        bb, float(nums[i]), float(nums[i + 1]), float(nums[i + 2])
                    )
                    vcount += 1
                except ValueError:
                    pass
        self._emit_geometry(
            ds,
            local_fid,
            vertices=vcount or None,
            bbox=bb,
            props={
                "indexed_face_set_count": ifs,
                "coordinate_nodes": len(coords_attrs),
            },
        )

    def _mesh_usd(self, path, ds, local_fid):
        from collections import Counter

        text = self._read_text_head(path, self.MAX_STRUCT_TEXT_BYTES)
        prims = re.findall(r'\bdef\s+(\w+)?\s*"([^"]+)"', text)
        types = Counter(t for t, _ in prims if t)
        vcount = None
        m = re.search(r"point3f\[\]\s+points\s*=\s*\[(.*?)\]", text, re.S)
        if m:
            vcount = m.group(1).count("(")
        self._emit_geometry(
            ds,
            local_fid,
            vertices=vcount,
            props={
                "prim_count": len(prims),
                "mesh_count": types.get("Mesh", 0),
                "prim_types": dict(types),
            },
        )

    def _mesh_mtl(self, path, ds, local_fid):
        materials = maps = 0
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                s = line.strip()
                if s.startswith("newmtl"):
                    materials += 1
                elif s.startswith("map_"):
                    maps += 1
        ds["record_count"] = materials
        self._add_properties(
            ds["dataset_id"],
            {"material_count": materials, "texture_map_count": maps or None},
            "geometry",
            local_fid,
        )

    # ==================================================================
    # Geospatial handlers  (feature/geometry counts, CRS, bbox)
    # ==================================================================
    def _handle_geospatial(self, path, ext, category, subcategory, local_fid):
        base = ("." + ext.split(".")[-1]) if ext else ext
        ds = self._add_dataset(
            path,
            ext,
            category or "geospatial",
            subcategory or "vector_geo",
            "geospatial",
            local_fid,
        )
        try:
            self._geo_parse(path, ds, base, local_fid)
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"geo parse failed: {err}"

    def _geo_parse(self, path, ds, base, local_fid):
        fn = {
            ".geojson": self._geo_geojson,
            ".topojson": self._geo_topojson,
            ".kml": self._geo_kml,
            ".gpx": self._geo_gpx,
            ".osm": self._geo_osm,
            ".wkt": self._geo_wkt,
            ".prj": self._geo_prj,
            ".gml": self._geo_gml,
        }.get(base)
        if fn is None:
            ds["analysis_status"] = "generic"
            return
        fn(path, ds, local_fid)

    def _geo_geojson(self, path, ds, local_fid):
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        if size > self.MAX_JSON_BYTES:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"geojson too large ({size} bytes)"
            return
        from collections import Counter

        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
        gt = Counter()
        bb = self._bb2_new()

        def walk_coords(coords):
            if isinstance(coords, list):
                if coords and isinstance(coords[0], (int, float)) and len(coords) >= 2:
                    try:
                        self._bb2_add(bb, float(coords[0]), float(coords[1]))
                    except (ValueError, TypeError):
                        pass
                else:
                    for c in coords:
                        walk_coords(c)

        def geom(g):
            if not isinstance(g, dict):
                return
            t = g.get("type")
            if t:
                gt[t] += 1
            if t == "GeometryCollection":
                for gg in g.get("geometries", []) or []:
                    geom(gg)
            else:
                walk_coords(g.get("coordinates"))

        t = doc.get("type")
        features = None
        if t == "FeatureCollection":
            feats = doc.get("features", []) or []
            features = len(feats)
            for f in feats:
                if isinstance(f, dict):
                    geom(f.get("geometry"))
        elif t == "Feature":
            features = 1
            geom(doc.get("geometry"))
        elif t:
            geom(doc)
        crs = None
        c = doc.get("crs")
        if isinstance(c, dict):
            crs = (c.get("properties") or {}).get("name") or c.get("type")
        docbbox = doc.get("bbox")
        bbox = (
            docbbox
            if isinstance(docbbox, list)
            else (bb if any(v is not None for v in bb) else None)
        )
        self._emit_geo(
            ds,
            local_fid,
            features=features,
            geometries=sum(gt.values()) or None,
            crs=crs,
            bbox=bbox,
            geom_types=dict(gt) or None,
        )

    def _geo_topojson(self, path, ds, local_fid):
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        if size > self.MAX_JSON_BYTES:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"topojson too large ({size} bytes)"
            return
        from collections import Counter

        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
        objects = doc.get("objects", {}) or {}
        arcs = doc.get("arcs", []) or []
        gt = Counter()
        feat = 0
        for _name, obj in objects.items():
            if not isinstance(obj, dict):
                continue
            t = obj.get("type")
            if t == "GeometryCollection":
                geoms = obj.get("geometries", []) or []
                feat += len(geoms)
                for g in geoms:
                    if isinstance(g, dict) and g.get("type"):
                        gt[g["type"]] += 1
            elif t:
                feat += 1
                gt[t] += 1
        bbox = doc.get("bbox")
        self._emit_geo(
            ds,
            local_fid,
            features=feat or None,
            geometries=sum(gt.values()) or None,
            bbox=bbox if isinstance(bbox, list) else None,
            geom_types=dict(gt) or None,
            props={
                "object_count": len(objects),
                "arc_count": len(arcs),
                "has_transform": bool(doc.get("transform")),
            },
        )

    def _geo_kml(self, path, ds, local_fid):
        from collections import Counter

        text = self._read_text_head(path, self.MAX_STRUCT_TEXT_BYTES)
        placemarks = len(re.findall(r"<Placemark\b", text))
        gt = Counter()
        for g in (
            "Point",
            "LineString",
            "Polygon",
            "MultiGeometry",
            "LinearRing",
            "Model",
            "gx:Track",
        ):
            n = len(re.findall(rf"<{re.escape(g)}\b", text))
            if n:
                gt[g] = n
        bb = self._bb2_new()
        for coord in re.findall(r"<coordinates>(.*?)</coordinates>", text, re.S):
            for tok in coord.replace("\n", " ").split():
                parts = tok.split(",")
                if len(parts) >= 2:
                    try:
                        self._bb2_add(bb, float(parts[0]), float(parts[1]))
                    except ValueError:
                        pass
        self._emit_geo(
            ds,
            local_fid,
            features=placemarks or None,
            geometries=sum(gt.values()) or None,
            crs="EPSG:4326",
            bbox=bb if any(v is not None for v in bb) else None,
            geom_types=dict(gt) or None,
        )

    def _geo_gpx(self, path, ds, local_fid):
        text = self._read_text_head(path, self.MAX_STRUCT_TEXT_BYTES)
        trkpts = len(re.findall(r"<trkpt\b", text))
        wpts = len(re.findall(r"<wpt\b", text))
        rtepts = len(re.findall(r"<rtept\b", text))
        tracks = len(re.findall(r"<trk\b", text))
        routes = len(re.findall(r"<rte\b", text))
        bb = self._bb2_new()
        for lat, lon in re.findall(
            r'<(?:trkpt|wpt|rtept)[^>]*?lat="([^"]+)"[^>]*?lon="([^"]+)"', text
        ):
            try:
                self._bb2_add(bb, float(lon), float(lat))
            except ValueError:
                pass
        total = trkpts + wpts + rtepts
        self._emit_geo(
            ds,
            local_fid,
            features=total or None,
            crs="EPSG:4326",
            bbox=bb if any(v is not None for v in bb) else None,
            geom_types={"trkpt": trkpts, "wpt": wpts, "rtept": rtepts},
            props={
                "track_count": tracks,
                "route_count": routes,
                "waypoint_count": wpts,
                "trackpoint_count": trkpts,
            },
        )

    def _geo_osm(self, path, ds, local_fid):
        text = self._read_text_head(path, self.MAX_STRUCT_TEXT_BYTES)
        nodes = len(re.findall(r"<node\b", text))
        ways = len(re.findall(r"<way\b", text))
        rels = len(re.findall(r"<relation\b", text))
        bb = self._bb2_new()
        m = re.search(r"<bounds\b[^>]*>", text)
        if m:
            tag = m.group(0)

            def at(a):
                mm = re.search(rf'{a}="([^"]+)"', tag)
                return float(mm.group(1)) if mm else None

            try:
                minlat, minlon = at("minlat"), at("minlon")
                maxlat, maxlon = at("maxlat"), at("maxlon")
                if None not in (minlat, minlon, maxlat, maxlon):
                    bb = [minlon, minlat, maxlon, maxlat]
            except (ValueError, TypeError):
                pass
        if not any(v is not None for v in bb):
            for lat, lon in re.findall(
                r'<node[^>]*?lat="([^"]+)"[^>]*?lon="([^"]+)"', text
            ):
                try:
                    self._bb2_add(bb, float(lon), float(lat))
                except ValueError:
                    pass
        self._emit_geo(
            ds,
            local_fid,
            features=(nodes + ways + rels) or None,
            crs="EPSG:4326",
            bbox=bb if any(v is not None for v in bb) else None,
            geom_types={"node": nodes, "way": ways, "relation": rels},
            props={"node_count": nodes, "way_count": ways, "relation_count": rels},
        )

    _WKT_RE = re.compile(
        r"\b(MULTIPOLYGON|MULTILINESTRING|MULTIPOINT|GEOMETRYCOLLECTION"
        r"|POLYHEDRALSURFACE|CIRCULARSTRING|COMPOUNDCURVE|CURVEPOLYGON"
        r"|TRIANGLE|POLYGON|LINESTRING|POINT|TIN)\b"
    )

    def _geo_wkt(self, path, ds, local_fid):
        from collections import Counter

        gt = Counter()
        bb = self._bb2_new()
        crs = None
        scanned = 0
        trunc = False
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                scanned += len(line)
                if scanned > self.MAX_STRUCT_SCAN_BYTES:
                    trunc = True
                    break
                s = line.strip()
                if not s:
                    continue
                up = s.upper()
                if up.startswith("SRID="):
                    mm = re.match(r"SRID=(\d+)", up)
                    if mm:
                        crs = f"EPSG:{mm.group(1)}"
                m = self._WKT_RE.search(up)
                if m:
                    gt[m.group(1)] += 1
                for x, y in re.findall(r"(-?\d+\.?\d*)\s+(-?\d+\.?\d*)", s):
                    try:
                        self._bb2_add(bb, float(x), float(y))
                    except ValueError:
                        pass
        self._emit_geo(
            ds,
            local_fid,
            geometries=sum(gt.values()) or None,
            crs=crs,
            bbox=bb if any(v is not None for v in bb) else None,
            geom_types=dict(gt) or None,
            props={"scan_truncated": trunc},
        )

    def _geo_prj(self, path, ds, local_fid):
        text = self._read_text_head(path, 1024 * 1024)

        def name(tag):
            m = re.search(rf'{tag}\["([^"]+)"', text)
            return m.group(1) if m else None

        projcs = name("PROJCS")
        geogcs = name("GEOGCS")
        datum = name("DATUM")
        epsg = None
        m = re.search(r'AUTHORITY\["EPSG","(\d+)"\]\s*\]\s*$', text.strip())
        if m:
            epsg = f"EPSG:{m.group(1)}"
        self._emit_geo(
            ds,
            local_fid,
            crs=(epsg or projcs or geogcs),
            props={
                "projected_cs": projcs,
                "geographic_cs": geogcs,
                "datum": datum,
                "epsg": epsg,
            },
        )

    def _geo_gml(self, path, ds, local_fid):
        from collections import Counter

        text = self._read_text_head(path, self.MAX_STRUCT_TEXT_BYTES)
        feats = len(re.findall(r"<(?:\w+:)?featureMember\b", text))
        srs = re.search(r'srsName="([^"]+)"', text)
        gt = Counter()
        for g in (
            "Point",
            "LineString",
            "Polygon",
            "MultiSurface",
            "MultiCurve",
            "Surface",
            "Curve",
            "LinearRing",
            "MultiPolygon",
        ):
            n = len(re.findall(rf"<(?:\w+:)?{g}\b", text))
            if n:
                gt[g] = n
        bb = self._bb2_new()
        for txt in re.findall(
            r"<(?:\w+:)?(?:pos|posList|coordinates)[^>]*>(.*?)</", text, re.S
        ):
            nums = re.findall(r"-?\d+\.?\d*", txt)
            for i in range(0, len(nums) - 1, 2):
                try:
                    self._bb2_add(bb, float(nums[i]), float(nums[i + 1]))
                except ValueError:
                    pass
        self._emit_geo(
            ds,
            local_fid,
            features=feats or None,
            geometries=sum(gt.values()) or None,
            crs=srs.group(1) if srs else None,
            bbox=bb if any(v is not None for v in bb) else None,
            geom_types=dict(gt) or None,
        )

    # ==================================================================
    # .gml disambiguation  (Geography ML XML  vs  Graph Modeling Language)
    # ==================================================================
    def _handle_gml_dispatch(self, path, ext, category, subcategory, local_fid):
        head = self._read_text_head(path, 8192).lstrip()
        low = head.lower()
        is_xml = low.startswith("<?xml") or low.startswith("<")
        is_graph = (
            not is_xml
            and "graph" in low
            and "[" in low
            and ("node" in low or "edge" in low)
        )
        if is_graph:
            ds = self._add_dataset(
                path,
                ext,
                category or "graph",
                "graph_modeling_language",
                "graph",
                local_fid,
            )
            try:
                self._graph_gml(path, ds, local_fid)
            except Exception as err:
                ds["analysis_status"] = "partial"
                ds["notes"] = f"gml(graph) parse failed: {err}"
        else:
            ds = self._add_dataset(
                path,
                ext,
                category or "geospatial",
                "geography_markup",
                "geospatial",
                local_fid,
            )
            try:
                self._geo_gml(path, ds, local_fid)
            except Exception as err:
                ds["analysis_status"] = "partial"
                ds["notes"] = f"gml(geo) parse failed: {err}"

    # ==================================================================
    # Graph / network handlers  (node/edge counts)
    # ==================================================================
    def _handle_graph(self, path, ext, category, subcategory, local_fid):
        base = ("." + ext.split(".")[-1]) if ext else ext
        ds = self._add_dataset(
            path,
            ext,
            category or "graph",
            subcategory or "graph_network",
            "graph",
            local_fid,
        )
        try:
            self._graph_parse(path, ds, base, local_fid)
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"graph parse failed: {err}"

    def _graph_parse(self, path, ds, base, local_fid):
        fn = {
            ".graphml": self._graph_graphml,
            ".gexf": self._graph_gexf,
            ".dot": self._graph_dot,
            ".gv": self._graph_dot,
            ".net": self._graph_pajek,
            ".edgelist": self._graph_edgelist,
            ".mtx": self._graph_matrixmarket,
            ".mm": self._graph_matrixmarket,
            ".gml": self._graph_gml,
        }.get(base)
        if fn is None:
            ds["analysis_status"] = "generic"
            return
        fn(path, ds, local_fid)

    def _graph_graphml(self, path, ds, local_fid):
        text = self._read_text_head(path, self.MAX_STRUCT_TEXT_BYTES)
        nodes = len(re.findall(r"<node\b", text))
        edges = len(re.findall(r"<edge\b", text))
        m = re.search(r'edgedefault="(\w+)"', text)
        directed = (m.group(1) == "directed") if m else None
        keys = re.findall(r'<key[^>]*\battr\.name="([^"]+)"', text)
        self._emit_graph(
            ds,
            local_fid,
            nodes=nodes,
            edges=edges,
            directed=directed,
            attributes=sorted(set(keys)) or None,
        )

    def _graph_gexf(self, path, ds, local_fid):
        text = self._read_text_head(path, self.MAX_STRUCT_TEXT_BYTES)
        m = re.search(r'<nodes[^>]*\bcount="(\d+)"', text)
        nodes = int(m.group(1)) if m else len(re.findall(r"<node\b", text))
        m = re.search(r'<edges[^>]*\bcount="(\d+)"', text)
        edges = int(m.group(1)) if m else len(re.findall(r"<edge\b", text))
        dm = re.search(r'defaultedgetype="(\w+)"', text)
        directed = (dm.group(1) == "directed") if dm else None
        attrs = re.findall(r'<attribute[^>]*\btitle="([^"]+)"', text)
        self._emit_graph(
            ds,
            local_fid,
            nodes=nodes,
            edges=edges,
            directed=directed,
            attributes=sorted(set(attrs)) or None,
        )

    def _graph_dot(self, path, ds, local_fid):
        text = self._read_text_head(path, self.MAX_STRUCT_TEXT_BYTES)
        text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
        text = re.sub(r"//[^\n]*", " ", text)
        directed = bool(re.search(r"\bdigraph\b", text))
        edges = text.count("->") + text.count("--")
        node_ids = set()
        for m in re.finditer(
            r'([A-Za-z0-9_."]+)\s*(?:->|--)\s*([A-Za-z0-9_."]+)', text
        ):
            node_ids.add(m.group(1))
            node_ids.add(m.group(2))
        for m in re.finditer(r'(?m)^\s*("?[\w.]+"?)\s*\[', text):
            node_ids.add(m.group(1))
        self._emit_graph(
            ds,
            local_fid,
            nodes=len(node_ids) or None,
            edges=edges or None,
            directed=directed,
            props={"count_method": "parsed"},
        )

    def _graph_pajek(self, path, ds, local_fid):
        nodes = None
        edge_ct = 0
        section = None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                s = line.strip()
                if not s:
                    continue
                if s.startswith("*"):
                    low = s.lower()
                    m = re.match(r"\*vertices\s+(\d+)", low)
                    if m:
                        nodes = int(m.group(1))
                        section = "vertices"
                    elif (
                        low.startswith("*edges")
                        or low.startswith("*arcs")
                        or low.startswith("*edgeslist")
                        or low.startswith("*arcslist")
                    ):
                        section = "edges"
                    else:
                        section = None
                    continue
                if section == "edges":
                    edge_ct += 1
        self._emit_graph(
            ds, local_fid, nodes=nodes, edges=edge_ct or None, props={"format": "pajek"}
        )

    def _graph_edgelist(self, path, ds, local_fid):
        nodes = set()
        edges = 0
        weighted = False
        scanned = 0
        trunc = False
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                scanned += len(line)
                if scanned > self.MAX_STRUCT_SCAN_BYTES:
                    trunc = True
                    break
                s = line.strip()
                if not s or s[0] in "#%":
                    continue
                parts = s.split()
                if len(parts) < 2:
                    continue
                edges += 1
                if len(nodes) < self.MAX_GEOM_VERTS:
                    nodes.add(parts[0])
                    nodes.add(parts[1])
                if len(parts) >= 3:
                    weighted = True
        self._emit_graph(
            ds,
            local_fid,
            nodes=len(nodes) or None,
            edges=edges,
            props={"weighted": weighted, "scan_truncated": trunc},
        )

    def _graph_matrixmarket(self, path, ds, local_fid):
        banner = fmt = symmetry = None
        rows = cols = nnz = None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                s = line.strip()
                if not s:
                    continue
                if s.startswith("%%MatrixMarket"):
                    banner = s
                    toks = s.split()
                    fmt = toks[3] if len(toks) > 3 else None
                    symmetry = toks[4] if len(toks) > 4 else None
                    continue
                if s.startswith("%"):
                    continue
                d = s.split()
                try:
                    if len(d) == 3:
                        rows, cols, nnz = int(d[0]), int(d[1]), int(d[2])
                    elif len(d) == 2:
                        rows, cols = int(d[0]), int(d[1])
                except ValueError:
                    pass
                break
        if banner is None and rows is None:
            ds["analysis_status"] = "generic"
            ds["notes"] = "not a Matrix Market file"
            return
        nodes = rows if (rows is not None and rows == cols) else None
        self._emit_graph(
            ds,
            local_fid,
            nodes=nodes,
            edges=nnz,
            props={
                "matrix_rows": rows,
                "matrix_cols": cols,
                "nonzeros": nnz,
                "mm_format": fmt,
                "mm_symmetry": symmetry,
                "banner": banner,
            },
        )

    def _graph_gml(self, path, ds, local_fid):
        nodes = edges = 0
        directed = None
        scanned = 0
        trunc = False
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                scanned += len(line)
                if scanned > self.MAX_STRUCT_SCAN_BYTES:
                    trunc = True
                    break
                s = line.strip()
                if s.startswith("node"):
                    nodes += 1
                elif s.startswith("edge"):
                    edges += 1
                elif s.startswith("directed"):
                    m = re.match(r"directed\s+(\d+)", s)
                    if m:
                        directed = m.group(1) == "1"
        self._emit_graph(
            ds,
            local_fid,
            nodes=nodes or None,
            edges=edges or None,
            directed=directed,
            props={"format": "gml", "scan_truncated": trunc},
        )

    # ==================================================================
    # Config / serialization handlers  (key counts, sections)
    # ==================================================================
    def _handle_config(self, path, ext, category, subcategory, local_fid):
        base = ("." + ext.split(".")[-1]) if ext else ext
        ds = self._add_dataset(
            path,
            ext,
            category or "config",
            subcategory or "configuration",
            "config",
            local_fid,
        )
        try:
            if base == ".toml":
                self._config_toml(path, ds, local_fid)
            elif base == ".env":
                self._config_env(path, ds, local_fid)
            elif base in (".hcl", ".tf", ".tfvars"):
                self._config_hcl(path, ds, local_fid)
            elif base in (".jsonnet", ".libsonnet"):
                self._config_jsonnet(path, ds, local_fid)
            else:
                self._config_ini_like(
                    path,
                    ds,
                    local_fid,
                    fmt={
                        ".ini": "ini",
                        ".cfg": "ini",
                        ".conf": "conf",
                        ".properties": "properties",
                    }.get(base, "ini"),
                )
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"config parse failed: {err}"

    def _config_toml(self, path, ds, local_fid):
        try:
            import tomllib
        except ImportError:
            tomllib = None
        if tomllib is not None:
            try:
                with open(path, "rb") as fh:
                    data = tomllib.load(fh)
            except Exception as err:
                ds["notes"] = f"toml parse failed; line scan: {err}"
                self._config_ini_like(path, ds, local_fid, fmt="toml")
                return

            def count(d, prefix=""):
                k = 0
                sect = []
                for key, val in d.items():
                    dotted = prefix + key
                    if isinstance(val, dict):
                        sect.append(dotted)
                        sk, ss = count(val, dotted + ".")
                        k += sk
                        sect += ss
                    elif (
                        isinstance(val, list)
                        and val
                        and all(isinstance(e, dict) for e in val)
                    ):
                        for e in val:
                            sect.append(dotted)
                            sk, ss = count(e, dotted + ".")
                            k += sk
                            sect += ss
                    else:
                        k += 1
                return k, sect

            nk, sects = count(data)
            self._emit_config(
                ds,
                local_fid,
                keys=nk,
                sections=len(sects) or None,
                section_names=sects or None,
                fmt="toml",
            )
            return
        self._config_ini_like(path, ds, local_fid, fmt="toml")

    def _config_ini_like(self, path, ds, local_fid, fmt="ini"):
        sections = []
        keys = 0
        scanned = 0
        trunc = False
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                scanned += len(line)
                if scanned > self.MAX_STRUCT_SCAN_BYTES:
                    trunc = True
                    break
                s = line.strip()
                if not s or s[0] in "#;":
                    continue
                m = re.match(r"\[+([^\]]+)\]+\s*$", s)
                if m:
                    sections.append(m.group(1))
                    continue
                if "=" in s or ":" in s:
                    keys += 1
        self._emit_config(
            ds,
            local_fid,
            keys=keys,
            sections=len(sections) or None,
            section_names=sections or None,
            fmt=fmt,
            props={"scan_truncated": trunc},
        )

    def _config_env(self, path, ds, local_fid):
        keys = 0
        names = []
        scanned = 0
        trunc = False
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                scanned += len(line)
                if scanned > self.MAX_STRUCT_SCAN_BYTES:
                    trunc = True
                    break
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                s2 = s[7:] if s.lower().startswith("export ") else s
                m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*=", s2)
                if m:
                    keys += 1
                    if len(names) < 500:
                        names.append(m.group(1))
        self._emit_config(
            ds,
            local_fid,
            keys=keys,
            fmt="dotenv",
            props={"variable_names": names or None, "scan_truncated": trunc},
        )

    def _config_hcl(self, path, ds, local_fid):
        from collections import Counter

        text = self._read_text_head(path, self.MAX_STRUCT_TEXT_BYTES)
        text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
        text = re.sub(r"(?m)(#|//).*$", "", text)
        blocks = re.findall(r'(?m)^\s*([A-Za-z_][\w-]*)\s+(?:"[^"]*"\s+)*\{', text)
        assigns = re.findall(r"(?m)^\s*([A-Za-z_][\w-]*)\s*=(?!=)", text)
        self._emit_config(
            ds,
            local_fid,
            keys=len(assigns) or None,
            sections=len(blocks) or None,
            section_names=blocks or None,
            fmt="hcl",
            props={
                "block_types": dict(Counter(blocks)) or None,
                "assignment_count": len(assigns),
            },
        )

    def _config_jsonnet(self, path, ds, local_fid):
        text = self._read_text_head(path, self.MAX_STRUCT_TEXT_BYTES)
        locals_ = len(re.findall(r"(?m)^\s*local\s+\w+", text))
        functions = len(re.findall(r"\bfunction\s*\(", text))
        imports = len(re.findall(r"\bimport(?:str)?\s+", text))
        depth = 0
        fields = 0
        for raw in text.splitlines():
            s = raw.strip()
            if depth == 1 and re.match(
                r"""(?:[A-Za-z_]\w*|"[^"]*"|'[^']*')\s*\+?::?""", s
            ):
                fields += 1
            depth += raw.count("{") - raw.count("}") + raw.count("[") - raw.count("]")
            if depth < 0:
                depth = 0
        self._emit_config(
            ds,
            local_fid,
            keys=fields or None,
            fmt="jsonnet",
            props={
                "local_count": locals_,
                "function_count": functions,
                "import_count": imports,
                "fields_estimated": True,
            },
        )

    # ==================================================================
    # Bio / chem handlers  (record/sequence counts)
    # ==================================================================
    def _handle_bio(self, path, ext, category, subcategory, local_fid):
        base = ("." + ext.split(".")[-1]) if ext else ext
        ds = self._add_dataset(
            path,
            ext,
            category or "bioinformatics",
            subcategory or "sequence_data",
            "bioinformatics",
            local_fid,
        )
        try:
            if base in (".fasta", ".fa", ".fna", ".faa", ".ffn", ".frn"):
                self._bio_fasta(path, ds, local_fid)
            elif base in (".fastq", ".fq"):
                self._bio_fastq(path, ds, local_fid)
            elif base == ".sam":
                self._bio_sam(path, ds, local_fid)
            elif base == ".vcf":
                self._bio_vcf(path, ds, local_fid)
            elif base == ".bed":
                self._bio_bed(path, ds, local_fid)
            elif base in (".gff", ".gff3"):
                self._bio_gff(path, ds, local_fid, "gff")
            elif base == ".gtf":
                self._bio_gff(path, ds, local_fid, "gtf")
            elif base == ".mol":
                self._bio_mol(path, ds, local_fid)
            elif base == ".sdf":
                self._bio_sdf(path, ds, local_fid)
            elif base == ".pdb":
                self._bio_pdb(path, ds, local_fid)
            else:
                ds["analysis_status"] = "generic"
        except Exception as err:
            ds["analysis_status"] = "partial"
            ds["notes"] = f"bio parse failed: {err}"

    def _bio_fasta(self, path, ds, local_fid):
        seqs = total = longest = cur = 0
        scanned = 0
        trunc = False
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                scanned += len(line)
                if scanned > self.MAX_STRUCT_SCAN_BYTES:
                    trunc = True
                    break
                if line.startswith(">"):
                    if cur:
                        longest = max(longest, cur)
                    cur = 0
                    seqs += 1
                elif line.startswith(";"):
                    continue
                else:
                    L = len(line.strip())
                    total += L
                    cur += L
            if cur:
                longest = max(longest, cur)
        self._emit_bio(
            ds,
            local_fid,
            sequences=seqs,
            props={
                "total_residues": total,
                "longest_sequence": longest or None,
                "avg_length": round(total / seqs, 2) if seqs else None,
                "scan_truncated": trunc,
            },
        )

    def _bio_fastq(self, path, ds, local_fid):
        lines = 0
        scanned = 0
        trunc = False
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                scanned += len(line)
                lines += 1
                if scanned > self.MAX_STRUCT_SCAN_BYTES:
                    trunc = True
                    break
        reads = lines // 4
        self._emit_bio(
            ds,
            local_fid,
            records=reads,
            props={"line_count": lines, "reads": reads, "scan_truncated": trunc},
        )

    def _bio_sam(self, path, ds, local_fid):
        aln = refs = header = 0
        ver = None
        scanned = 0
        trunc = False
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                scanned += len(line)
                if scanned > self.MAX_STRUCT_SCAN_BYTES:
                    trunc = True
                    break
                if line.startswith("@"):
                    header += 1
                    if line.startswith("@SQ"):
                        refs += 1
                    elif line.startswith("@HD"):
                        m = re.search(r"VN:(\S+)", line)
                        if m:
                            ver = m.group(1)
                elif line.strip():
                    aln += 1
        self._emit_bio(
            ds,
            local_fid,
            records=aln,
            props={
                "alignment_count": aln,
                "reference_count": refs,
                "header_lines": header,
                "sam_version": ver,
                "scan_truncated": trunc,
            },
        )

    def _bio_vcf(self, path, ds, local_fid):
        variants = samples = meta = 0
        ver = None
        scanned = 0
        trunc = False
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                scanned += len(line)
                if scanned > self.MAX_STRUCT_SCAN_BYTES:
                    trunc = True
                    break
                if line.startswith("##"):
                    meta += 1
                    if line.startswith("##fileformat="):
                        ver = line.strip().split("=", 1)[1]
                elif line.startswith("#CHROM"):
                    cols = line.rstrip("\n").split("\t")
                    samples = max(0, len(cols) - 9)
                elif line.strip():
                    variants += 1
        self._emit_bio(
            ds,
            local_fid,
            records=variants,
            props={
                "variant_count": variants,
                "sample_count": samples,
                "meta_lines": meta,
                "vcf_version": ver,
                "scan_truncated": trunc,
            },
        )

    def _bio_bed(self, path, ds, local_fid):
        feats = maxcols = 0
        scanned = 0
        trunc = False
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                scanned += len(line)
                if scanned > self.MAX_STRUCT_SCAN_BYTES:
                    trunc = True
                    break
                s = line.rstrip("\n")
                if not s.strip() or s.startswith(("#", "track", "browser")):
                    continue
                feats += 1
                nc = len(s.split("\t"))
                if nc > maxcols:
                    maxcols = nc
        self._emit_bio(
            ds,
            local_fid,
            records=feats,
            props={
                "feature_count": feats,
                "bed_columns": maxcols or None,
                "scan_truncated": trunc,
            },
        )

    def _bio_gff(self, path, ds, local_fid, fmt="gff"):
        from collections import Counter

        feats = seqregions = 0
        types = Counter()
        scanned = 0
        trunc = False
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                scanned += len(line)
                if scanned > self.MAX_STRUCT_SCAN_BYTES:
                    trunc = True
                    break
                if line.startswith("#"):
                    if line.startswith("##sequence-region"):
                        seqregions += 1
                    continue
                cols = line.rstrip("\n").split("\t")
                if len(cols) >= 8:
                    feats += 1
                    types[cols[2]] += 1
        self._emit_bio(
            ds,
            local_fid,
            records=feats,
            props={
                "feature_count": feats,
                "feature_types": dict(types) or None,
                "sequence_regions": seqregions or None,
                "format": fmt,
                "scan_truncated": trunc,
            },
        )

    def _bio_mol(self, path, ds, local_fid):
        atoms = bonds = None
        name = None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = [fh.readline() for _ in range(4)]
        if lines and lines[0]:
            name = lines[0].strip() or None
        if len(lines) >= 4 and lines[3]:
            counts = lines[3]
            try:
                atoms = int(counts[0:3])
                bonds = int(counts[3:6])
            except ValueError:
                pass
        self._emit_bio(
            ds,
            local_fid,
            records=1,
            props={
                "molecule_count": 1,
                "atom_count": atoms,
                "bond_count": bonds,
                "title": name,
            },
        )

    def _bio_sdf(self, path, ds, local_fid):
        mols = 0
        first_atoms = first_bonds = None
        line_in_mol = 0
        scanned = 0
        trunc = False
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                scanned += len(line)
                if scanned > self.MAX_STRUCT_SCAN_BYTES:
                    trunc = True
                    break
                if line.startswith("$$$$"):
                    mols += 1
                    line_in_mol = 0
                    continue
                line_in_mol += 1
                if mols == 0 and line_in_mol == 4 and first_atoms is None:
                    try:
                        first_atoms = int(line[0:3])
                        first_bonds = int(line[3:6])
                    except ValueError:
                        pass
        self._emit_bio(
            ds,
            local_fid,
            records=mols or None,
            props={
                "molecule_count": mols,
                "first_atom_count": first_atoms,
                "first_bond_count": first_bonds,
                "scan_truncated": trunc,
            },
        )

    def _bio_pdb(self, path, ds, local_fid):
        magic = self._read_magic(path, 32)
        if magic.startswith(b"Microsoft C/C++"):
            # MSVC program database, not Protein Data Bank -- classify only.
            ds["modality"] = "binary"
            ds["subcategory"] = "program_database"
            ds["analysis_status"] = "generic"
            self._add_property(
                ds["dataset_id"], "magic_hex", magic.hex(), "binary", local_fid
            )
            return
        atoms = hetatm = models = seqres = 0
        chains = set()
        title = None
        scanned = 0
        trunc = False
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                scanned += len(line)
                if scanned > self.MAX_STRUCT_SCAN_BYTES:
                    trunc = True
                    break
                rec = line[:6].strip()
                if rec == "ATOM":
                    atoms += 1
                    if len(line) > 21:
                        chains.add(line[21])
                elif rec == "HETATM":
                    hetatm += 1
                elif rec == "MODEL":
                    models += 1
                elif rec == "SEQRES":
                    seqres += 1
                elif rec == "TITLE" and title is None:
                    title = line[10:].strip()
        self._emit_bio(
            ds,
            local_fid,
            records=atoms,
            props={
                "atom_count": atoms,
                "hetatm_count": hetatm,
                "model_count": models or None,
                "chain_count": len(chains) or None,
                "seqres_lines": seqres or None,
                "title": title or None,
                "scan_truncated": trunc,
            },
        )

    # ==================================================================
    # Repository linkage (local file_id -> repo file_details.file_id)
    # ==================================================================
    def link_repository(
        self,
        repository_tables: Tuple[
            List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]
        ],
        analyzed_file_paths: Optional[List[Union[str, Path]]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Rewrite every entity's LOCAL ``file_id`` to the matching repository
        ``file_details.file_id`` (via path/basename bridging identical to
        SchemaAnalyzer) and build ``data_file_index``.
        """
        folders, extensions, files = repository_tables
        ext_by_id = {e["extension_id"]: e["extension_name"] for e in extensions}
        folder_by_id = {f["folder_id"]: f["folder_name"] for f in folders}

        repo_by_relpath: Dict[str, int] = {}
        repo_by_basename: Dict[str, List[int]] = {}
        for f in files:
            ext = ext_by_id.get(f.get("file_extension_id"))
            ext = None if ext in (None, "None", "") else ext
            location = f.get("location") or []
            deepest = location[-1] if location else 1
            folder_path = folder_by_id.get(deepest, ".")
            fname = f["file_name"] + (f".{ext}" if ext else "")
            relpath = (
                fname if folder_path in (".", "", None) else f"{folder_path}/{fname}"
            )
            repo_by_relpath.setdefault(relpath, f["file_id"])
            repo_by_basename.setdefault(Path(relpath).name, []).append(f["file_id"])

        analyzed = [Path(p) for p in (analyzed_file_paths or self.file_paths)]
        local_to_repo: Dict[int, Optional[int]] = {}
        for idx, p in enumerate(analyzed, start=1):
            posix = p.as_posix()
            matched = None
            best_len = -1
            for rel, fid in repo_by_relpath.items():
                if posix == rel or posix.endswith("/" + rel):
                    if len(rel) > best_len:
                        best_len = len(rel)
                        matched = fid
            if matched is None:
                cands = repo_by_basename.get(p.name, [])
                if len(cands) == 1:
                    matched = cands[0]
            local_to_repo[idx] = matched

        entity_tables = [
            (self.KIND_DATASET, self.data_datasets_table, "dataset_id"),
            (self.KIND_COLUMN, self.data_columns_table, "column_id"),
            (self.KIND_TENSOR, self.data_tensors_table, "tensor_id"),
            (self.KIND_RELATION, self.data_relations_table, "relation_id"),
            (self.KIND_PROPERTY, self.data_properties_table, "property_id"),
            (self.KIND_MODEL_LAYER, self.data_model_layers_table, "model_layer_id"),
        ]
        # Clear in place (never rebind) so any table dict already handed out by
        # ``get_tables()`` before linkage observes the populated index.
        self.data_file_index.clear()
        for kind, rows, id_key in entity_tables:
            for row in rows:
                repo_id = local_to_repo.get(row.get("file_id"))
                row["file_id"] = repo_id
                if repo_id is not None:
                    self.data_file_index.append(
                        {
                            "dfi_id": self._next("dfi"),
                            "file_id": repo_id,
                            "entity_kind": kind,
                            "entity_id": row[id_key],
                        }
                    )
        return self.data_file_index

    # ==================================================================
    # Export
    # ==================================================================
    def _export(self, tables: Dict[str, List[Dict[str, Any]]]) -> None:
        out = Path(self.dump_file_path)
        if self.dump_file_type == "json":
            with open(out, "w", encoding="utf-8") as f:
                json.dump(tables, f, indent=2)
            print(f"Exported data analysis to JSON: {out}")
        elif self.dump_file_type in ("yml", "yaml"):
            import yaml

            with open(out, "w", encoding="utf-8") as f:
                yaml.dump(tables, f, sort_keys=False)
            print(f"Exported data analysis to YAML: {out}")
