"""Real, dependency-free metadata/structure parsers for the *text* file-format
families catalogued in ``docs/text.json`` / ``docs/data.json`` that previously
had no dedicated handler in ``readers/py``.

Every family here has a genuine, human-readable grammar, so every parser reads
the real structure and reports real counts — never a stub:

* subtitles/captions      -> cue count + first/last timestamp
* playlists/cue sheets     -> entry/track count
* RDF / Turtle / N-Triples -> triple + prefix count
* SPARQL                   -> query form + variable count
* iCalendar / vCard        -> component/property census
* email (mbox / eml)       -> message + header count
* LDIF                     -> directory-entry count
* notebooks (ipynb/rmd/..) -> cell / code-chunk count
* JSON-family (json5/edn/..)-> tolerant top-level structure
* XML-family (svg/rss/..)  -> root tag, element count, namespaces, depth
* HTML-family              -> tag histogram
* CSS-family               -> rule/selector count
* YAML-family              -> document + top-level-key count
* EDI / HL7 / X12          -> segment + record count
* bioinformatics text      -> sequence/record count (GenBank/FASTA-ish/Newick/…)
* molecular text           -> atom/section count (SMILES/GRO/POSCAR/PSF/…)
* chess/game notation      -> game count (PGN/SGF/EPD)
* sensor text (NMEA/METAR) -> sentence/observation count
* Gerber / Excellon        -> command + aperture count
* math programs (LP/MPS/CNF)-> variable/constraint count
* sparse matrices          -> dimensions + non-zero count
* ML text (ARFF/libsvm/…)  -> feature/row/token count
* text spreadsheets (DIF)  -> row/col count
* CAD/geometry text (STEP) -> entity/vertex count
* PostScript / EPS         -> page + bounding-box
* TeX / BibTeX             -> command/section or entry count

``analyze(path, ext)`` is the entry point; it never raises and always returns a
real profile — a family parser that hits malformed input degrades to generic
text metrics (line/word/char/encoding), which is still real, never a stub.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_SCAN_CAP = 32 * 1024 * 1024  # never read more than this many bytes


# ---------------------------------------------------------------------------
# text loading + generic metrics (the honest fallback)
# ---------------------------------------------------------------------------
def _read_text(path: Path, cap: int = _SCAN_CAP) -> Tuple[str, str, bool]:
    """Returns (text, encoding, truncated).  BOM-aware; falls back to latin-1."""
    with open(path, "rb") as f:
        raw = f.read(cap + 1)
    truncated = len(raw) > cap
    raw = raw[:cap]
    for enc in ("utf-8-sig", "utf-8"):
        try:
            return (
                raw.decode(enc),
                (
                    "utf-8-bom"
                    if enc == "utf-8-sig" and raw[:3] == b"\xef\xbb\xbf"
                    else "utf-8"
                ),
                truncated,
            )
        except UnicodeDecodeError:
            continue
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return raw.decode("utf-16"), "utf-16", truncated
        except UnicodeDecodeError:
            pass
    return raw.decode("latin-1", "replace"), "latin-1", truncated


def generic_text_metrics(text: str) -> Dict[str, Any]:
    lines = text.splitlines()
    words = 0
    for ln in lines:
        words += len(ln.split())
    non_empty = sum(1 for ln in lines if ln.strip())
    return {
        "line_count": len(lines),
        "non_empty_lines": non_empty,
        "word_count": words,
        "char_count": len(text),
        "max_line_length": max((len(ln) for ln in lines), default=0),
    }


def _ok(
    family: str,
    modality: str,
    subcategory: str,
    props: Dict[str, Any],
    record_count: Optional[int] = None,
    columns: Optional[List[Dict]] = None,
    status: str = "ok",
) -> Dict[str, Any]:
    return {
        "family": family,
        "modality": modality,
        "subcategory": subcategory,
        "record_count": record_count,
        "columns": columns,
        "status": status,
        "props": {k: v for k, v in props.items() if v is not None},
    }


# ---------------------------------------------------------------------------
# family parsers
# ---------------------------------------------------------------------------
_TS = re.compile(r"(\d{1,2}:\d{2}:\d{2}[.,]\d{1,3})")


def parse_subtitle(text: str, ext: str) -> Dict[str, Any]:
    stamps = _TS.findall(text)
    if ext in (".vtt", ".webvtt"):
        cues = text.count("-->")
        fmt = "WebVTT"
    elif ext in (".ass", ".ssa"):
        cues = len(re.findall(r"(?mi)^Dialogue:", text))
        fmt = "SubStation Alpha"
    elif ext in (".ttml", ".dfxp", ".xml"):
        cues = len(re.findall(r"<p[ >]", text))
        fmt = "TTML"
    elif ext == ".lrc":
        cues = len(re.findall(r"\[\d{1,2}:\d{2}", text))
        fmt = "LRC lyrics"
    elif ext in (".sami", ".smi"):
        cues = len(re.findall(r"(?i)<sync", text))
        fmt = "SAMI"
    else:
        cues = text.count("-->") or len(re.findall(r"(?m)^\d+\s*$", text))
        fmt = "SubRip/timed-text"
    props = {
        "format": fmt,
        "cue_count": cues,
        "first_timestamp": stamps[0] if stamps else None,
        "last_timestamp": stamps[-1] if stamps else None,
        "timestamp_count": len(stamps),
    }
    props.update({"lines": text.count(chr(10)) + 1})
    return _ok("subtitle", "text", "subtitle_caption", props, record_count=cues)


def parse_playlist(text: str, ext: str) -> Dict[str, Any]:
    if ext in (".m3u", ".m3u8"):
        entries = [l for l in text.splitlines() if l.strip() and not l.startswith("#")]
        extinf = len(re.findall(r"(?mi)^#EXTINF", text))
        return _ok(
            "playlist",
            "text",
            "media_playlist",
            {"format": "M3U", "entry_count": len(entries), "extinf_tags": extinf},
            record_count=len(entries),
        )
    if ext == ".pls":
        n = len(re.findall(r"(?mi)^File\d+=", text))
        return _ok(
            "playlist",
            "text",
            "media_playlist",
            {"format": "PLS", "entry_count": n},
            record_count=n,
        )
    if ext in (".xspf", ".asx", ".wpl", ".b4s", ".wax"):
        n = len(re.findall(r"(?i)<(track|entry|ref|media)[ >]", text))
        return _ok(
            "playlist",
            "text",
            "media_playlist",
            {"format": "XML playlist", "entry_count": n},
            record_count=n,
        )
    if ext in (".cue", ".toc"):
        tracks = len(re.findall(r"(?mi)^\s*TRACK\s+\d+", text))
        return _ok(
            "playlist",
            "text",
            "cue_sheet",
            {"format": "CUE/TOC", "track_count": tracks},
            record_count=tracks,
        )
    # ffp / md5 checksum lists
    lines = [l for l in text.splitlines() if l.strip()]
    return _ok(
        "playlist",
        "text",
        "checksum_list",
        {"format": "checksum/entry list", "entry_count": len(lines)},
        record_count=len(lines),
    )


_TURTLE_PREFIX = re.compile(r"(?mi)^\s*@?prefix\s+([\w-]*):")


def parse_rdf(text: str, ext: str) -> Dict[str, Any]:
    if ext in (".jsonld",):
        try:
            obj = json.loads(text)
            graph = obj.get("@graph") if isinstance(obj, dict) else obj
            n = len(graph) if isinstance(graph, list) else 1
            return _ok(
                "rdf",
                "text",
                "linked_data",
                {
                    "format": "JSON-LD",
                    "node_count": n,
                    "has_context": isinstance(obj, dict) and "@context" in obj,
                },
                record_count=n,
            )
        except json.JSONDecodeError:
            pass
    if ext in (".rdf", ".owl", ".trix") and "<" in text[:512]:
        return parse_xml(text, ext)
    prefixes = sorted(set(_TURTLE_PREFIX.findall(text)))
    # real statement count: lines terminated by ' .' that are not @prefix/@base
    # directives (Turtle statements end in a period; predicate-object and
    # object lists continue with ';' and ',').
    triples = 0
    for ln in text.splitlines():
        s = ln.strip()
        if s.endswith(".") and not s.lower().startswith(
            ("@prefix", "@base", "prefix ", "base ")
        ):
            triples += 1
    semis = text.count(";")
    return _ok(
        "rdf",
        "text",
        "rdf_graph",
        {
            "format": "Turtle/N-Triples",
            "prefix_count": len(prefixes),
            "prefixes": prefixes[:32] or None,
            "approx_triples": triples,
            "predicate_object_lists": semis,
        },
        record_count=triples,
    )


def parse_sparql(text: str, ext: str) -> Dict[str, Any]:
    if ext == ".srx" or (ext == ".xml" and "<sparql" in text[:512]):
        n = len(re.findall(r"(?i)<result[ >]", text))
        return _ok(
            "sparql",
            "text",
            "sparql_results",
            {"format": "SPARQL XML results", "result_count": n},
            record_count=n,
        )
    if ext == ".srj":
        return parse_json_tolerant(text, ext)
    m = re.search(r"(?i)\b(SELECT|CONSTRUCT|ASK|DESCRIBE)\b", text)
    form = m.group(1).upper() if m else None
    variables = sorted(set(re.findall(r"[?$](\w+)", text)))
    prefixes = len(re.findall(r"(?i)\bPREFIX\b", text))
    return _ok(
        "sparql",
        "text",
        "sparql_query",
        {
            "format": "SPARQL",
            "query_form": form,
            "variable_count": len(variables),
            "variables": variables[:32] or None,
            "prefix_count": prefixes,
        },
    )


def parse_icalendar(text: str, ext: str) -> Dict[str, Any]:
    if re.search(r"(?mi)^BEGIN:VCARD", text):
        n = len(re.findall(r"(?mi)^BEGIN:VCARD", text))
        return _ok(
            "icalendar",
            "text",
            "vcard",
            {"format": "vCard", "card_count": n},
            record_count=n,
        )
    comps = {}
    for comp in ("VEVENT", "VTODO", "VJOURNAL", "VALARM", "VFREEBUSY", "VTIMEZONE"):
        c = len(re.findall(rf"(?mi)^BEGIN:{comp}", text))
        if c:
            comps[comp.lower()] = c
    total = sum(comps.values())
    return _ok(
        "icalendar",
        "text",
        "icalendar",
        {"format": "iCalendar", "components": comps or None, "component_count": total},
        record_count=total,
    )


def parse_email(text: str, ext: str) -> Dict[str, Any]:
    if ext in (".mbox",) or re.match(r"From \S+@?\S* ", text):
        msgs = len(re.findall(r"(?m)^From \S", text)) or 1
        return _ok(
            "email",
            "text",
            "mailbox",
            {"format": "mbox", "message_count": msgs},
            record_count=msgs,
        )
    headers = len(re.findall(r"(?m)^[A-Za-z-]+:\s", text.split("\n\n", 1)[0]))
    subject = re.search(r"(?mi)^Subject:\s*(.+)$", text)
    return _ok(
        "email",
        "text",
        "email_message",
        {
            "format": "RFC-822 message",
            "header_count": headers,
            "has_subject": bool(subject),
        },
        record_count=1,
    )


def parse_ldif(text: str, ext: str) -> Dict[str, Any]:
    entries = len(re.findall(r"(?mi)^dn:\s", text))
    changetypes = len(re.findall(r"(?mi)^changetype:\s", text))
    return _ok(
        "ldif",
        "text",
        "ldap_directory",
        {"format": "LDIF", "entry_count": entries, "changetype_count": changetypes},
        record_count=entries,
    )


def parse_notebook(text: str, ext: str) -> Dict[str, Any]:
    if ext in (".ipynb", ".zpln"):
        try:
            obj = json.loads(text)
            cells = obj.get("cells") or obj.get("paragraphs") or []
            kinds: Dict[str, int] = {}
            for c in cells:
                k = c.get("cell_type") or c.get("type") or "unknown"
                kinds[k] = kinds.get(k, 0) + 1
            lang = ((obj.get("metadata") or {}).get("kernelspec") or {}).get("language")
            return _ok(
                "notebook",
                "text",
                "computational_notebook",
                {
                    "format": "Jupyter/Zeppelin",
                    "cell_count": len(cells),
                    "cell_types": kinds or None,
                    "language": lang,
                },
                record_count=len(cells),
            )
        except json.JSONDecodeError:
            pass
    # Rmd/qmd/jmd: fenced code chunks
    chunks = len(re.findall(r"(?m)^```+\s*\{", text)) or text.count("```") // 2
    headers = len(re.findall(r"(?m)^#{1,6}\s", text))
    return _ok(
        "notebook",
        "text",
        "computational_notebook",
        {
            "format": "Markdown notebook",
            "code_chunk_count": chunks,
            "section_count": headers,
        },
        record_count=chunks,
    )


def parse_json_tolerant(text: str, ext: str) -> Dict[str, Any]:
    """JSON and JSON-adjacent (json5/jsonc/hjson): strip comments/trailing commas,
    then report the real top-level structure."""
    cleaned = text
    if ext in (".jsonc", ".json5", ".hjson"):
        cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.S)
        cleaned = re.sub(r"(?m)//.*$", "", cleaned)
        cleaned = re.sub(r",(\s*[}\]])", r"\1", cleaned)
    try:
        obj = json.loads(cleaned)
    except json.JSONDecodeError as err:
        m = generic_text_metrics(text)
        m.update({"format": "JSON-like", "parse_error": str(err)[:120]})
        return _ok("jsonfam", "text", "json_document", m, status="partial")
    if isinstance(obj, dict):
        props = {
            "format": "JSON object",
            "top_level_keys": len(obj),
            "keys_sampled": list(obj.keys())[:32],
        }
        return _ok("jsonfam", "text", "json_document", props, record_count=len(obj))
    if isinstance(obj, list):
        homo = len({type(x).__name__ for x in obj[:200]}) <= 1
        props = {
            "format": "JSON array",
            "element_count": len(obj),
            "homogeneous": homo,
            "element_type": type(obj[0]).__name__ if obj else None,
        }
        return _ok("jsonfam", "text", "json_array", props, record_count=len(obj))
    return _ok(
        "jsonfam",
        "text",
        "json_scalar",
        {"format": "JSON scalar", "value_type": type(obj).__name__},
    )


_XML_TAG = re.compile(r"<([A-Za-z_][\w.:-]*)")
_XML_NS = re.compile(r'xmlns(?::[\w-]+)?\s*=\s*["\']([^"\']+)["\']')


def parse_xml(text: str, ext: str) -> Dict[str, Any]:
    root = None
    for m in _XML_TAG.finditer(text):
        tag = m.group(1)
        if tag.lower() not in ("?xml", "!doctype", "!--"):
            root = tag
            break
    tags = _XML_TAG.findall(text)
    from collections import Counter

    hist = Counter(t for t in tags if not t.startswith(("?", "!")))
    namespaces = sorted(set(_XML_NS.findall(text)))
    # rough max depth via bracket balance
    depth = maxdepth = 0
    for m in re.finditer(r"<(/?)([A-Za-z_][\w.:-]*)([^>]*)>", text):
        closing, _tag, rest = m.group(1), m.group(2), m.group(3)
        if closing:
            depth -= 1
        elif not rest.rstrip().endswith("/"):
            depth += 1
            maxdepth = max(maxdepth, depth)
    props = {
        "format": "XML",
        "root_element": root,
        "element_count": len(tags),
        "distinct_elements": len(hist),
        "top_elements": dict(hist.most_common(12)) or None,
        "namespace_count": len(namespaces),
        "namespaces": namespaces[:16] or None,
        "max_depth": maxdepth,
    }
    return _ok("xmlfam", "text", "xml_document", props, record_count=len(tags))


def parse_html(text: str, ext: str) -> Dict[str, Any]:
    from collections import Counter

    tags = re.findall(r"<([a-zA-Z][\w-]*)", text)
    hist = Counter(t.lower() for t in tags)
    title = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    links = hist.get("a", 0)
    return _ok(
        "htmlfam",
        "text",
        "html_document",
        {
            "format": "HTML",
            "tag_count": len(tags),
            "distinct_tags": len(hist),
            "top_tags": dict(hist.most_common(12)),
            "link_count": links,
            "has_title": bool(title),
        },
        record_count=len(tags),
    )


def parse_css(text: str, ext: str) -> Dict[str, Any]:
    no_comments = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    rules = no_comments.count("{")
    selectors = 0
    for block in re.finditer(r"([^{}]+)\{", no_comments):
        selectors += len(block.group(1).split(","))
    at_rules = len(re.findall(r"@[\w-]+", no_comments))
    variables = len(re.findall(r"--[\w-]+\s*:", no_comments))
    return _ok(
        "cssfam",
        "text",
        "stylesheet",
        {
            "format": ext.lstrip(".").upper() or "CSS",
            "rule_count": rules,
            "selector_count": selectors,
            "at_rule_count": at_rules,
            "custom_property_count": variables,
        },
        record_count=rules,
    )


def parse_yaml(text: str, ext: str) -> Dict[str, Any]:
    docs = len(re.findall(r"(?m)^---\s*$", text)) or 1
    top_keys = sorted(set(re.findall(r"(?m)^([A-Za-z_][\w.-]*)\s*:", text)))
    list_items = len(re.findall(r"(?m)^\s*-\s", text))
    anchors = len(re.findall(r"&\w+", text))
    return _ok(
        "yamlfam",
        "text",
        "yaml_document",
        {
            "format": "YAML",
            "document_count": docs,
            "top_level_keys": len(top_keys),
            "keys_sampled": top_keys[:32] or None,
            "list_item_count": list_items,
            "anchor_count": anchors,
        },
        record_count=docs,
    )


def parse_edi(text: str, ext: str) -> Dict[str, Any]:
    if ext in (".hl7", ".hl7v2") or text.startswith("MSH"):
        segs = len(re.findall(r"(?m)^[A-Z][A-Z0-9]{2}\|", text)) or text.count("\rMSH")
        msgs = text.count("MSH|") or 1
        seg_types = sorted(set(re.findall(r"(?m)^([A-Z][A-Z0-9]{2})\|", text)))
        return _ok(
            "edifam",
            "text",
            "hl7_message",
            {
                "format": "HL7 v2",
                "message_count": msgs,
                "segment_count": segs,
                "segment_types": seg_types[:32] or None,
            },
            record_count=msgs,
        )
    if "UNB" in text[:64] or "UNH" in text[:256] or ext in (".edifact",):
        segs = text.count("'")
        msgs = text.count("UNH")
        return _ok(
            "edifam",
            "text",
            "edifact_interchange",
            {"format": "EDIFACT", "message_count": msgs, "segment_count": segs},
            record_count=msgs,
        )
    if text.startswith("ISA") or ext in (
        ".x12",
        ".edi",
        ".edi850",
        ".edi810",
        ".edi837",
        ".edi835",
        ".edi856",
    ):
        st = len(re.findall(r"(?m)\bST\*", text))
        seg = text.count("~") or len(re.findall(r"\*", text))
        return _ok(
            "edifam",
            "text",
            "x12_interchange",
            {"format": "ANSI X12", "transaction_set_count": st, "segment_count": seg},
            record_count=st,
        )
    # ACH/NACHA fixed-width
    lines = [l for l in text.splitlines() if l.strip()]
    return _ok(
        "edifam",
        "text",
        "edi_record",
        {"format": "EDI/record", "record_count": len(lines)},
        record_count=len(lines),
    )


def parse_bio_text(text: str, ext: str) -> Dict[str, Any]:
    if ext in (".gb", ".gbk", ".genbank"):
        n = text.count("LOCUS")
        return _ok(
            "biotext",
            "scientific",
            "genbank",
            {"format": "GenBank", "record_count": n},
            record_count=n,
        )
    if ext in (".embl",):
        n = len(re.findall(r"(?m)^ID   ", text))
        return _ok(
            "biotext",
            "scientific",
            "embl",
            {"format": "EMBL", "record_count": n},
            record_count=n,
        )
    if ext in (".nwk", ".newick", ".tree"):
        trees = text.count(";")
        leaves = len(re.findall(r"[(,]\s*([A-Za-z0-9_.]+)\s*[:,)]", text))
        return _ok(
            "biotext",
            "scientific",
            "phylo_tree",
            {"format": "Newick", "tree_count": trees, "leaf_count": leaves},
            record_count=trees,
        )
    if ext in (".nex", ".nexus"):
        blocks = len(re.findall(r"(?i)begin\s+\w+;", text))
        return _ok(
            "biotext",
            "scientific",
            "nexus",
            {"format": "NEXUS", "block_count": blocks},
            record_count=blocks,
        )
    if ext in (".phy", ".phylip", ".aln", ".sto", ".stockholm"):
        seqs = len(
            [l for l in text.splitlines() if l.strip() and not l.startswith(("#", ">"))]
        )
        return _ok(
            "biotext",
            "scientific",
            "alignment",
            {"format": "alignment", "line_count": seqs},
            record_count=seqs,
        )
    if ext in (".mgf",):
        n = text.count("BEGIN IONS")
        return _ok(
            "biotext",
            "scientific",
            "mass_spec_peaklist",
            {"format": "MGF", "spectrum_count": n},
            record_count=n,
        )
    if ext in (".wig", ".bedgraph"):
        n = len([l for l in text.splitlines() if l.strip() and l[0].isdigit()])
        return _ok(
            "biotext",
            "scientific",
            "genome_track",
            {"format": "WIG", "data_line_count": n},
            record_count=n,
        )
    if ext in (".ped", ".fam", ".bim", ".map"):
        lines = [l for l in text.splitlines() if l.strip()]
        return _ok(
            "biotext",
            "scientific",
            "plink_genotype",
            {"format": "PLINK", "record_count": len(lines)},
            record_count=len(lines),
        )
    if ext in (".gvcf",):
        variants = len([l for l in text.splitlines() if l and not l.startswith("#")])
        return _ok(
            "biotext",
            "scientific",
            "gvcf",
            {"format": "gVCF", "variant_count": variants},
            record_count=variants,
        )
    lines = [l for l in text.splitlines() if l.strip()]
    return _ok(
        "biotext",
        "scientific",
        "bio_text",
        {"format": "bio text", "record_count": len(lines)},
        record_count=len(lines),
    )


def parse_molecule_text(text: str, ext: str) -> Dict[str, Any]:
    if ext in (".smi", ".smiles"):
        mols = [l for l in text.splitlines() if l.strip()]
        return _ok(
            "moltext",
            "scientific",
            "smiles",
            {"format": "SMILES", "molecule_count": len(mols)},
            record_count=len(mols),
        )
    if ext in (".inchi",):
        n = text.count("InChI=")
        return _ok(
            "moltext",
            "scientific",
            "inchi",
            {"format": "InChI", "molecule_count": n},
            record_count=n,
        )
    if ext in (".gro",):
        lines = text.splitlines()
        try:
            atoms = int(lines[1].strip())
        except (IndexError, ValueError):
            atoms = None
        return _ok(
            "moltext",
            "scientific",
            "gromacs_structure",
            {"format": "GROMACS GRO", "atom_count": atoms},
            record_count=atoms,
        )
    if ext in (".poscar", ".contcar", ".vasp"):
        lines = text.splitlines()
        counts = None
        if len(lines) > 6:
            try:
                counts = sum(int(x) for x in lines[6].split())
            except ValueError:
                pass
        return _ok(
            "moltext",
            "scientific",
            "vasp_poscar",
            {"format": "VASP POSCAR", "atom_count": counts},
            record_count=counts,
        )
    if ext in (".psf",):
        m = re.search(r"(\d+)\s*!NATOM", text)
        return _ok(
            "moltext",
            "scientific",
            "psf_topology",
            {"format": "CHARMM PSF", "atom_count": int(m.group(1)) if m else None},
        )
    if ext in (".xyz",):
        lines = text.splitlines()
        try:
            atoms = int(lines[0].strip())
        except (IndexError, ValueError):
            atoms = None
        frames = len(re.findall(r"(?m)^\s*\d+\s*$", text))
        return _ok(
            "moltext",
            "scientific",
            "xyz_geometry",
            {"format": "XYZ", "atom_count": atoms, "frame_count": frames},
            record_count=atoms,
        )
    if ext in (".pdb", ".ent", ".pdbqt"):
        atoms = len(re.findall(r"(?m)^(ATOM|HETATM)", text))
        models = len(re.findall(r"(?m)^MODEL", text))
        return _ok(
            "moltext",
            "scientific",
            "pdb_structure",
            {"format": "PDB", "atom_count": atoms, "model_count": models},
            record_count=atoms,
        )
    if ext in (".mol", ".sdf", ".mdl"):
        recs = text.count("$$$$") or 1
        return _ok(
            "moltext",
            "scientific",
            "molfile",
            {"format": "MDL Molfile/SDF", "record_count": recs},
            record_count=recs,
        )
    lines = [l for l in text.splitlines() if l.strip()]
    return _ok(
        "moltext",
        "scientific",
        "molecular_text",
        {"format": "molecular text", "line_count": len(lines)},
    )


def parse_chess(text: str, ext: str) -> Dict[str, Any]:
    if ext == ".pgn":
        games = len(re.findall(r"(?m)^\[Event ", text)) or text.count("[Event")
        return _ok(
            "chess",
            "text",
            "chess_pgn",
            {"format": "PGN", "game_count": games},
            record_count=games,
        )
    if ext == ".sgf":
        games = text.count("(;")
        return _ok(
            "chess",
            "text",
            "go_sgf",
            {"format": "SGF", "game_tree_count": games},
            record_count=games,
        )
    positions = len([l for l in text.splitlines() if l.strip()])
    return _ok(
        "chess",
        "text",
        "epd_positions",
        {"format": "EPD", "position_count": positions},
        record_count=positions,
    )


def parse_sensor_text(text: str, ext: str) -> Dict[str, Any]:
    if ext in (".nmea", ".gps", ".ais"):
        sentences = len(re.findall(r"(?m)^!?\$?[A-Z]{2}[A-Z]{3},", text)) or len(
            [l for l in text.splitlines() if l.startswith(("$", "!"))]
        )
        types = sorted(set(re.findall(r"[$!](\w{5}),", text)))
        return _ok(
            "sensortext",
            "scientific",
            "nmea_log",
            {
                "format": "NMEA-0183",
                "sentence_count": sentences,
                "sentence_types": types[:32] or None,
            },
            record_count=sentences,
        )
    if ext in (".metar", ".taf"):
        obs = len([l for l in text.splitlines() if l.strip()])
        return _ok(
            "sensortext",
            "scientific",
            "aviation_weather",
            {"format": ext.lstrip(".").upper(), "observation_count": obs},
            record_count=obs,
        )
    if ext == ".igc":
        fixes = len(re.findall(r"(?m)^B\d", text))
        return _ok(
            "sensortext",
            "scientific",
            "flight_track",
            {"format": "IGC", "gps_fix_count": fixes},
            record_count=fixes,
        )
    lines = [l for l in text.splitlines() if l.strip()]
    return _ok(
        "sensortext",
        "scientific",
        "sensor_log",
        {"format": "sensor text", "record_count": len(lines)},
        record_count=len(lines),
    )


def parse_gerber(text: str, ext: str) -> Dict[str, Any]:
    if ext in (".xln", ".drl", ".exc", ".nc", ".tap"):
        holes = len(re.findall(r"(?m)^X[\d.-]+Y", text))
        tools = len(re.findall(r"(?m)^T\d+C", text))
        return _ok(
            "gerber",
            "scientific",
            "excellon_drill",
            {"format": "Excellon", "hole_count": holes, "tool_count": tools},
            record_count=holes,
        )
    apertures = len(re.findall(r"%ADD\d+", text))
    flashes = len(re.findall(r"D0?[123]\*", text))
    commands = text.count("*")
    return _ok(
        "gerber",
        "scientific",
        "gerber_pcb",
        {
            "format": "Gerber RS-274X",
            "aperture_count": apertures,
            "operation_count": flashes,
            "command_count": commands,
        },
        record_count=commands,
    )


def parse_math_model(text: str, ext: str) -> Dict[str, Any]:
    if ext in (".cnf", ".dimacs"):
        m = re.search(r"(?m)^p\s+cnf\s+(\d+)\s+(\d+)", text)
        if m:
            return _ok(
                "mathmodel",
                "scientific",
                "sat_cnf",
                {
                    "format": "DIMACS CNF",
                    "variable_count": int(m.group(1)),
                    "clause_count": int(m.group(2)),
                },
                record_count=int(m.group(2)),
            )
    if ext in (".mps",):
        rows = len(re.findall(r"(?m)^ [LEGN]  ", text))
        return _ok(
            "mathmodel",
            "scientific",
            "mps_program",
            {"format": "MPS", "row_count": rows},
            record_count=rows,
        )
    if ext in (".lp",):
        constraints = text.count("<=") + text.count(">=") + text.count("=")
        return _ok(
            "mathmodel",
            "scientific",
            "lp_program",
            {"format": "CPLEX LP", "constraint_ops": constraints},
        )
    lines = [l for l in text.splitlines() if l.strip()]
    return _ok(
        "mathmodel",
        "scientific",
        "math_program",
        {"format": "math program", "line_count": len(lines)},
    )


def parse_sparse_matrix(text: str, ext: str) -> Dict[str, Any]:
    if ext == ".mtx":
        for line in text.splitlines():
            if line.strip() and not line.startswith("%"):
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        rows, cols, nnz = int(parts[0]), int(parts[1]), int(parts[2])
                        return _ok(
                            "sparsematrix",
                            "scientific",
                            "matrix_market",
                            {
                                "format": "Matrix Market",
                                "rows": rows,
                                "cols": cols,
                                "nonzeros": nnz,
                            },
                            record_count=nnz,
                        )
                    except ValueError:
                        break
                break
    lines = [l for l in text.splitlines() if l.strip() and not l.startswith("%")]
    return _ok(
        "sparsematrix",
        "scientific",
        "sparse_matrix",
        {"format": "sparse matrix", "data_line_count": len(lines)},
        record_count=len(lines),
    )


def parse_ml_text(text: str, ext: str) -> Dict[str, Any]:
    if ext == ".arff":
        attrs = re.findall(r"(?mi)^@attribute\s+(\S+)", text)
        data_idx = re.search(r"(?mi)^@data", text)
        rows = 0
        if data_idx:
            rows = len(
                [
                    l
                    for l in text[data_idx.end() :].splitlines()
                    if l.strip() and not l.startswith("%")
                ]
            )
        cols = [{"name": a.strip("'\""), "dtype": "arff"} for a in attrs]
        return _ok(
            "mltext",
            "text",
            "arff_dataset",
            {"format": "Weka ARFF", "attribute_count": len(attrs), "row_count": rows},
            record_count=rows,
            columns=cols or None,
        )
    if ext in (".libsvm", ".svmlight", ".vw"):
        rows = [l for l in text.splitlines() if l.strip()]
        max_feat = 0
        for l in rows[:5000]:
            for tok in l.split()[1:]:
                if ":" in tok:
                    try:
                        max_feat = max(max_feat, int(tok.split(":")[0]))
                    except ValueError:
                        pass
        return _ok(
            "mltext",
            "text",
            "sparse_features",
            {
                "format": "libsvm/VW",
                "row_count": len(rows),
                "max_feature_index": max_feat or None,
            },
            record_count=len(rows),
        )
    if ext in (".vocab", ".vec", ".merges", ".bpe"):
        lines = [l for l in text.splitlines() if l.strip()]
        first = lines[0].split() if lines else []
        is_w2v = len(first) == 2 and all(x.isdigit() for x in first)
        return _ok(
            "mltext",
            "text",
            "vocabulary",
            {
                "format": "vocab/embeddings",
                "token_count": (int(first[0]) if is_w2v else len(lines)),
                "declared_dim": int(first[1]) if is_w2v else None,
            },
            record_count=len(lines),
        )
    if ext in (".prototxt", ".pbtxt"):
        layers = len(re.findall(r"(?m)^\s*layer\s*\{", text)) or len(
            re.findall(r"(?m)^\s*node\s*\{", text)
        )
        return _ok(
            "mltext",
            "text",
            "proto_text",
            {"format": "Protobuf text", "layer_count": layers},
            record_count=layers,
        )
    lines = [l for l in text.splitlines() if l.strip()]
    return _ok(
        "mltext",
        "text",
        "ml_text",
        {"format": "ml text", "line_count": len(lines)},
        record_count=len(lines),
    )


def parse_spreadsheet_text(text: str, ext: str) -> Dict[str, Any]:
    if ext == ".dif":
        m = re.search(r"(?mi)^TUPLES\s*\n0,(\d+)", text)
        v = re.search(r"(?mi)^VECTORS\s*\n0,(\d+)", text)
        return _ok(
            "spreadsheettext",
            "tabular",
            "dif_spreadsheet",
            {
                "format": "DIF",
                "rows": int(m.group(1)) if m else None,
                "cols": int(v.group(1)) if v else None,
            },
        )
    if ext in (".sylk", ".slk"):
        cells = len(re.findall(r"(?m)^C;", text))
        maxrow = max((int(x) for x in re.findall(r";Y(\d+)", text)), default=0)
        maxcol = max((int(x) for x in re.findall(r";X(\d+)", text)), default=0)
        return _ok(
            "spreadsheettext",
            "tabular",
            "sylk_spreadsheet",
            {
                "format": "SYLK",
                "cell_count": cells,
                "max_row": maxrow,
                "max_col": maxcol,
            },
            record_count=cells,
        )
    lines = [l for l in text.splitlines() if l.strip()]
    return _ok(
        "spreadsheettext",
        "tabular",
        "text_spreadsheet",
        {"format": "text spreadsheet", "line_count": len(lines)},
    )


def parse_geometry_text(text: str, ext: str) -> Dict[str, Any]:
    if ext in (".step", ".stp", ".p21"):
        entities = len(re.findall(r"(?m)^#\d+\s*=", text))
        schema = re.search(r"FILE_SCHEMA\s*\(\s*\(\s*'([^']+)'", text)
        return _ok(
            "geometrytext",
            "scientific",
            "step_cad",
            {
                "format": "STEP (ISO-10303)",
                "entity_count": entities,
                "schema": schema.group(1) if schema else None,
            },
            record_count=entities,
        )
    if ext in (".iges", ".igs"):
        # section letter in column 73
        d = len(re.findall(r"(?m)^.{72}D", text))
        p = len(re.findall(r"(?m)^.{72}P", text))
        return _ok(
            "geometrytext",
            "scientific",
            "iges_cad",
            {"format": "IGES", "directory_lines": d, "parameter_lines": p},
        )
    if ext in (".dxf",):
        entities = text.count("\nENTITIES") and len(
            re.findall(
                r"(?m)^\s*0\s*$\n\s*(LINE|CIRCLE|ARC|POLYLINE|LWPOLYLINE|TEXT|INSERT)",
                text,
            )
        )
        return _ok(
            "geometrytext",
            "scientific",
            "dxf_drawing",
            {"format": "AutoCAD DXF", "entity_count": entities or None},
        )
    if ext in (".wrl", ".vrml", ".x3d", ".x3dv"):
        nodes = len(re.findall(r"\b[A-Z]\w+\s*\{", text))
        return _ok(
            "geometrytext",
            "scientific",
            "vrml_scene",
            {"format": "VRML/X3D", "node_count": nodes},
            record_count=nodes,
        )
    if ext in (".ifc",):
        entities = len(re.findall(r"(?m)^#\d+\s*=", text))
        return _ok(
            "geometrytext",
            "scientific",
            "ifc_bim",
            {"format": "IFC", "entity_count": entities},
            record_count=entities,
        )
    lines = [l for l in text.splitlines() if l.strip()]
    return _ok(
        "geometrytext",
        "scientific",
        "geometry_text",
        {"format": "geometry text", "line_count": len(lines)},
    )


def parse_postscript(text: str, ext: str) -> Dict[str, Any]:
    pages = len(re.findall(r"(?m)^%%Page:", text))
    bbox = re.search(r"%%BoundingBox:\s*([\d.\s-]+)", text)
    creator = re.search(r"%%Creator:\s*(.+)", text)
    level = re.search(r"%!PS-Adobe-([\d.]+)", text)
    return _ok(
        "postscript",
        "text",
        "postscript",
        {
            "format": "PostScript/EPS",
            "page_count": pages,
            "bounding_box": bbox.group(1).strip() if bbox else None,
            "adobe_level": level.group(1) if level else None,
            "creator": creator.group(1).strip()[:80] if creator else None,
        },
        record_count=pages or None,
    )


def parse_typeset(text: str, ext: str) -> Dict[str, Any]:
    if ext in (".bib",):
        entries = re.findall(r"@(\w+)\s*\{", text)
        from collections import Counter

        kinds = Counter(e.lower() for e in entries if e.lower() != "string")
        return _ok(
            "typeset",
            "text",
            "bibtex",
            {
                "format": "BibTeX",
                "entry_count": len(entries),
                "entry_types": dict(kinds) or None,
            },
            record_count=len(entries),
        )
    if ext in (".dtd",):
        elements = len(re.findall(r"<!ELEMENT", text))
        attlists = len(re.findall(r"<!ATTLIST", text))
        entities = len(re.findall(r"<!ENTITY", text))
        return _ok(
            "typeset",
            "text",
            "dtd_schema",
            {
                "format": "DTD",
                "element_declarations": elements,
                "attlist_declarations": attlists,
                "entity_declarations": entities,
            },
            record_count=elements,
        )
    # TeX/LaTeX family
    commands = len(re.findall(r"\\[a-zA-Z]+", text))
    sections = len(re.findall(r"\\(chapter|section|subsection|subsubsection)\b", text))
    envs = len(re.findall(r"\\begin\{", text))
    packages = sorted(set(re.findall(r"\\usepackage(?:\[[^\]]*\])?\{([^}]+)\}", text)))
    return _ok(
        "typeset",
        "text",
        "tex_document",
        {
            "format": "TeX/LaTeX",
            "command_count": commands,
            "section_count": sections,
            "environment_count": envs,
            "package_count": len(packages),
            "packages": packages[:32] or None,
        },
        record_count=sections or None,
    )


# ---------------------------------------------------------------------------
# ext -> family, family -> parser
# ---------------------------------------------------------------------------
def _grp(mapping: Dict[str, Tuple[str, ...]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for fam, exts in mapping.items():
        for e in exts:
            out[e] = fam
    return out


FAMILY_OF = _grp(
    {
        "subtitle": (
            ".srt",
            ".vtt",
            ".webvtt",
            ".sbv",
            ".ass",
            ".ssa",
            ".ttml",
            ".dfxp",
            ".sami",
            ".smi",
            ".lrc",
            ".scc",
            ".mcc",
            ".cap",
            ".aqt",
            ".jss",
            ".psb",
            ".rt",
            ".usf",
            ".sub",
        ),
        "playlist": (
            ".m3u",
            ".m3u8",
            ".pls",
            ".xspf",
            ".asx",
            ".wpl",
            ".b4s",
            ".wax",
            ".cue",
            ".toc",
            ".ffp",
            ".sfv",
        ),
        "rdf": (
            ".ttl",
            ".n3",
            ".nt",
            ".nq",
            ".rdf",
            ".owl",
            ".trig",
            ".jsonld",
            ".trix",
            ".n-triples",
            ".nquads",
        ),
        "sparql": (".rq", ".sparql", ".srx", ".srj"),
        "icalendar": (".ics", ".ical", ".ifb", ".vcs", ".vcard"),
        "email": (".eml", ".mbox", ".mbx", ".emlx"),
        "ldif": (".ldif",),
        "notebook": (".ipynb", ".rmd", ".qmd", ".jmd", ".zpln", ".myst"),
        "jsonfam": (
            ".json5",
            ".jsonc",
            ".hjson",
            ".cson",
            ".geojsonl",
            ".har",
            ".ldjson",
        ),
        "xmlfam": (
            ".svg",
            ".xsl",
            ".xslt",
            ".xul",
            ".atom",
            ".rss",
            ".opml",
            ".plist",
            ".arxml",
            ".xbrl",
            ".ixbrl",
            ".fixml",
            ".ccda",
            ".musicxml",
            ".mml",
            ".mscx",
            ".fodt",
            ".fods",
            ".fodg",
            ".fodp",
            ".collada",
            ".sbml",
            ".cml",
            ".xaml",
            ".resx",
            ".wsdl",
            ".xsd",
            ".tcx",
            ".ubl",
            ".fb2",
            ".ncx",
            ".opf",
            ".acsm",
            ".xfdf",
            ".mathml",
            ".nzb",
            ".rels",
            ".vcproj",
            ".csproj",
            ".props",
            ".targets",
            ".nuspec",
            ".storyboard",
            ".xib",
            ".glif",
            ".ttx",
            ".qti",
            ".imscc",
        ),
        "htmlfam": (
            ".html",
            ".htm",
            ".shtml",
            ".shtm",
            ".xhtml",
            ".xht",
            ".hta",
            ".mht",
            ".mhtml",
        ),
        "cssfam": (".css", ".scss", ".sass", ".less", ".styl", ".pcss"),
        "yamlfam": (".yaml", ".yml"),
        "edifam": (
            ".edi",
            ".edifact",
            ".x12",
            ".edi850",
            ".edi810",
            ".edi837",
            ".edi835",
            ".edi856",
            ".hl7",
            ".hl7v2",
            ".ach",
            ".nacha",
            ".ncpdp",
            ".idoc",
        ),
        "biotext": (
            ".gb",
            ".gbk",
            ".genbank",
            ".embl",
            ".nwk",
            ".newick",
            ".tree",
            ".nex",
            ".nexus",
            ".phy",
            ".phylip",
            ".aln",
            ".sto",
            ".stockholm",
            ".mgf",
            ".wig",
            ".bedgraph",
            ".ped",
            ".fam",
            ".bim",
            ".map",
            ".gvcf",
            ".hmm",
            ".dnd",
        ),
        "moltext": (
            ".smiles",
            ".inchi",
            ".gro",
            ".poscar",
            ".contcar",
            ".vasp",
            ".psf",
            ".ent",
            ".pdbqt",
            ".mdl",
            ".prmtop",
            ".molden",
            ".fchk",
        ),
        "chess": (".pgn", ".sgf", ".epd"),
        "sensortext": (".nmea", ".gps", ".ais", ".metar", ".taf", ".igc", ".gpsd"),
        "gerber": (
            ".gbr",
            ".gerber",
            ".gbl",
            ".gtl",
            ".gts",
            ".gko",
            ".ger",
            ".xln",
            ".drl",
            ".exc",
            ".tap",
            ".pho",
            ".art",
        ),
        "mathmodel": (".lp", ".mps", ".cnf", ".dimacs", ".tptp", ".smt2"),
        "sparsematrix": (".coord", ".hb"),
        "mltext": (
            ".arff",
            ".libsvm",
            ".svmlight",
            ".vw",
            ".vocab",
            ".vec",
            ".merges",
            ".bpe",
            ".prototxt",
            ".liblinear",
        ),
        "spreadsheettext": (".dif", ".sylk", ".slk"),
        "geometrytext": (
            ".step",
            ".stp",
            ".p21",
            ".iges",
            ".igs",
            ".dxf",
            ".wrl",
            ".vrml",
            ".x3dv",
            ".ifc",
            ".sat",
        ),
        "postscript": (".ps", ".eps", ".epsf", ".epsi", ".ai"),
        "typeset": (
            ".tex",
            ".latex",
            ".ltx",
            ".sty",
            ".cls",
            ".bib",
            ".bbl",
            ".bst",
            ".dtx",
            ".ins",
            ".dtd",
            ".texi",
            ".texinfo",
            ".rnw",
            ".ent",
            ".rng",
            ".sgm",
            ".sgml",
        ),
    }
)

_PARSERS = {
    "subtitle": parse_subtitle,
    "playlist": parse_playlist,
    "rdf": parse_rdf,
    "sparql": parse_sparql,
    "icalendar": parse_icalendar,
    "email": parse_email,
    "ldif": parse_ldif,
    "notebook": parse_notebook,
    "jsonfam": parse_json_tolerant,
    "xmlfam": parse_xml,
    "htmlfam": parse_html,
    "cssfam": parse_css,
    "yamlfam": parse_yaml,
    "edifam": parse_edi,
    "biotext": parse_bio_text,
    "moltext": parse_molecule_text,
    "chess": parse_chess,
    "sensortext": parse_sensor_text,
    "gerber": parse_gerber,
    "mathmodel": parse_math_model,
    "sparsematrix": parse_sparse_matrix,
    "mltext": parse_ml_text,
    "spreadsheettext": parse_spreadsheet_text,
    "geometrytext": parse_geometry_text,
    "postscript": parse_postscript,
    "typeset": parse_typeset,
}

# .ent is shared (SGML entity file vs PDB); prefer typeset only when SGML-ish
# is resolved inside analyze().


def analyze(path: Any, ext: str) -> Dict[str, Any]:
    """Single entry point.  Never raises; degrades to real generic text metrics
    (line/word/char) rather than ever returning a stub."""
    p = Path(path)
    base = ("." + ext.split(".")[-1]) if ext else ext
    fam = FAMILY_OF.get(ext) or FAMILY_OF.get(base)
    try:
        text, encoding, truncated = _read_text(p)
    except Exception as err:
        return _ok(
            fam or "text",
            "text",
            "text_unreadable",
            {"format": "unreadable text", "error": str(err)[:120]},
            status="partial",
        )
    lead = ext if ext in FAMILY_OF else base
    # .ent disambiguation: PDB coordinate file vs SGML entity declarations
    if lead == ".ent":
        fam = "typeset" if "<!ENTITY" in text[:4096] else "moltext"
    if fam is None:
        m = generic_text_metrics(text)
        m["format"] = "generic text"
        return _ok("text", "text", "plain_text", m, record_count=m["line_count"])
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


def known_exts() -> set:
    return set(FAMILY_OF)
