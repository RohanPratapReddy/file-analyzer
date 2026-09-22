"""
DocumentParser -- dedicated analysis plane for true *document* formats.

This is the engine the router's ``document_parser`` class routes to: the
``document`` ``extension_type`` universe from the canonical catalogue
(``file_analyzer/tables/file_extensions.json``) -- word-processor documents, e-books,
page-description / fixed-layout formats, notation and other rich documents
(``.pdf``, ``.doc``/``.docx``, ``.odt``, ``.rtf``, ``.epub``, ``.mobi``,
``.azw*``, ``.pages``, ``.keynote``, ``.djvu``, ...).

STATUS: routing and the per-shard worker are fully wired (see
:func:`file_analyzer.router.routing.resolve_analyzer` and ``file_analyzer/router/worker.py``) so every
document-format file is assigned to this plane and flows through a real
``shard_document_parser`` worker. :meth:`_converter` is a *real* format-to-text
converter (DOCX / ODT / EPUB / RTF / (X)HTML / MusicXML with the standard library
alone; PDF / XPS / PostScript / DjVu / OCR through optional libraries or CLIs when
installed; optional AI backends only as a last resort). :meth:`analyze` still emits
a one-row-per-file *census* (name, extension, byte size); wiring the converter's
output into a richer per-file table is the remaining follow-up and needs no changes
elsewhere in the pipeline -- it only fills the same table shape.

Interface parity with the sibling plane engines (schema / data / config / text /
markup / document / misc): a ``file_paths`` constructor, :meth:`analyze`,
:meth:`get_tables`, :meth:`routing_suffixes` / :meth:`_known_exts`, and a
:meth:`link_repository` that rewrites the LOCAL ``file_id`` (1-based index into
the analyzed file list) to the repository ``file_details.file_id`` and populates
``document_parser_file_index`` -- so the plane plugs straight into the
Go/Java per-shard worker and (once its tables are consumed) the
``RepositoryDatabaseGenerator``.
"""

from __future__ import annotations

import hashlib
import json
import math
import posixpath
import re
import shutil
import subprocess
import unicodedata
import zipfile
from html.parser import HTMLParser
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
)
from xml.etree import ElementTree as ET

# The ``document`` extension_type universe (lower-cased last-component suffixes),
# lifted verbatim from file_analyzer/tables/file_extensions.json. This is the plane's
# candidate set; the router subtracts any suffix a higher-priority plane already
# owns for a *non-document* meaning (source code / schema-definition languages),
# so genuinely dual-use tails such as ``.gp`` / ``.ws`` / ``.ily`` (code) and
# ``.msg`` (ROS message IDL) keep their existing owners.
DOCUMENT_SUFFIXES: Tuple[str, ...] = (
    ".602",
    ".abw",
    ".afp",
    ".azw",
    ".azw3",
    ".azw4",
    ".bwp",
    ".capx",
    ".cba",
    ".cdf",
    ".ceb",
    ".cwk",
    ".djv",
    ".djvu",
    ".doc",
    ".docm",
    ".docx",
    ".dot",
    ".dotm",
    ".dotx",
    ".dpt",
    ".dvi",
    ".dwf",
    ".dwfx",
    ".epsi",
    ".epub",
    ".epub3",
    ".fb3",
    ".fdf",
    ".fm",
    ".gdoc",
    ".gp",
    ".gp3",
    ".gp4",
    ".gp5",
    ".gp7",
    ".gpx",
    ".gslides",
    ".hml",
    ".hwp",
    ".hwpx",
    ".ibooks",
    ".ily",
    ".journal",
    ".keynote",
    ".kf8",
    ".kfx",
    ".kpf",
    ".lit",
    ".lrf",
    ".lrx",
    ".lwp",
    ".mcdx",
    ".mcw",
    ".mobi",
    ".modca",
    ".mrc",
    ".mscz",
    ".msg",
    ".musx",
    ".mwp",
    ".mxl",
    ".mxm",
    ".nbk",
    ".odt",
    ".one",
    ".ott",
    ".oxps",
    ".pades",
    ".pages",
    ".pdb",
    ".pdf",
    ".pdfa",
    ".pdfvt",
    ".pdfx",
    ".pdfx1a",
    ".pdfx4",
    ".pml",
    ".ppam",
    ".prc",
    ".pressready",
    ".ps",
    ".ps3",
    ".ptb",
    ".rtf",
    ".sam",
    ".sdd",
    ".sdw",
    ".sib",
    ".sldm",
    ".snb",
    ".spv",
    ".sti",
    ".stw",
    ".sxw",
    ".t23",
    ".tax",
    ".tax2023",
    ".tcr",
    ".tg",
    ".tns",
    ".tr2",
    ".tr3",
    ".uof",
    ".uos",
    ".uot",
    ".vor",
    ".wn",
    ".wpd",
    ".wps",
    ".wri",
    ".ws",
    ".wwf",
    ".xdv",
    ".xfdf",
    ".xmcd",
    ".xopp",
    ".xps",
    ".xwp",
    ".zabw",
)


# --- conversion modality families -------------------------------------------
# _converter() maps each suffix to *how* it must be turned into text. Model-backed
# modalities are optional: without a registered backend the converter reports the
# modality it needs rather than fabricating output.

# Music / score notation -> textual MusicXML / ABC (a notation or text model).
_NOTATION_EXTS = frozenset(
    {
        ".gp",
        ".gp3",
        ".gp4",
        ".gp5",
        ".gp7",
        ".gpx",
        ".mscz",
        ".musx",
        ".mxl",
        ".mxm",
        ".sib",
        ".mcdx",
        ".ptb",
        ".tg",
        ".ily",
    }
)
# Page-description / fixed-layout: try an embedded text layer, else OCR.
_LAYOUT_EXTS = frozenset(
    {
        ".pdf",
        ".pdfa",
        ".pdfvt",
        ".pdfx",
        ".pdfx1a",
        ".pdfx4",
        ".ps",
        ".ps3",
        ".oxps",
        ".xps",
        ".dvi",
        ".xdv",
        ".dwf",
        ".dwfx",
        ".pades",
        ".pressready",
        ".journal",
    }
)
# Raster / scanned image documents: OCR only.
_OCR_EXTS = frozenset({".djvu", ".djv", ".epsi", ".afp", ".modca"})
# Bitmap image files (e.g. scanned pages) -> image-caption / OCR model. Not part
# of the document universe, but supported so the converter is truly multimodal.
_IMAGE_EXTS = frozenset(
    {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".gif", ".webp"}
)
# Audio files -> speech-to-text model. Also outside the document universe.
_AUDIO_EXTS = frozenset({".wav", ".mp3", ".m4a", ".flac", ".ogg", ".aac", ".opus"})
# Already-plain text families -> decoded directly, no model required.
_PLAINTEXT_EXTS = frozenset(
    {
        ".txt",
        ".text",
        ".note",
        ".todo",
        ".nfo",
        ".lst",
        ".out",
        ".asc",
        ".md",
        ".markdown",
    }
)

# --- native (stdlib-only) extractor families --------------------------------
# These are converted for real with the standard library alone -- no third-party
# package and no external binary -- so they work everywhere, including CI.
_HTML_EXTS = frozenset({".htm", ".html", ".xhtml"})
_RTF_EXTS = frozenset({".rtf"})
# Office Open XML wordprocessing (a zip of XML parts).
_OOXML_WORD_EXTS = frozenset({".docx", ".docm", ".dotx", ".dotm"})
# OpenDocument text (a zip whose content.xml holds the body).
_ODF_EXTS = frozenset({".odt", ".ott", ".fodt", ".sxw", ".stw", ".sxg", ".vor"})
# EPUB (a zip of XHTML documents ordered by the OPF spine).
_EPUB_ZIP_EXTS = frozenset({".epub", ".epub3"})
# MusicXML / MuseScore containers we can pull title + lyrics from.
_MUSICXML_EXTS = frozenset({".mxl", ".musicxml", ".mscz", ".mscx"})

# --- optional-backend families (real when the lib / CLI is present) ---------
_PDF_EXTS = frozenset({".pdf", ".pdfa", ".pdfvt", ".pdfx", ".pdfx1a", ".pdfx4"})
_XPS_EXTS = frozenset({".xps", ".oxps"})
_PS_EXTS = frozenset({".ps", ".ps3"})
_DJVU_EXTS = frozenset({".djvu", ".djv"})

# --- code-source families (from file_analyzer/tables/file_extensions.json extension_type) -
# DocumentParser owns Database 1 (the concordance over *every* repository file),
# so it carries the canonical code-extension universe: the source_code / script /
# shader / makefile families are text-decodable (indexed for real by the
# concordance) and the object_code family is compiled/binary (concord-skipped like
# any other binary). These drive :meth:`code_family`, which tags each indexed file
# with the kind of code it is. Kept as split-string frozensets so the lists stay
# diffable against the master extension catalogue.
_SOURCE_CODE_EXTS = frozenset(
    (
        ".4gl .abap .ada .adb .ads .afl .agda .al .alembic .algol .ampl .apl .as "
        ".ashx .asl .asm .asmx .astro .awl .bal .ballerina .bas .beam .befunge .bf "
        ".bicep .blackbird .blq .bms .boo .bsv .c .c++ .cairo .carbon .cask .cbl "
        ".cc .cdk .cedar .ceylon .cfc .chisel .chpl .cir .cirq .cjs .cl .clar .clj "
        ".cljc .cljs .cls .cob .coffee .com .cpp .cppm .cpy .cr .cs .ctl .cts .cu "
        ".cuf .cuh .curry .cxx .cy .d .d.ts .dag .dagster .dart .dds .def .di .dot "
        ".dpk .dpr .drl .dss .dts .dtsi .dtx .e .easytrieve .edgeworker .eiffel .el "
        ".elm .els .erl .ex .f .f03 .f08 .f77 .f90 .f95 .factor .flix .fnl .focus "
        ".for .forth .frege .frm .fs .fsharp .fsi .fth .fun .g4 .gd .geo .gjf "
        ".gleam .gms .go .gren .groovy .gv .h .hh .hip .hpf .hpp .hrl .hs .hx .hxx "
        ".hy .i3 .icn .ideal .idr .ink .inl .ino .intercal .io .ipp .ixx .j .jai "
        ".janet .java .jbi .jl .jmd .js .jsbundle .jsx .k .k6 .kk .krl .kt .l .lark "
        ".lean .lgt .lhs .lib .lidr .ligo .lisp .litcoffee .lkml .ll .locustfile "
        ".logtalk .lolcode .ls .lsp .lua .luigi .ly .m .m3 .mac .magik .marko "
        ".mercury .mermaid .mf .michelson .mizar .mjs .ml .ml4 .mli .mlir .mll .mly "
        ".mm .mmd .mo .mod .mojo .moon .move .mq4 .mq5 .mts .n .nasm .nat .nav "
        ".nbconvert .nemerle .nim .nix .nl .nut .oberon .odin .ook .openqasm .p .p6 "
        ".pas .pde .peg .pennylane .php .piet .pine .plantuml .pli .pluto.jl .pm "
        ".pony .pp .prefect .prg .progress .prolog .ptx .puml .purs .pxd .pxi .py "
        ".py.ipynb .pyi .pyquil .pyw .pyx .q .qasm .qir .qml .qmod .qs .qsharp "
        ".quest .quil .r .raku .ramis .rapid .rb .rc .re .reb .rebol .red .rego "
        ".ren .res .riot .rkt .robot .roc .rpg .rpgle .rs .s .scad .scala .sci "
        ".scilla .scl .scm .script .sentinel .sig .simula .sl .smali .sml .smt2 "
        ".snobol .sol .sp .spec .spi .ss .st .stim .sty .subckt .sv .svelte .svh "
        ".swift .swiftinterface .sycl .tal .teal .test .tf .thy .tpp .tree-sitter "
        ".triton .ts .tsl .tsx .twee .u .unison .upc .v .vala .vapi .varnish .vb "
        ".vcl .vh .vhd .vhdl .vi .vue .vy .w .wat .wl .wren .ws .y .yar .yara .zig "
        ".zpl .zpln .\U0001f525"
    ).split()
)
_SCRIPT_EXTS = frozenset(
    (
        ".ac .ado .ahk .ahk2 .applescript .atn .au3 .awk .bash .bashrc .bat .bb "
        ".bbappend .bbclass .bt .bzl .clist .clp .cmake .cmd .conanfile .csh .csx "
        ".dcl .do .ebuild .elv .expect .exs .fish .fsx .g .gdbinit .gp .gradle "
        ".gradlew .hexpat .ins .iss .jcl .jenkinsfile .jnl .js .jse .ksh .kts .m4 "
        ".mac .macro .mix .mpl .nims .nk .nknc .nsh .nsi .nu .pac .painless "
        ".pkgbuild .pl .port .postinst .postrm .preinst .prerm .prg .proclib "
        ".profile .ps1 .psm1 .rake .rexx .sage .sas .sc .sce .scl .scons .scpt "
        ".scptd .sed .sh .spack .sps .star .t .tcl .tcsh .tk .userdata .vagrantfile "
        ".vbe .vbs .wezterm .wls .wpad .wpm .wsf .xinitrc .xlm .xsession .zsh .zshrc"
    ).split()
)
_SHADER_EXTS = frozenset(
    (
        ".cg .cginc .comp .frag .geom .glsl .hlsl .metal .osl .rsl .shader .tesc "
        ".tese .usf .ush .vert .wgsl"
    ).split()
)
_OBJECT_CODE_EXTS = frozenset(
    (
        ".bc .beam .class .cof .elc .gch .hbc .lo .luac .mpy .o .obj .p .pch .pyc "
        ".pyo .r .rpyc .spv"
    ).split()
)
_MAKEFILE_EXTS = frozenset(".am .d .dep .mak .makefile .mk .mms .port".split())
# Text-decodable code families: indexed for real by the concordance (Database 1).
_CODE_TEXT_EXTS = _SOURCE_CODE_EXTS | _SCRIPT_EXTS | _SHADER_EXTS | _MAKEFILE_EXTS

# OOXML / ODF text namespaces.
_OOXML_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _localname(tag: str) -> str:
    """Strip any ``{namespace}`` prefix from an ElementTree tag."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


class _HTMLToText(HTMLParser):
    """Minimal, dependency-free HTML -> text extractor.

    Drops ``<script>`` / ``<style>`` content, turns block-level tags into line
    breaks and collapses runs of blank lines. Good enough to recover the readable
    text of an (X)HTML document or an EPUB chapter without pulling in bs4/lxml.
    """

    _BLOCK = frozenset(
        {
            "p",
            "div",
            "br",
            "li",
            "tr",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "section",
            "article",
            "header",
            "footer",
            "blockquote",
            "pre",
            "table",
            "ul",
            "ol",
            "hr",
        }
    )
    _SKIP = frozenset({"script", "style", "head", "title", "meta", "link"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: List[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag in self._SKIP:
            self._skip_depth += 1
        elif tag in self._BLOCK:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP and self._skip_depth:
            self._skip_depth -= 1
        elif tag in self._BLOCK:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0:
            self._parts.append(data)

    def get_text(self) -> str:
        text = "".join(self._parts)
        # Collapse 3+ newlines to a blank line, trim trailing spaces per line.
        text = re.sub(r"[ \t]+\n", "\n", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()


def _html_to_text(data: bytes) -> str:
    """Decode HTML bytes and reduce them to readable text."""
    html = data.decode("utf-8", errors="replace")
    parser = _HTMLToText()
    parser.feed(html)
    parser.close()
    return parser.get_text()


# RTF control words that emit whitespace / punctuation.
_RTF_SPECIAL = {
    "par": "\n",
    "sect": "\n",
    "page": "\n",
    "line": "\n",
    "tab": "\t",
    "emdash": "\u2014",
    "endash": "\u2013",
    "bullet": "\u2022",
    "lquote": "\u2018",
    "rquote": "\u2019",
    "ldblquote": "\u201c",
    "rdblquote": "\u201d",
}
# Group destinations whose contents are not body text.
_RTF_DESTINATIONS = frozenset(
    {
        "fonttbl",
        "colortbl",
        "stylesheet",
        "listtable",
        "listoverridetable",
        "info",
        "pict",
        "object",
        "themedata",
        "colorschememapping",
        "datastore",
        "generator",
        "rsidtbl",
        "mmathPr",
        "wgrffmtfilter",
        "latentstyles",
    }
)
_RTF_TOKEN = re.compile(
    r"\\([a-z]{1,32})(-?\d{1,10})?[ ]?|\\'([0-9a-fA-F]{2})|\\([^a-z])|([{}])|[\r\n]+|(.)",
    re.IGNORECASE,
)


def _rtf_to_text(data: bytes) -> str:
    """Convert RTF bytes to plain text (real de-RTF, no third-party dep).

    Handles groups, ignorable ``{\\*..}`` and known non-body destinations,
    ``\\'xx`` hex bytes, ``\\uN`` unicode escapes (with the following fallback
    char skipped) and the common whitespace control words.
    """
    text = data.decode("latin-1", errors="replace")
    out: List[str] = []
    # Stack entries: (is_ignored_destination, unicode_skip_count).
    stack: List[List[Any]] = [[False, 1]]
    ignore = False
    ucskip = 1
    skip = 0
    for match in _RTF_TOKEN.finditer(text):
        word, arg, hexb, ctrl, brace, char = (
            match.group(1),
            match.group(2),
            match.group(3),
            match.group(4),
            match.group(5),
            match.group(6),
        )
        if brace == "{":
            stack.append([ignore, ucskip])
        elif brace == "}":
            if len(stack) > 1:
                ignore, ucskip = stack.pop()
        elif ctrl == "*":
            ignore = True
        elif word is not None:
            if word == "u":
                if not ignore and skip <= 0:
                    code = int(arg) if arg else 0
                    if code < 0:
                        code += 65536
                    out.append(chr(code))
                skip = ucskip
            elif word == "uc":
                ucskip = int(arg) if arg else 1
            elif word in _RTF_DESTINATIONS:
                ignore = True
            elif word in _RTF_SPECIAL:
                if not ignore:
                    out.append(_RTF_SPECIAL[word])
        elif hexb is not None:
            if skip > 0:
                skip -= 1
            elif not ignore:
                out.append(bytes([int(hexb, 16)]).decode("latin-1", errors="replace"))
        elif char is not None:
            if skip > 0:
                skip -= 1
            elif not ignore:
                out.append(char)
    result = "".join(out)
    result = re.sub(r"[ \t]+\n", "\n", result)
    result = re.sub(r"\n{3,}", "\n\n", result)
    return result.strip()


# ============================================================================
# Concordance + document-metrics helper layer (all standard-library, all real)
#
# These module-level primitives back the two databases DocumentParser builds:
#   * the token/character concordance that feeds Database 1 (the hash-table
#     registry), and
#   * the Part-A static-layer metric catalogue that feeds Database 2.
# Everything here is deterministic and dependency-free; the optional/library
# gated metrics (deep font parse, image quality, OCR confidence) live in the
# class as lazy extractors and honestly record "unavailable" when absent.
# ============================================================================

# A word token: a run of Unicode word characters, allowing internal
# apostrophes/hyphens so "don't" and "state-of-the-art" stay whole.
_WORD_RE = re.compile(r"[^\W\d_]+(?:['’\-][^\W\d_]+)*|\d[\d,.]*\d|\d", re.UNICODE)
# Sentence terminator run used for sentence counting (A5/A12).
_SENTENCE_SPLIT_RE = re.compile(r"[.!?…]+[\"'”’)\]]*(?:\s|$)")
# Paragraph = one or more blank lines.
_PARAGRAPH_SPLIT_RE = re.compile(r"\n[ \t]*\n")

# A compact but genuine English stop-word list (A12 stop-word ratio). Not meant
# to be exhaustive; it is the standard "short list" used by classic IR toolkits.
_STOPWORDS = frozenset("""
    a about above after again against all am an and any are aren't as at be
    because been before being below between both but by can't cannot could
    couldn't did didn't do does doesn't doing don't down during each few for
    from further had hadn't has hasn't have haven't having he he'd he'll he's
    her here here's hers herself him himself his how how's i i'd i'll i'm i've
    if in into is isn't it it's its itself let's me more most mustn't my myself
    no nor not of off on once only or other ought our ours ourselves out over
    own same shan't she she'd she'll she's should shouldn't so some such than
    that that's the their theirs them themselves then there there's these they
    they'd they'll they're they've this those through to too under until up
    very was wasn't we we'd we'll we're we've were weren't what what's when
    when's where where's which while who who's whom why why's with won't would
    wouldn't you you'd you'll you're you've your yours yourself yourselves
    """.split())

# --- A11 pattern / rule-based entity extraction -----------------------------
# Each pattern is compiled once; validators (Luhn / IBAN mod-97 / ISBN) run on
# the raw match so a hit is only recorded as "valid" when the checksum agrees.
_ENTITY_PATTERNS: Dict[str, "re.Pattern[str]"] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    "url": re.compile(r"\bhttps?://[^\s<>\"')]+", re.IGNORECASE),
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    ),
    "ipv6": re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b"),
    "phone": re.compile(
        r"(?<!\w)(?:\+?\d{1,3}[ .\-]?)?(?:\(\d{1,4}\)[ .\-]?)?"
        r"\d{2,4}[ .\-]\d{2,4}(?:[ .\-]\d{2,4}){0,2}(?!\w)"
    ),
    "date_iso": re.compile(r"\b\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b"),
    "date_us": re.compile(
        r"\b(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12]\d|3[01])[/\-]\d{2,4}\b"
    ),
    "date_written": re.compile(
        r"\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
        r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|"
        r"Dec(?:ember)?)\.?\s+\d{1,2},?\s+\d{4}\b",
        re.IGNORECASE,
    ),
    "money": re.compile(
        r"(?:[$€£¥]|USD|EUR|GBP|JPY|INR)\s?\d[\d,]*(?:\.\d{1,2})?"
        r"|\b\d[\d,]*(?:\.\d{1,2})?\s?(?:USD|EUR|GBP|JPY|INR)\b"
    ),
    "percent": re.compile(r"\b\d+(?:\.\d+)?\s?%"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    "credit_card": re.compile(r"\b(?:\d[ \-]?){13,19}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "isbn": re.compile(r"\b(?:ISBN(?:-1[03])?:?\s?)?(?=[\dX \-]{10,17})[\dX \-]+\b"),
    "doi": re.compile(r"\b10\.\d{4,9}/[^\s\"'<>]+\b"),
    "swift_bic": re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"),
}
# Entity categories that only count as "valid" when a checksum agrees.
_CHECKSUMMED = frozenset({"credit_card", "iban", "isbn"})


def _luhn_ok(digits: str) -> bool:
    """Luhn (mod-10) check for credit-card candidates (A11)."""
    ds = [int(c) for c in digits if c.isdigit()]
    if len(ds) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(ds)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _iban_ok(value: str) -> bool:
    """IBAN mod-97 == 1 check (A11)."""
    s = re.sub(r"\s", "", value).upper()
    if len(s) < 15:
        return False
    rearranged = s[4:] + s[:4]
    digits = "".join(str(int(ch, 36)) if ch.isalpha() else ch for ch in rearranged)
    try:
        return int(digits) % 97 == 1
    except ValueError:
        return False


def _isbn_ok(value: str) -> bool:
    """ISBN-10 / ISBN-13 checksum (A11)."""
    s = re.sub(r"[^0-9X]", "", value.upper())
    if len(s) == 10:
        total = sum((10 - i) * (10 if c == "X" else int(c)) for i, c in enumerate(s))
        return total % 11 == 0
    if len(s) == 13:
        total = sum((1 if i % 2 == 0 else 3) * int(c) for i, c in enumerate(s))
        return total % 10 == 0
    return False


def _entity_valid(category: str, value: str) -> bool:
    if category == "credit_card":
        return _luhn_ok(value)
    if category == "iban":
        return _iban_ok(value)
    if category == "isbn":
        return _isbn_ok(value)
    return True


# --- Database-1 grep sweep ---------------------------------------------------
# A line-oriented regex battery run over *every* indexed file (code, config,
# prose, data) to pull out the structural / forensic details a thorough ``grep``
# sweep would surface. Categories: ``secret`` (cloud/service credentials, keys,
# tokens, private-key and auth-header lines), ``network`` (IPv4/IPv6/MAC, URLs,
# DB/broker URIs, CIDR blocks, socket bindings), ``contact`` (email, phone),
# ``pii`` (SSN), ``finance`` (card / money / IBAN), ``identifier`` (UUID, the
# SHA-512/256/1 & MD5 hash families, Mongo ObjectId, hex colour, DOI, ISBN),
# ``code`` (imports & module/package/namespace/using declarations, Python/Go/
# Rust/JS function & class defs, decorators, env-var refs, dotenv assignments,
# shebangs, SQL statements, logging & debug-print calls), ``annotation`` (TODO
# markers, linter suppressions, copyright, SPDX), ``path`` (Windows / UNC /
# POSIX absolute paths, file:// URIs), ``vcs`` (conflict markers, semver, git
# remote URLs, issue-tracker keys), ``datetime`` (ISO date-time, bare date,
# wall-clock time), ``web`` (HTML/XML tags, XML prolog, Markdown headings &
# links), ``numeric`` (hex / scientific / percentage literals) and ``crypto``
# (data: URIs, long base64 blobs). Each entry is
# ``(pattern_name, category, is_sensitive, description, regex_source)``.
#
# The battery is deliberately line-oriented (each pattern is matched against one
# physical line at a time) so a match carries a real 1-based ``line`` and 0-based
# ``start_col``/``end_col`` -- exactly what ``grep -n -b`` reports -- and so the
# ``^`` anchors below mean "line start" without needing re.MULTILINE. Patterns
# whose length is fixed and bounded by ``\b`` (the hash families) are mutually
# exclusive, so a 64-hex SHA-256 is not also double-counted as a 40-hex SHA-1.
_GREP_SPECS: Tuple[Tuple[str, str, bool, str, str], ...] = (
    # -- secrets / credentials (is_sensitive=True) --------------------------
    (
        "aws_access_key_id",
        "secret",
        True,
        "AWS access key id (AKIA/ASIA/... + 16 base32 chars)",
        r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16}\b",
    ),
    (
        "google_api_key",
        "secret",
        True,
        "Google API key (AIza + 35 url-safe chars)",
        r"\bAIza[0-9A-Za-z\-_]{35}\b",
    ),
    (
        "github_token",
        "secret",
        True,
        "GitHub personal-access / app token (ghp_/gho_/ghu_/ghs_/ghr_/github_pat_)",
        r"\b(?:gh[pousr]_[0-9A-Za-z]{36,}|github_pat_[0-9A-Za-z_]{22,255})\b",
    ),
    (
        "gitlab_token",
        "secret",
        True,
        "GitLab personal/pipeline token (glpat-/GR13...)",
        r"\b(?:glpat-[0-9A-Za-z_\-]{20,}|GR1348941[0-9A-Za-z_\-]{20,})\b",
    ),
    (
        "slack_token",
        "secret",
        True,
        "Slack token (xox[baprs]-...)",
        r"\bxox[baprs]-[0-9A-Za-z\-]{10,72}\b",
    ),
    (
        "slack_webhook",
        "secret",
        True,
        "Slack incoming-webhook URL",
        r"\bhttps://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/"
        r"[A-Za-z0-9]{16,}",
    ),
    (
        "discord_webhook",
        "secret",
        True,
        "Discord webhook URL",
        r"\bhttps://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/"
        r"\d+/[\w\-]+",
    ),
    (
        "stripe_key",
        "secret",
        True,
        "Stripe secret/publishable/restricted key",
        r"\b[sprk]k_(?:live|test)_[0-9A-Za-z]{10,99}\b",
    ),
    (
        "openai_key",
        "secret",
        True,
        "OpenAI-style API key (sk-... / sk-proj-...)",
        r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
    ),
    (
        "sendgrid_key",
        "secret",
        True,
        "SendGrid API key (SG.<22>.<43>)",
        r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
    ),
    (
        "twilio_account_sid",
        "secret",
        True,
        "Twilio Account SID (AC + 32 hex)",
        r"\bAC[0-9a-fA-F]{32}\b",
    ),
    (
        "npm_token",
        "secret",
        True,
        "npm access token (npm_ + 36 chars)",
        r"\bnpm_[A-Za-z0-9]{36}\b",
    ),
    (
        "pypi_token",
        "secret",
        True,
        "PyPI upload token (pypi-AgEIcHlwaS...)",
        r"\bpypi-AgEIcHlwaS[A-Za-z0-9\-_]{50,}\b",
    ),
    (
        "aws_secret_access_key",
        "secret",
        True,
        "AWS secret access key assigned a 40-char value",
        r"(?i)aws_secret_access_key\b['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}",
    ),
    (
        "private_key_block",
        "secret",
        True,
        "PEM private-key header line",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
    ),
    (
        "jwt",
        "secret",
        True,
        "JSON Web Token (three base64url segments)",
        r"\beyJ[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+\b",
    ),
    (
        "bearer_token",
        "secret",
        True,
        "HTTP Bearer authorization token",
        r"(?i)\bbearer\s+[0-9A-Za-z._\-]{10,}",
    ),
    (
        "url_basic_auth",
        "secret",
        True,
        "credentials embedded in a URL (scheme://user:pass@host)",
        r"\b[a-z][a-z0-9+.\-]*://[^\s:@/]+:[^\s:@/]+@",
    ),
    (
        "secret_assignment",
        "secret",
        True,
        "password / secret / api-key assigned a quoted literal",
        r"(?i)\b(?:password|passwd|pwd|secret|api[_\-]?key|access[_\-]?token|"
        r"auth[_\-]?token|client[_\-]?secret)\b\s*[:=]\s*['\"][^'\"]{3,}['\"]",
    ),
    (
        "ssh_public_key",
        "secret",
        True,
        "OpenSSH public key line",
        r"\bssh-(?:rsa|dss|ed25519|ecdsa[\w\-]*)\s+AAAA[0-9A-Za-z+/]+={0,2}",
    ),
    (
        "authorization_header",
        "secret",
        True,
        "HTTP Authorization header with a credential",
        r"(?i)\bauthorization\s*[:=]\s*(?:bearer|basic|token|digest)\s+[^\s\"']+",
    ),
    # -- network endpoints --------------------------------------------------
    (
        "ipv4",
        "network",
        False,
        "IPv4 dotted-quad address",
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    ),
    (
        "ipv6",
        "network",
        False,
        "IPv6 colon-hex address",
        r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b",
    ),
    (
        "mac_address",
        "network",
        False,
        "MAC / EUI-48 hardware address",
        r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b",
    ),
    (
        "url",
        "network",
        False,
        "http/https URL",
        r"\bhttps?://[^\s<>\"')]+",
    ),
    (
        "db_connection_uri",
        "network",
        False,
        "database / broker connection URI (mongodb/postgres/mysql/redis/amqp/ftp)",
        r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|amqps?|ftp)"
        r"://[^\s\"'<>]+",
    ),
    (
        "cidr_block",
        "network",
        False,
        "IPv4 CIDR network block",
        r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b",
    ),
    (
        "socket_addr",
        "network",
        False,
        "loopback / wildcard host:port binding",
        r"\b(?:0\.0\.0\.0|127\.0\.0\.1|localhost):\d{2,5}\b",
    ),
    # -- contacts -----------------------------------------------------------
    (
        "email",
        "contact",
        False,
        "email address",
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    ),
    (
        "phone",
        "contact",
        False,
        "telephone number (international / grouped digits)",
        r"(?<!\w)(?:\+?\d{1,3}[ .\-]?)?(?:\(\d{1,4}\)[ .\-]?)?"
        r"\d{2,4}[ .\-]\d{2,4}(?:[ .\-]\d{2,4}){0,2}(?!\w)",
    ),
    # -- personally-identifiable / financial --------------------------------
    (
        "us_ssn",
        "pii",
        True,
        "US Social Security Number (NNN-NN-NNNN)",
        r"\b\d{3}-\d{2}-\d{4}\b",
    ),
    (
        "credit_card",
        "finance",
        True,
        "credit-card-shaped digit run (13-19 digits)",
        r"\b(?:\d[ \-]?){13,19}\b",
    ),
    (
        "money",
        "finance",
        False,
        "monetary amount with currency symbol / code",
        r"(?:[$€£¥]|USD|EUR|GBP|JPY|INR)\s?\d[\d,]*(?:\.\d{1,2})?"
        r"|\b\d[\d,]*(?:\.\d{1,2})?\s?(?:USD|EUR|GBP|JPY|INR)\b",
    ),
    (
        "iban",
        "finance",
        False,
        "IBAN bank account number",
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
    ),
    # -- identifiers / hashes ----------------------------------------------
    (
        "uuid",
        "identifier",
        False,
        "RFC-4122 UUID",
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
        r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
    ),
    (
        "sha512_hex",
        "identifier",
        False,
        "128-char hex digest (SHA-512)",
        r"\b[0-9a-fA-F]{128}\b",
    ),
    (
        "sha256_hex",
        "identifier",
        False,
        "64-char hex digest (SHA-256)",
        r"\b[0-9a-fA-F]{64}\b",
    ),
    (
        "sha1_hex",
        "identifier",
        False,
        "40-char hex digest (SHA-1 / git object id)",
        r"\b[0-9a-fA-F]{40}\b",
    ),
    (
        "md5_hex",
        "identifier",
        False,
        "32-char hex digest (MD5)",
        r"\b[0-9a-fA-F]{32}\b",
    ),
    (
        "mongo_objectid",
        "identifier",
        False,
        "24-char hex MongoDB ObjectId",
        r"\b[0-9a-fA-F]{24}\b",
    ),
    (
        "hex_color",
        "identifier",
        False,
        "CSS hex color literal",
        r"#(?:[0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b",
    ),
    (
        "doi",
        "identifier",
        False,
        "Digital Object Identifier",
        r"\b10\.\d{4,9}/[^\s\"'<>]+",
    ),
    (
        "isbn",
        "identifier",
        False,
        "ISBN-10 / ISBN-13 (prefixed)",
        r"\bISBN(?:-1[03])?:?\s?[\dX\- ]{10,17}\b",
    ),
    # -- code structure -----------------------------------------------------
    (
        "python_import",
        "code",
        False,
        "Python import / from-import statement",
        r"^\s*(?:from\s+[\w.]+\s+import\b|import\s+[\w.]+)",
    ),
    (
        "java_import",
        "code",
        False,
        "Java/Kotlin/Scala import statement",
        r"^\s*import\s+(?:static\s+)?[\w.]+(?:\.\*)?\s*;",
    ),
    (
        "c_include",
        "code",
        False,
        "C/C++ #include directive",
        r"^\s*#\s*include\s*[<\"][^>\"]+[>\"]",
    ),
    (
        "js_module",
        "code",
        False,
        "JS/TS require() or ES import-from",
        r"require\(\s*['\"][^'\"]+['\"]\s*\)"
        r"|\bimport\b[^;\n]*\bfrom\s+['\"][^'\"]+['\"]",
    ),
    (
        "package_decl",
        "code",
        False,
        "package declaration (Java/Kotlin/Go)",
        r"^\s*package\s+[\w.]+",
    ),
    (
        "namespace_decl",
        "code",
        False,
        "namespace declaration (C++/C#/PHP)",
        r"^\s*namespace\s+[\w:\\]+",
    ),
    (
        "using_decl",
        "code",
        False,
        "using / using-static directive (C#/C++)",
        r"^\s*using\s+(?:static\s+)?[\w:.<>]+\s*;",
    ),
    (
        "python_def",
        "code",
        False,
        "Python function definition",
        r"^\s*(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(",
    ),
    (
        "go_func",
        "code",
        False,
        "Go function / method definition",
        r"^\s*func\s+(?:\([^)]*\)\s*)?[A-Za-z_]\w*\s*\(",
    ),
    (
        "rust_fn",
        "code",
        False,
        "Rust function definition",
        r"^\s*(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+[A-Za-z_]\w*",
    ),
    (
        "class_def",
        "code",
        False,
        "class definition (Python/Java/C#/C++/TS)",
        r"^\s*(?:public\s+|private\s+|protected\s+|abstract\s+|final\s+|"
        r"export\s+|export\s+default\s+|sealed\s+|static\s+)*class\s+[A-Za-z_]\w*",
    ),
    (
        "js_function",
        "code",
        False,
        "JavaScript named function declaration",
        r"\bfunction\s*\*?\s*[A-Za-z_$][\w$]*\s*\(",
    ),
    (
        "decorator",
        "code",
        False,
        "decorator / annotation line (@name)",
        r"^\s*@[A-Za-z_][\w.]*",
    ),
    (
        "env_var_ref",
        "code",
        False,
        "environment-variable reference (${VAR} / $VAR / %VAR%)",
        r"\$\{[A-Za-z_]\w*\}|\$[A-Za-z_]\w*|%[A-Za-z_]\w*%",
    ),
    (
        "dotenv_assignment",
        "code",
        False,
        "shell/.env style UPPER_SNAKE assignment at line start",
        r"^\s*(?:export\s+)?[A-Z][A-Z0-9_]{2,}=",
    ),
    (
        "shell_shebang",
        "code",
        False,
        "interpreter shebang line",
        r"^#!\s*\S+",
    ),
    (
        "sql_statement",
        "code",
        False,
        "SQL DML/DDL statement keyword",
        r"(?i)\b(?:SELECT\s+(?:\*|[\w,]+)|INSERT\s+INTO|UPDATE\s+\w+\s+SET|"
        r"DELETE\s+FROM|CREATE\s+(?:TABLE|VIEW|INDEX|DATABASE|SCHEMA)|"
        r"DROP\s+(?:TABLE|VIEW|INDEX|DATABASE)|ALTER\s+TABLE|TRUNCATE\s+TABLE)",
    ),
    (
        "logging_call",
        "code",
        False,
        "logger call (log.info / logger.error / ...)",
        r"(?i)\blog(?:ger|ging)?\.(?:trace|debug|info|warn(?:ing)?|error|"
        r"critical|fatal|exception)\b",
    ),
    (
        "print_debug",
        "code",
        False,
        "console/stdout debug print call",
        r"\b(?:console\.(?:log|debug|error|warn)|System\.out\.println|"
        r"fmt\.Print(?:ln|f)?|printf|println)\s*\(",
    ),
    # -- source annotations -------------------------------------------------
    (
        "todo_marker",
        "annotation",
        False,
        "TODO/FIXME/HACK/XXX/BUG/NOTE-style source marker",
        r"(?i)\b(?:TODO|FIXME|HACK|XXX|BUG|NOTE|OPTIMIZE|DEPRECATED|REVIEW)\b"
        r"[:\- (]",
    ),
    (
        "linter_suppression",
        "annotation",
        False,
        "linter / type-checker suppression directive",
        r"(?i)(?:eslint-disable(?:-next-line|-line)?|noqa(?::\s*[\w,]+)?|"
        r"type:\s*ignore|pylint:\s*disable|flake8:\s*noqa|"
        r"@ts-(?:ignore|nocheck|expect-error)|prettier-ignore|"
        r"coverage:\s*ignore|nosec)",
    ),
    (
        "copyright",
        "annotation",
        False,
        "copyright notice with year",
        r"(?i)copyright\s+(?:\(c\)\s*|©\s*)?\d{4}(?:\s*[-,]\s*\d{4})?",
    ),
    (
        "spdx_license",
        "annotation",
        False,
        "SPDX license identifier",
        r"SPDX-License-Identifier:\s*[\w.\-+]+",
    ),
    # -- file-system paths --------------------------------------------------
    (
        "windows_path",
        "path",
        False,
        "absolute Windows path (drive-letter)",
        r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\?)+",
    ),
    (
        "unc_path",
        "path",
        False,
        "Windows UNC network path (\\\\host\\share\\...)",
        r"\\\\[A-Za-z0-9._\-]+\\[^\s\"'<>|]+",
    ),
    (
        "unix_abs_path",
        "path",
        False,
        "absolute POSIX path (>=2 components)",
        r"(?<![\w./])/(?:[\w.\-]+/){2,}[\w.\-]+",
    ),
    (
        "file_uri",
        "path",
        False,
        "file:// URI",
        r"\bfile://[^\s'\"<>]+",
    ),
    # -- version control / releases ----------------------------------------
    (
        "git_conflict_marker",
        "vcs",
        False,
        "git merge-conflict marker line",
        r"^(?:<{7}|={7}|>{7})(?:\s|$)",
    ),
    (
        "semver",
        "vcs",
        False,
        "semantic version (major.minor.patch[-pre][+build])",
        r"\bv?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?\b",
    ),
    (
        "git_remote_url",
        "vcs",
        False,
        "git remote URL (ssh git@host:path.git or https ...*.git)",
        r"\b(?:git@[\w.\-]+:[\w./\-]+\.git|https?://[\w.\-]+/[\w./\-]+\.git)\b",
    ),
    (
        "issue_tracker_id",
        "vcs",
        False,
        "issue-tracker key (JIRA-style PROJ-123)",
        r"\b[A-Z][A-Z0-9]{1,9}-\d{1,6}\b",
    ),
    # -- timestamps ---------------------------------------------------------
    (
        "iso_datetime",
        "datetime",
        False,
        "ISO-8601 date-time",
        r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?"
        r"(?:Z|[+\-]\d{2}:?\d{2})?\b",
    ),
    (
        "date_ymd",
        "datetime",
        False,
        "bare ISO calendar date (not part of a date-time)",
        r"\b\d{4}-\d{2}-\d{2}\b(?![T ]\d{2}:)",
    ),
    (
        "time_hms",
        "datetime",
        False,
        "wall-clock time (HH:MM:SS)",
        r"\b[0-2]\d:[0-5]\d:[0-5]\d\b",
    ),
    # -- markup / documentation --------------------------------------------
    (
        "html_tag",
        "web",
        False,
        "HTML/XML element tag",
        r"</?[a-zA-Z][a-zA-Z0-9\-]*(?:\s+[^<>]*?)?/?>",
    ),
    (
        "xml_declaration",
        "web",
        False,
        "XML prolog declaration",
        r"<\?xml\b[^>]*\?>",
    ),
    (
        "markdown_heading",
        "web",
        False,
        "Markdown ATX heading",
        r"^#{1,6}\s+\S",
    ),
    (
        "markdown_link",
        "web",
        False,
        "Markdown inline link [text](target)",
        r"\[[^\]]+\]\([^)\s]+\)",
    ),
    # -- numeric literals ---------------------------------------------------
    (
        "hex_literal",
        "numeric",
        False,
        "0x-prefixed hexadecimal literal",
        r"\b0[xX][0-9a-fA-F]+\b",
    ),
    (
        "scientific_notation",
        "numeric",
        False,
        "scientific / exponential number",
        r"\b\d+(?:\.\d+)?[eE][+\-]?\d+\b",
    ),
    (
        "percentage",
        "numeric",
        False,
        "percentage value",
        r"\b\d+(?:\.\d+)?\s?%",
    ),
    # -- long encoded blobs -------------------------------------------------
    (
        "data_uri",
        "crypto",
        False,
        "RFC-2397 base64 data: URI",
        r"\bdata:[\w.+\-]+/[\w.+\-]+;base64,[A-Za-z0-9+/=]+",
    ),
    (
        "base64_blob",
        "crypto",
        False,
        "long base64 run (>=40 chars, non-hex; e.g. embedded key/asset)",
        r"\b(?=[A-Za-z0-9+/]{40,}={0,2}\b)[A-Za-z0-9+/]*[G-Zg-z+/]"
        r"[A-Za-z0-9+/]*={0,2}\b",
    ),
)

# Compiled once, in catalogue order (pattern_id == 1-based position).
_GREP_PATTERNS: Tuple[Tuple[str, str, bool, "re.Pattern[str]"], ...] = tuple(
    (name, category, sensitive, re.compile(rx))
    for name, category, sensitive, _desc, rx in _GREP_SPECS
)


# --- Database-1 language-aware construct sweep -------------------------------
# Where the generic grep battery above is language-agnostic, this second layer
# is *language-specific*: a file's extension resolves to one programming
# language and only that language's construct battery is run over it, so the
# hits carry the precise grammar of the language (Python ``def`` vs Go ``func``
# vs Rust ``fn`` vs Ruby ``def`` -- each recognised on its own terms rather than
# by a lowest-common-denominator regex). Like the grep sweep it is line-oriented
# (one physical line at a time, so every hit has a real 1-based ``line`` and
# 0-based columns and ``^`` anchors mean line start) and stdlib-only, so it runs
# everywhere including CI. It feeds the Database-1 ``language_construct_*`` tables.
#
# ``_LANGUAGE_EXTS`` maps each language to the last-component suffixes it owns.
# The mapping is 1:1 (every suffix belongs to exactly one language); genuinely
# ambiguous tails are assigned to their most common language on purpose (``.m``
# -> Objective-C, ``.r`` -> R, ``.sc`` -> Scala, ``.h`` -> C, ``.pl``/``.pm`` ->
# Perl), which is a deliberate, documented heuristic rather than a guess.
_LANGUAGE_EXTS: Dict[str, Tuple[str, ...]] = {
    "python": (".py", ".pyw", ".pyi", ".pyx", ".pxd", ".pxi"),
    "javascript": (".js", ".jsx", ".cjs", ".mjs", ".jsbundle"),
    "typescript": (".ts", ".tsx", ".mts", ".cts"),
    "java": (".java",),
    "kotlin": (".kt", ".kts"),
    "c": (".c", ".h"),
    "cpp": (
        ".cpp",
        ".cc",
        ".cxx",
        ".c++",
        ".hpp",
        ".hh",
        ".hxx",
        ".ipp",
        ".cppm",
        ".ixx",
        ".inl",
        ".tpp",
    ),
    "csharp": (".cs", ".csx"),
    "go": (".go",),
    "rust": (".rs",),
    "ruby": (".rb", ".rake", ".gemspec"),
    "php": (".php",),
    "swift": (".swift",),
    "scala": (".scala", ".sc"),
    "shell": (".sh", ".bash", ".zsh", ".ksh", ".bashrc", ".zshrc", ".profile"),
    "sql": (".sql",),
    "r": (".r",),
    "perl": (".pl", ".pm", ".perl", ".t"),
    "lua": (".lua",),
    "haskell": (".hs", ".lhs"),
    "elixir": (".ex", ".exs"),
    "dart": (".dart",),
    "objc": (".m", ".mm"),
    "powershell": (".ps1", ".psm1", ".psd1"),
}

# Per-language construct battery. Each language maps to a tuple of
# ``(construct_name, kind, description, regex_source)``; ``kind`` groups the
# construct (``import`` / ``definition`` / ``declaration`` / ``control`` /
# ``annotation`` / ``query`` / ``clause`` / ``other``). ``construct_name`` is
# unique within its language; the global ``construct_id`` is the 1-based
# position when the battery is walked language-by-language in this order.
_LANG_SPECS: Tuple[Tuple[str, Tuple[Tuple[str, str, str, str], ...]], ...] = (
    (
        "python",
        (
            ("import", "import", "import statement", r"^\s*import\s+[A-Za-z_]"),
            (
                "from_import",
                "import",
                "from-import statement",
                r"^\s*from\s+[\w.]+\s+import\b",
            ),
            (
                "function",
                "definition",
                "function/method definition",
                r"^\s*(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(",
            ),
            ("class", "definition", "class definition", r"^\s*class\s+[A-Za-z_]\w*"),
            ("decorator", "annotation", "decorator", r"^\s*@[A-Za-z_][\w.]*"),
            (
                "constant",
                "declaration",
                "module-level UPPER_CASE constant",
                r"^[A-Z_][A-Z0-9_]+\s*(?::[^=\n]+)?=",
            ),
            (
                "global_decl",
                "declaration",
                "global/nonlocal declaration",
                r"^\s*(?:global|nonlocal)\s+[A-Za-z_]",
            ),
            ("raise", "control", "raise statement", r"^\s*raise\s+[A-Za-z_]"),
            (
                "with_context",
                "control",
                "with-context manager",
                r"^\s*(?:async\s+)?with\s+.+\bas\s+[A-Za-z_]",
            ),
            ("lambda", "definition", "lambda expression", r"\blambda\b[^:\n]*:"),
        ),
    ),
    (
        "javascript",
        (
            (
                "import",
                "import",
                "ES-module import ... from",
                r"^\s*import\b[^;\n]*\bfrom\s+['\"]",
            ),
            (
                "require",
                "import",
                "CommonJS require()",
                r"\brequire\(\s*['\"][^'\"]+['\"]\s*\)",
            ),
            ("export", "export", "export statement", r"^\s*export\b(?:\s+default\b)?"),
            (
                "function",
                "definition",
                "function declaration",
                r"\bfunction\s*\*?\s*[A-Za-z_$][\w$]*\s*\(",
            ),
            (
                "arrow_function",
                "definition",
                "named arrow function",
                r"\b(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*(?:async\s+)?"
                r"\([^)]*\)\s*=>",
            ),
            (
                "class",
                "definition",
                "class declaration",
                r"\bclass\s+[A-Za-z_$][\w$]*(?:\s+extends\s+[\w$.]+)?",
            ),
            (
                "method",
                "definition",
                "class method",
                r"^\s*(?:static\s+|async\s+|get\s+|set\s+)*[A-Za-z_$][\w$]*"
                r"\s*\([^)]*\)\s*\{",
            ),
            (
                "variable",
                "declaration",
                "const/let/var binding",
                r"\b(?:const|let|var)\s+[A-Za-z_$][\w$]*",
            ),
        ),
    ),
    (
        "typescript",
        (
            (
                "import",
                "import",
                "ES-module import ... from",
                r"^\s*import\b[^;\n]*\bfrom\s+['\"]",
            ),
            (
                "require",
                "import",
                "CommonJS require()",
                r"\brequire\(\s*['\"][^'\"]+['\"]\s*\)",
            ),
            ("export", "export", "export statement", r"^\s*export\b(?:\s+default\b)?"),
            (
                "interface",
                "definition",
                "interface declaration",
                r"\binterface\s+[A-Za-z_$][\w$]*",
            ),
            (
                "type_alias",
                "declaration",
                "type alias",
                r"\btype\s+[A-Za-z_$][\w$]*\s*(?:<[^>]*>)?\s*=",
            ),
            (
                "enum",
                "definition",
                "enum declaration",
                r"\b(?:const\s+)?enum\s+[A-Za-z_$][\w$]*",
            ),
            ("class", "definition", "class declaration", r"\bclass\s+[A-Za-z_$][\w$]*"),
            (
                "function",
                "definition",
                "function declaration",
                r"\bfunction\s*\*?\s*[A-Za-z_$][\w$]*\s*\(",
            ),
            ("decorator", "annotation", "decorator", r"^\s*@[A-Za-z_][\w.]*"),
            (
                "namespace",
                "definition",
                "namespace/module block",
                r"\b(?:namespace|module)\s+[A-Za-z_$][\w$.]*",
            ),
        ),
    ),
    (
        "java",
        (
            (
                "package",
                "declaration",
                "package declaration",
                r"^\s*package\s+[\w.]+\s*;",
            ),
            (
                "import",
                "import",
                "import declaration",
                r"^\s*import\s+(?:static\s+)?[\w.]+(?:\.\*)?\s*;",
            ),
            (
                "class",
                "definition",
                "class declaration",
                r"^\s*(?:public\s+|final\s+|abstract\s+|static\s+)*class\s+"
                r"[A-Za-z_]\w*",
            ),
            (
                "interface",
                "definition",
                "interface declaration",
                r"^\s*(?:public\s+|abstract\s+)*interface\s+[A-Za-z_]\w*",
            ),
            (
                "enum",
                "definition",
                "enum declaration",
                r"^\s*(?:public\s+|final\s+)*enum\s+[A-Za-z_]\w*",
            ),
            ("annotation", "annotation", "annotation use", r"^\s*@[A-Za-z_][\w.]*"),
            (
                "method",
                "definition",
                "method declaration",
                r"^\s*(?:public|private|protected)\s+(?:static\s+|final\s+|"
                r"synchronized\s+|abstract\s+|native\s+)*[\w<>\[\].]+\s+"
                r"[A-Za-z_]\w*\s*\(",
            ),
            (
                "field",
                "declaration",
                "field declaration",
                r"^\s*(?:public|private|protected)\s+(?:static\s+|final\s+|"
                r"volatile\s+|transient\s+)*[\w<>\[\].]+\s+[A-Za-z_]\w*\s*[=;]",
            ),
        ),
    ),
    (
        "kotlin",
        (
            ("package", "declaration", "package header", r"^\s*package\s+[\w.]+"),
            ("import", "import", "import directive", r"^\s*import\s+[\w.]+(?:\.\*)?"),
            (
                "function",
                "definition",
                "function declaration",
                r"^\s*(?:(?:public|private|internal|protected|open|override|"
                r"suspend|inline|operator|infix|tailrec|external|final|abstract)"
                r"\s+)*fun\s+(?:<[^>]*>\s+)?[A-Za-z_]\w*",
            ),
            (
                "class",
                "definition",
                "class/interface/object",
                r"^\s*(?:(?:public|private|internal|sealed|open|abstract|data|"
                r"enum|inner|final|annotation)\s+)*(?:class|interface|object)\s+"
                r"[A-Za-z_]\w*",
            ),
            (
                "property",
                "declaration",
                "val/var property",
                r"^\s*(?:(?:public|private|internal|const|lateinit|override|open)"
                r"\s+)*(?:val|var)\s+[A-Za-z_]\w*",
            ),
            ("annotation", "annotation", "annotation use", r"^\s*@[A-Za-z_][\w.]*"),
        ),
    ),
    (
        "c",
        (
            (
                "include",
                "import",
                "#include directive",
                r"^\s*#\s*include\s*[<\"][^>\"]+[>\"]",
            ),
            (
                "define",
                "declaration",
                "#define macro",
                r"^\s*#\s*define\s+[A-Za-z_]\w*",
            ),
            (
                "preproc_cond",
                "control",
                "conditional-compilation directive",
                r"^\s*#\s*(?:if|ifdef|ifndef|elif|else|endif|pragma)\b",
            ),
            (
                "struct",
                "definition",
                "struct/union/enum tag",
                r"^\s*(?:typedef\s+)?(?:struct|union|enum)\s+[A-Za-z_]\w*",
            ),
            ("typedef", "declaration", "typedef", r"^\s*typedef\s+[A-Za-z_]"),
            (
                "function",
                "definition",
                "function definition",
                r"^(?:[A-Za-z_][\w]*[\s\*]+)+\*?[A-Za-z_]\w*\s*"
                r"\([^;{}]*\)\s*\{?\s*$",
            ),
        ),
    ),
    (
        "cpp",
        (
            (
                "include",
                "import",
                "#include directive",
                r"^\s*#\s*include\s*[<\"][^>\"]+[>\"]",
            ),
            (
                "define",
                "declaration",
                "#define macro",
                r"^\s*#\s*define\s+[A-Za-z_]\w*",
            ),
            (
                "using",
                "import",
                "using declaration/directive",
                r"^\s*using\s+(?:namespace\s+)?[\w:<>]+\s*;?",
            ),
            (
                "namespace",
                "definition",
                "namespace definition",
                r"^\s*namespace\s+[A-Za-z_]?\w*\s*\{?",
            ),
            (
                "class",
                "definition",
                "class/struct definition",
                r"^\s*(?:template\s*<[^>]*>\s*)?(?:class|struct)\s+[A-Za-z_]\w*",
            ),
            ("template", "definition", "template declaration", r"^\s*template\s*<"),
            (
                "function",
                "definition",
                "function definition",
                r"^(?:[A-Za-z_][\w:<>,\*&]*[\s\*&]+)+[A-Za-z_]\w*\s*"
                r"\([^;{}]*\)\s*(?:const\b\s*)?(?:noexcept\b\s*)?"
                r"(?:override\b\s*)?\{?\s*$",
            ),
        ),
    ),
    (
        "csharp",
        (
            (
                "using",
                "import",
                "using directive",
                r"^\s*using\s+(?:static\s+)?[\w.=<>? ]+;",
            ),
            (
                "namespace",
                "definition",
                "namespace declaration",
                r"^\s*namespace\s+[\w.]+",
            ),
            (
                "class",
                "definition",
                "class/struct/record/interface",
                r"^\s*(?:(?:public|private|protected|internal|sealed|abstract|"
                r"static|partial)\s+)*(?:class|struct|record|interface)\s+"
                r"[A-Za-z_]\w*",
            ),
            (
                "enum",
                "definition",
                "enum declaration",
                r"^\s*(?:(?:public|private|protected|internal)\s+)*enum\s+"
                r"[A-Za-z_]\w*",
            ),
            (
                "method",
                "definition",
                "method declaration",
                r"^\s*(?:(?:public|private|protected|internal|static|virtual|"
                r"override|async|sealed|abstract|extern)\s+)+[\w<>\[\].,? ]+\s+"
                r"[A-Za-z_]\w*\s*\(",
            ),
            (
                "property",
                "declaration",
                "auto-property",
                r"^\s*(?:(?:public|private|protected|internal|static|virtual|"
                r"override)\s+)+[\w<>\[\].,? ]+\s+[A-Za-z_]\w*\s*\{\s*get",
            ),
            (
                "attribute",
                "annotation",
                "attribute",
                r"^\s*\[[A-Za-z_][\w.]*(?:\([^)]*\))?\]",
            ),
        ),
    ),
    (
        "go",
        (
            ("package", "declaration", "package clause", r"^\s*package\s+[A-Za-z_]\w*"),
            ("import", "import", "import spec/block", r"^\s*import\s+(?:\(|[\"\w])"),
            (
                "func",
                "definition",
                "function/method definition",
                r"^\s*func\s+(?:\([^)]*\)\s*)?[A-Za-z_]\w*\s*\(",
            ),
            (
                "type",
                "definition",
                "type definition",
                r"^\s*type\s+[A-Za-z_]\w*\s+(?:struct|interface|func|map|\[|"
                r"chan|\*|[A-Za-z_])",
            ),
            (
                "const",
                "declaration",
                "const declaration",
                r"^\s*const\s+(?:\(|[A-Za-z_])",
            ),
            ("var", "declaration", "var declaration", r"^\s*var\s+[A-Za-z_]\w*"),
            (
                "short_var",
                "declaration",
                "short variable declaration :=",
                r"^\s*[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*\s*:=",
            ),
        ),
    ),
    (
        "rust",
        (
            ("use", "import", "use declaration", r"^\s*(?:pub\s+)?use\s+[\w:{}*, ]+;"),
            (
                "mod",
                "definition",
                "module declaration",
                r"^\s*(?:pub\s+)?mod\s+[A-Za-z_]\w*",
            ),
            (
                "fn",
                "definition",
                "function definition",
                r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?"
                r"(?:extern\s+\"[^\"]*\"\s+)?fn\s+[A-Za-z_]\w*",
            ),
            (
                "struct_enum",
                "definition",
                "struct/enum/union",
                r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum|union)\s+"
                r"[A-Za-z_]\w*",
            ),
            (
                "trait",
                "definition",
                "trait definition",
                r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?trait\s+[A-Za-z_]\w*",
            ),
            (
                "impl",
                "definition",
                "impl block",
                r"^\s*impl(?:\s*<[^>]*>)?\s+[\w:<>, ]+",
            ),
            (
                "macro_def",
                "definition",
                "macro_rules! definition",
                r"^\s*macro_rules!\s+[A-Za-z_]\w*",
            ),
            (
                "const_static",
                "declaration",
                "const/static item",
                r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const|static)\s+(?:mut\s+)?"
                r"[A-Za-z_]\w*\s*:",
            ),
            ("attribute", "annotation", "attribute", r"^\s*#!?\[[^\]]+\]"),
            (
                "let_binding",
                "declaration",
                "let binding",
                r"^\s*let\s+(?:mut\s+)?[A-Za-z_]\w*",
            ),
        ),
    ),
    (
        "ruby",
        (
            (
                "require",
                "import",
                "require/require_relative",
                r"^\s*require(?:_relative)?\s+['\"]",
            ),
            ("class", "definition", "class definition", r"^\s*class\s+[A-Z]\w*"),
            ("module", "definition", "module definition", r"^\s*module\s+[A-Z]\w*"),
            (
                "method",
                "definition",
                "method definition",
                r"^\s*def\s+(?:self\.)?[A-Za-z_]\w*[!?=]?",
            ),
            (
                "attr",
                "declaration",
                "attr_accessor/reader/writer",
                r"^\s*attr_(?:accessor|reader|writer)\s+:",
            ),
            (
                "constant",
                "declaration",
                "constant assignment",
                r"^\s*[A-Z][A-Z0-9_]+\s*=",
            ),
            (
                "mixin",
                "import",
                "include/extend/prepend mixin",
                r"^\s*(?:include|extend|prepend)\s+[A-Z]",
            ),
        ),
    ),
    (
        "php",
        (
            (
                "namespace",
                "definition",
                "namespace declaration",
                r"^\s*namespace\s+[\w\\]+",
            ),
            ("use", "import", "use import", r"^\s*use\s+[\w\\]+(?:\s+as\s+\w+)?\s*;"),
            (
                "class",
                "definition",
                "class/interface/trait",
                r"^\s*(?:(?:abstract|final)\s+)*(?:class|interface|trait)\s+"
                r"[A-Za-z_]\w*",
            ),
            (
                "function",
                "definition",
                "function/method definition",
                r"^\s*(?:(?:public|private|protected|static|abstract|final)\s+)*"
                r"function\s+&?[A-Za-z_]\w*\s*\(",
            ),
            (
                "require_include",
                "import",
                "require/include",
                r"\b(?:require|include)(?:_once)?\s*[('\"]",
            ),
            ("variable", "declaration", "variable assignment", r"\$[A-Za-z_]\w*\s*="),
            (
                "const",
                "declaration",
                "const/define constant",
                r"^\s*(?:const\s+[A-Z]|define\s*\(\s*['\"])",
            ),
        ),
    ),
    (
        "swift",
        (
            ("import", "import", "import statement", r"^\s*import\s+[A-Za-z_]\w*"),
            (
                "func",
                "definition",
                "function definition",
                r"^\s*(?:(?:public|private|internal|fileprivate|open|static|"
                r"class|final|override|mutating)\s+)*func\s+[A-Za-z_]\w*",
            ),
            (
                "type",
                "definition",
                "class/struct/enum/protocol/actor",
                r"^\s*(?:(?:public|private|internal|fileprivate|open|final)\s+)*"
                r"(?:class|struct|enum|protocol|actor|extension)\s+[A-Za-z_]\w*",
            ),
            (
                "property",
                "declaration",
                "let/var property",
                r"^\s*(?:(?:public|private|internal|fileprivate|static|lazy|"
                r"override|final|weak|unowned)\s+)*(?:let|var)\s+[A-Za-z_]\w*",
            ),
            ("attribute", "annotation", "attribute", r"^\s*@[A-Za-z_]\w*"),
        ),
    ),
    (
        "scala",
        (
            ("import", "import", "import clause", r"^\s*import\s+[\w.{}, _]+"),
            ("package", "declaration", "package clause", r"^\s*package\s+[\w.]+"),
            (
                "def",
                "definition",
                "method definition",
                r"^\s*(?:(?:private|protected|final|override|implicit|sealed|"
                r"abstract)\s+)*def\s+[A-Za-z_]\w*",
            ),
            (
                "class",
                "definition",
                "class/trait/object",
                r"^\s*(?:(?:private|protected|final|sealed|abstract|case|"
                r"implicit)\s+)*(?:class|trait|object)\s+[A-Za-z_]\w*",
            ),
            (
                "val_var",
                "declaration",
                "val/var binding",
                r"^\s*(?:(?:private|protected|final|override|implicit|lazy)\s+)*"
                r"(?:val|var)\s+[A-Za-z_]\w*",
            ),
            ("type", "declaration", "type member", r"^\s*type\s+[A-Za-z_]\w*"),
        ),
    ),
    (
        "shell",
        (
            ("shebang", "other", "interpreter shebang", r"^#!\s*\S+"),
            (
                "function",
                "definition",
                "function definition",
                r"^\s*(?:function\s+)?[A-Za-z_]\w*\s*\(\)\s*\{?",
            ),
            (
                "variable",
                "declaration",
                "variable assignment",
                r"^\s*(?:export\s+|local\s+|readonly\s+|declare\s+)?" r"[A-Za-z_]\w*=",
            ),
            (
                "source",
                "import",
                "source/dot include",
                r"^\s*(?:source|\.)\s+[\w./$~-]+",
            ),
            (
                "control",
                "control",
                "control-flow keyword",
                r"^\s*(?:if|elif|else|fi|for|while|until|case|esac|do|done|" r"then)\b",
            ),
        ),
    ),
    (
        "sql",
        (
            ("select", "query", "SELECT statement", r"(?i)^\s*SELECT\b"),
            ("insert", "query", "INSERT statement", r"(?i)^\s*INSERT\s+INTO\b"),
            (
                "update",
                "query",
                "UPDATE statement",
                r"(?i)^\s*UPDATE\s+[\w.\"`\[\]]+\s+SET\b",
            ),
            ("delete", "query", "DELETE statement", r"(?i)^\s*DELETE\s+FROM\b"),
            (
                "create",
                "definition",
                "CREATE object",
                r"(?i)^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:TEMP(?:ORARY)?\s+)?"
                r"(?:TABLE|VIEW|INDEX|DATABASE|SCHEMA|FUNCTION|PROCEDURE|"
                r"TRIGGER|SEQUENCE)\b",
            ),
            (
                "alter",
                "definition",
                "ALTER statement",
                r"(?i)^\s*ALTER\s+(?:TABLE|VIEW|INDEX|DATABASE|SCHEMA)\b",
            ),
            (
                "drop",
                "definition",
                "DROP statement",
                r"(?i)^\s*DROP\s+(?:TABLE|VIEW|INDEX|DATABASE|SCHEMA|FUNCTION|"
                r"PROCEDURE|TRIGGER|SEQUENCE)\b",
            ),
            (
                "join",
                "clause",
                "JOIN clause",
                r"(?i)\b(?:INNER\s+|LEFT\s+|RIGHT\s+|FULL\s+|CROSS\s+)?JOIN\b",
            ),
        ),
    ),
    (
        "r",
        (
            (
                "library",
                "import",
                "library()/require() load",
                r"^\s*(?:library|require)\s*\(",
            ),
            (
                "function",
                "definition",
                "function assignment",
                r"[A-Za-z_.][\w.]*\s*(?:<-|=)\s*function\s*\(",
            ),
            (
                "assignment",
                "declaration",
                "assignment via <-",
                r"^\s*[A-Za-z_.][\w.]*\s*<-",
            ),
            ("source", "import", "source() include", r"^\s*source\s*\("),
        ),
    ),
    (
        "perl",
        (
            (
                "use",
                "import",
                "use/require module or pragma",
                r"^\s*(?:use|require)\s+[\w:]+",
            ),
            ("package", "definition", "package declaration", r"^\s*package\s+[\w:]+"),
            ("sub", "definition", "subroutine definition", r"^\s*sub\s+[A-Za-z_]\w*"),
            (
                "my_var",
                "declaration",
                "my/our/local variable",
                r"^\s*(?:my|our|local)\s+[\$@%]",
            ),
        ),
    ),
    (
        "lua",
        (
            ("require", "import", "require() load", r"\brequire\s*\(?\s*['\"]"),
            (
                "function",
                "definition",
                "function definition",
                r"^\s*(?:local\s+)?function\s+[\w.:]*",
            ),
            ("local", "declaration", "local variable", r"^\s*local\s+[A-Za-z_]\w*"),
        ),
    ),
    (
        "haskell",
        (
            (
                "import",
                "import",
                "import declaration",
                r"^\s*import\s+(?:qualified\s+)?[\w.]+",
            ),
            ("module", "definition", "module header", r"^\s*module\s+[\w.]+"),
            (
                "data_type",
                "definition",
                "data/newtype/type declaration",
                r"^\s*(?:data|newtype|type)\s+[A-Z]\w*",
            ),
            (
                "class_instance",
                "definition",
                "type class / instance",
                r"^\s*(?:class|instance)\s+",
            ),
            (
                "signature",
                "declaration",
                "top-level type signature",
                r"^\s*[a-z_]\w*\s*::",
            ),
        ),
    ),
    (
        "elixir",
        (
            (
                "defmodule",
                "definition",
                "module definition",
                r"^\s*defmodule\s+[A-Z][\w.]*",
            ),
            (
                "def",
                "definition",
                "function/macro definition",
                r"^\s*def(?:p|macro|macrop|delegate|struct|impl|protocol)?\s+"
                r"[A-Za-z_]",
            ),
            (
                "import_use",
                "import",
                "import/alias/use/require",
                r"^\s*(?:import|alias|use|require)\s+[A-Z]",
            ),
            ("module_attr", "declaration", "module attribute", r"^\s*@[a-z_]\w*\s+\S"),
        ),
    ),
    (
        "dart",
        (
            (
                "import",
                "import",
                "import/export/part directive",
                r"^\s*(?:import|export|part)\s+['\"]",
            ),
            (
                "class",
                "definition",
                "class/mixin/enum",
                r"^\s*(?:abstract\s+)?(?:class|mixin|enum)\s+[A-Za-z_]\w*",
            ),
            (
                "function",
                "definition",
                "function/method definition",
                r"^\s*(?:(?:static|final|const|external|factory)\s+)*"
                r"[\w<>,.]+[\s]+[A-Za-z_]\w*\s*\(",
            ),
            (
                "variable",
                "declaration",
                "typed/var declaration",
                r"^\s*(?:final|const|var|late)\s+[\w<>]*\s*[A-Za-z_]\w*\s*=",
            ),
        ),
    ),
    (
        "objc",
        (
            (
                "import",
                "import",
                "#import/#include directive",
                r"^\s*#\s*(?:import|include)\s*[<\"]",
            ),
            (
                "interface",
                "definition",
                "@interface declaration",
                r"^\s*@interface\s+[A-Za-z_]\w*",
            ),
            (
                "implementation",
                "definition",
                "@implementation block",
                r"^\s*@implementation\s+[A-Za-z_]\w*",
            ),
            (
                "protocol",
                "definition",
                "@protocol declaration",
                r"^\s*@protocol\s+[A-Za-z_]\w*",
            ),
            (
                "method",
                "definition",
                "method (- / +) declaration",
                r"^\s*[-+]\s*\([\w\s\*]+\)\s*[A-Za-z_]\w*",
            ),
            ("property", "declaration", "@property declaration", r"^\s*@property\b"),
        ),
    ),
    (
        "powershell",
        (
            ("function", "definition", "function definition", r"^\s*function\s+[\w-]+"),
            ("param", "declaration", "param block", r"^\s*param\s*\("),
            (
                "import_module",
                "import",
                "Import-Module / using",
                r"^\s*(?:Import-Module\b|using\s+(?:namespace|module)\b)",
            ),
            (
                "variable",
                "declaration",
                "variable assignment",
                r"^\s*\[[\w.\[\]]+\]\s*\$[A-Za-z_]\w*\s*=|^\s*\$[A-Za-z_]\w*\s*=",
            ),
        ),
    ),
)

# suffix -> language (1:1; first spelling wins, but the map is authored unique).
_EXT_TO_LANGUAGE: Dict[str, str] = {
    ext: lang for lang, exts in _LANGUAGE_EXTS.items() for ext in exts
}

# language -> compiled construct battery, in catalogue order.
_LANG_PATTERNS: Dict[str, Tuple[Tuple[str, str, "re.Pattern[str]"], ...]] = {
    lang: tuple((cname, kind, re.compile(rx)) for cname, kind, _desc, rx in specs)
    for lang, specs in _LANG_SPECS
}


_VOWELS = "aeiouy"


def _count_syllables(word: str) -> int:
    """Heuristic English syllable count (A12 readability inputs)."""
    w = re.sub(r"[^a-z]", "", word.lower())
    if not w:
        return 0
    count = 0
    prev_vowel = False
    for ch in w:
        is_vowel = ch in _VOWELS
        if is_vowel and not prev_vowel:
            count += 1
        prev_vowel = is_vowel
    if w.endswith("e") and count > 1:
        count -= 1
    return max(1, count)


def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy (bits/byte) of a byte string (A1 obfuscation signal)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 4)


def _dominant_script(text: str, sample: int = 20000) -> str:
    """Return the most common Unicode script family in ``text`` (A5)."""
    counts: Dict[str, int] = {}
    for ch in text[:sample]:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        script = name.split(" ")[0]
        # Map a handful of common first-tokens to a script family label.
        if script in ("LATIN",):
            fam = "Latin"
        elif script in ("CYRILLIC",):
            fam = "Cyrillic"
        elif script in ("GREEK",):
            fam = "Greek"
        elif script in ("ARABIC",):
            fam = "Arabic"
        elif script in ("HEBREW",):
            fam = "Hebrew"
        elif script in ("CJK", "HIRAGANA", "KATAKANA", "HANGUL"):
            fam = "CJK"
        elif script in ("DEVANAGARI",):
            fam = "Devanagari"
        else:
            fam = script.title()
        counts[fam] = counts.get(fam, 0) + 1
    if not counts:
        return "unknown"
    return max(counts.items(), key=lambda kv: kv[1])[0]


def _readability_suite(
    words: int, sentences: int, syllables: int, chars: int, complex_words: int
) -> Dict[str, float]:
    """Compute the classic readability formulas (A12).

    Guards every division so an empty/degenerate document returns 0.0 rather
    than raising; values are rounded to 2 decimals.
    """
    if words == 0 or sentences == 0:
        return {
            "flesch_reading_ease": 0.0,
            "flesch_kincaid_grade": 0.0,
            "gunning_fog": 0.0,
            "smog": 0.0,
            "coleman_liau": 0.0,
            "automated_readability_index": 0.0,
        }
    wps = words / sentences
    spw = syllables / words
    cpw = chars / words
    complex_ratio = complex_words / words
    flesch = 206.835 - 1.015 * wps - 84.6 * spw
    fk = 0.39 * wps + 11.8 * spw - 15.59
    fog = 0.4 * (wps + 100 * complex_ratio)
    smog = 1.0430 * math.sqrt(complex_words * (30 / sentences)) + 3.1291
    cli = 0.0588 * (cpw * 100) - 0.296 * (sentences / words * 100) - 15.8
    ari = 4.71 * cpw + 0.5 * wps - 21.43
    return {
        "flesch_reading_ease": round(flesch, 2),
        "flesch_kincaid_grade": round(fk, 2),
        "gunning_fog": round(fog, 2),
        "smog": round(smog, 2),
        "coleman_liau": round(cli, 2),
        "automated_readability_index": round(ari, 2),
    }


# PDF active-content keyword flags (A2): presence + occurrence count scanned on
# the raw bytes. Each is a real /Name token that signals executable or network
# behaviour in a PDF.
_PDF_KEYWORD_FLAGS: Tuple[Tuple[str, bytes, str], ...] = (
    ("javascript", b"/JavaScript", "active_content"),
    ("js", b"/JS", "active_content"),
    ("openaction", b"/OpenAction", "auto_run"),
    ("additional_actions", b"/AA", "auto_run"),
    ("launch", b"/Launch", "external_program"),
    ("embedded_file", b"/EmbeddedFile", "embedding"),
    ("uri", b"/URI", "network"),
    ("submit_form", b"/SubmitForm", "network"),
    ("rich_media", b"/RichMedia", "active_content"),
    ("flash", b"/Flash", "active_content"),
    ("xfa", b"/XFA", "forms"),
    ("acroform", b"/AcroForm", "forms"),
    ("goto_remote", b"/GoToR", "network"),
    ("goto_embedded", b"/GoToE", "embedding"),
    ("object_stream", b"/ObjStm", "obfuscation"),
    ("encrypt", b"/Encrypt", "security"),
)

# The Part-A static-layer catalogue (Database 2's authoritative metric list).
# One row per (section, metric); ``computed`` marks whether this DocumentParser
# build produces the metric with the standard library / installed optional
# backends, vs. records it as a catalogued-but-unavailable slot. This mirrors
# ``DUMP/document-analysis-engine-metrics.md`` Part A (#46-#366).
_METRIC_CATALOG: Tuple[Tuple[str, str, str, str, bool], ...] = (
    # (section_id, section_title, metric, notes, computed)
    (
        "A1",
        "File and Container Structure",
        "file_type_magic",
        "magic-byte sniff vs extension",
        True,
    ),
    ("A1", "File and Container Structure", "mime_type", "mimetypes guess", True),
    ("A1", "File and Container Structure", "file_size", "bytes on disk", True),
    ("A1", "File and Container Structure", "hashes", "SHA-256 + MD5", True),
    ("A1", "File and Container Structure", "format_version", "PDF-x.y / OOXML", True),
    (
        "A1",
        "File and Container Structure",
        "encryption_flag",
        "/Encrypt or encrypted zip",
        True,
    ),
    (
        "A1",
        "File and Container Structure",
        "object_counts",
        "pages/streams/fonts/images",
        True,
    ),
    (
        "A1",
        "File and Container Structure",
        "incremental_updates",
        "%%EOF / revision count",
        True,
    ),
    (
        "A1",
        "File and Container Structure",
        "compression_ratio",
        "stored vs uncompressed (zip)",
        True,
    ),
    ("A1", "File and Container Structure", "entropy", "Shannon bits/byte", True),
    (
        "A1",
        "File and Container Structure",
        "embedded_file_count",
        "container members",
        True,
    ),
    (
        "A2",
        "Active Content and Security",
        "pdf_keyword_flags",
        "/JavaScript,/OpenAction,...",
        True,
    ),
    (
        "A2",
        "Active Content and Security",
        "network_indicators",
        "urls/domains/ips",
        True,
    ),
    (
        "A2",
        "Active Content and Security",
        "office_macros",
        "vbaProject.bin / DDE",
        True,
    ),
    (
        "A2",
        "Active Content and Security",
        "hidden_content",
        "tiny/invisible text heuristics",
        False,
    ),
    ("A3", "Metadata", "pdf_info_dict", "Title/Author/Creator/Producer/dates", True),
    ("A3", "Metadata", "ooxml_core_app", "core.xml + app.xml", True),
    (
        "A3",
        "Metadata",
        "consistency_checks",
        "ModDate<CreationDate, future dates",
        True,
    ),
    ("A3", "Metadata", "xmp_packet", "XMP presence + PDF/A id", True),
    ("A3", "Metadata", "image_exif", "EXIF device/gps/software", False),
    ("A4", "Page Geometry", "page_count", "number of pages", True),
    ("A4", "Page Geometry", "media_box", "per-page MediaBox/CropBox", True),
    ("A4", "Page Geometry", "orientation", "portrait/landscape/rotation", True),
    (
        "A4",
        "Page Geometry",
        "born_digital_vs_scanned",
        "text layer vs full-page image",
        True,
    ),
    ("A5", "Text Layer", "counts", "chars/words/lines/sentences/paragraphs", True),
    ("A5", "Text Layer", "fonts", "name/type/embedded/encoding", False),
    ("A5", "Text Layer", "text_quality", "FFFD/PUA/non-printable ratios", True),
    ("A5", "Text Layer", "language_script", "dominant script + language guess", True),
    ("A6", "Image Quality", "dpi_dimensions", "requires image backend", False),
    ("A6", "Image Quality", "blur_noise_skew", "requires image backend", False),
    ("A7", "OCR Output", "token_confidence", "requires OCR backend", False),
    ("A7", "OCR Output", "barcodes_qr", "requires image backend", False),
    ("A8", "Layout Elements", "heading_hierarchy", "H1-H6 from extracted text", True),
    ("A8", "Layout Elements", "toc_bookmarks", "outline detection", True),
    ("A8", "Layout Elements", "element_classes", "title/list/table heuristics", True),
    ("A9", "Tables", "table_count", "markup/table heuristics", True),
    ("A9", "Tables", "cell_structure", "rows x cols (when tabular)", True),
    ("A10", "Forms", "acroform_fields", "/AcroForm + /XFA presence", True),
    (
        "A11",
        "Pattern / Rule Entities",
        "entities",
        "dates/money/emails/ids + checksums",
        True,
    ),
    (
        "A12",
        "Lexical / Statistical NLP",
        "basic_statistics",
        "token/type/TTR/lengths",
        True,
    ),
    (
        "A12",
        "Lexical / Statistical NLP",
        "readability_suite",
        "Flesch/FK/Fog/SMOG/CLI/ARI",
        True,
    ),
    (
        "A12",
        "Lexical / Statistical NLP",
        "keywords_ngrams",
        "top n-grams / term freq",
        True,
    ),
    (
        "A13",
        "Deterministic Validation",
        "date_logic",
        "future-date / range plausibility",
        True,
    ),
    (
        "A13",
        "Deterministic Validation",
        "arithmetic",
        "line-item sums (structured docs)",
        False,
    ),
    (
        "A14",
        "Forensics and Compliance",
        "incremental_saves",
        "revision count with changes",
        True,
    ),
    (
        "A14",
        "Forensics and Compliance",
        "standards_conformance",
        "PDF/A,PDF/UA,PDF/X markers",
        True,
    ),
    ("A14", "Forensics and Compliance", "tamper_signals", "metadata anomalies", True),
    ("A15", "Chunking for RAG", "chunk_count", "token-window chunker", True),
    (
        "A15",
        "Chunking for RAG",
        "chunk_distribution",
        "min/p50/p95/max token counts",
        True,
    ),
    (
        "A15",
        "Chunking for RAG",
        "chunk_boundaries",
        "mid-sentence / orphan chunks",
        True,
    ),
)


class DocumentParser:
    """Analyze true document-format files into normalized ``document_parser_*`` tables.

    Real implementation. For every routed document file this plane runs the
    :meth:`_converter` text extraction and then computes the **Part-A static
    layer** metric catalogue (see ``DUMP/document-analysis-engine-metrics.md``):
    file/container structure, active-content & security indicators, metadata,
    page geometry, text-layer statistics, layout/table/form heuristics, rule
    based entity extraction with checksums, the lexical/readability suite, and
    RAG chunking. These feed **Database 2** (the metric database).

    Independently, :meth:`concord_text` / :meth:`concord_file` tokenize any file
    into per-occurrence ``(token, kind, line, start_col, end_col)`` records that
    feed **Database 1** (the hash-table registry keyed by repository file
    location). Both databases are materialized by
    :class:`file_analyzer.document.document_db.DocumentParserDatabaseGenerator`, which
    ``AnalysisEngine`` dumps beside the main repository database.
    """

    KIND_FILE = "file"
    KIND_METRIC = "metric"

    # Concordance defaults: index single characters in addition to words. The
    # character index is what makes Database 1 a true word/character registry;
    # a caller (or AnalysisEngine) can disable it for very large repositories.
    DEFAULT_INDEX_CHARS = True

    def __init__(
        self,
        file_paths: List[Union[str, Path]],
        dump_file_path: str = "document_parser_analysis.json",
        dump_file_type: str = "memory",
        index_chars: bool = DEFAULT_INDEX_CHARS,
        concordance_max_bytes: int = 25_000_000,
        enable_grep: bool = True,
        grep_max_matches_per_pattern: int = 10_000,
        enable_lang_scan: bool = True,
    ):
        self.file_paths = [Path(p) for p in file_paths]
        self.dump_file_path = dump_file_path
        self.dump_file_type = dump_file_type.lower()
        self.index_chars = index_chars
        self.concordance_max_bytes = concordance_max_bytes
        # Database-1 grep sweep: run the regex battery over every indexed file.
        # ``grep_max_matches_per_pattern`` caps how many hits of any one pattern
        # are recorded per file so a pathological file (e.g. one giant base64
        # asset) cannot blow up the match table; 0/None means "no cap". The same
        # cap bounds the language-aware construct sweep (per file x construct).
        self.enable_grep = enable_grep
        self.grep_max_matches_per_pattern = grep_max_matches_per_pattern
        # Database-1 language-aware construct sweep (per-language grammar battery,
        # keyed off the file's extension). Off -> lang_scan() returns nothing.
        self.enable_lang_scan = enable_lang_scan

        # Database-2 (metric) tables: one parent metrics row per file plus the
        # normalized children (keyword flags / entities / readability / fonts /
        # chunks) and the static Part-A catalogue.
        self.document_parser_files_table: List[Dict[str, Any]] = []
        self.document_metrics_table: List[Dict[str, Any]] = []
        self.document_keyword_flags_table: List[Dict[str, Any]] = []
        self.document_entities_table: List[Dict[str, Any]] = []
        self.document_readability_table: List[Dict[str, Any]] = []
        self.document_fonts_table: List[Dict[str, Any]] = []
        self.document_chunks_table: List[Dict[str, Any]] = []
        self.document_metric_catalog_table: List[Dict[str, Any]] = [
            {
                "catalog_id": i + 1,
                "section_id": sec,
                "section_title": title,
                "metric": metric,
                "notes": notes,
                "layer": "static",
                "computed": computed,
            }
            for i, (sec, title, metric, notes, computed) in enumerate(_METRIC_CATALOG)
        ]
        self.document_parser_file_index: List[Dict[str, Any]] = []

        # Database-1 (concordance) occurrences: one row per token occurrence,
        # pre-aggregation. AnalysisEngine (or the concordance worker) rolls these
        # up into the global hash-table registry keyed by repository location.
        self.document_concordance_occurrences: List[Dict[str, Any]] = []

        # Optional AI converter backends (hook key -> callable), consumed by
        # _converter(); empty by default. Populate via register_ai_model() or
        # pass ai_models=... to _converter().
        self._ai_models: Dict[str, Callable[..., str]] = {}

        # Database-3 (dynamic layer, Part B #368-458): populated on demand by
        # dynamic_analyze(). Extracted text is cached per file during analyze()
        # so the agent+code loop can re-read the source without re-converting.
        self._text_cache: Dict[int, str] = {}
        self.dynamic_tables: Dict[str, List[Dict[str, Any]]] = {}
        # Database-4 (evaluation layer, Part C #455-584): populated on demand by
        # evaluate().
        self.evaluation_tables: Dict[str, List[Dict[str, Any]]] = {}

        self._ids = {
            "file": 0,
            "dpfi": 0,
            "metric": 0,
            "flag": 0,
            "entity": 0,
            "read": 0,
            "font": 0,
            "chunk": 0,
        }

    # ------------------------------------------------------------------
    # id helpers
    # ------------------------------------------------------------------
    def _next(self, key: str) -> int:
        self._ids[key] += 1
        return self._ids[key]

    @classmethod
    def _known_exts(cls) -> frozenset:
        return frozenset(DOCUMENT_SUFFIXES)

    @classmethod
    def routing_suffixes(cls) -> Tuple[str, ...]:
        return DOCUMENT_SUFFIXES

    # Order matters: an extension shared by several families (e.g. ``.js`` is both
    # source_code and script; ``.p`` / ``.r`` / ``.beam`` are source_code and
    # object_code; ``.port`` is script and makefile) is reported under the richest
    # matching bucket first.
    _CODE_FAMILIES: Tuple[Tuple[str, frozenset], ...] = (
        ("source_code", _SOURCE_CODE_EXTS),
        ("shader", _SHADER_EXTS),
        ("script", _SCRIPT_EXTS),
        ("makefile", _MAKEFILE_EXTS),
        ("object_code", _OBJECT_CODE_EXTS),
    )

    @classmethod
    def code_family(cls, ext: Optional[str]) -> Optional[str]:
        """Return the code family (``source_code`` / ``script`` / ``shader`` /
        ``makefile`` / ``object_code``) for an extension, or ``None`` when it is
        not a known code extension. Extensions are the last-component suffix,
        matching the router's convention (see :meth:`_true_ext`)."""
        if not ext:
            return None
        ext = ext.lower()
        for name, exts in cls._CODE_FAMILIES:
            if ext in exts:
                return name
        return None

    @classmethod
    def code_extensions(cls) -> frozenset:
        """The full code-extension universe DocumentParser recognizes (all five
        families unioned; ``object_code`` included)."""
        return _CODE_TEXT_EXTS | _OBJECT_CODE_EXTS

    @staticmethod
    def _true_ext(path: Path) -> str:
        """Last-component suffix, lower-cased (mirrors the router's convention)."""
        name = path.name.lower()
        dot = name.rfind(".")
        return name[dot:] if dot > 0 else ""

    # ==================================================================
    # Format conversion (document / extension -> txt | md), optional AI
    # ==================================================================
    # modality -> ordered AI hook keys _converter() looks for in the model
    # registry. The first registered hook wins; an empty tuple means the
    # modality is handled without any model.
    _MODALITY_HOOKS: Dict[str, Tuple[str, ...]] = {
        "plaintext": (),
        "text_native": ("text",),
        "layout": ("text", "ocr"),
        "ocr": ("ocr",),
        "image": ("image", "ocr"),
        "audio": ("audio",),
        "notation": ("notation", "text"),
    }

    @classmethod
    def _conversion_modality(cls, ext: str) -> str:
        """Classify a suffix into the strategy :meth:`_converter` uses to reach text."""
        ext = ext.lower()
        if ext and not ext.startswith("."):
            ext = "." + ext
        if ext in _NOTATION_EXTS:
            return "notation"
        if ext in _AUDIO_EXTS:
            return "audio"
        if ext in _IMAGE_EXTS:
            return "image"
        if ext in _OCR_EXTS:
            return "ocr"
        if ext in _LAYOUT_EXTS:
            return "layout"
        if ext in _PLAINTEXT_EXTS:
            return "plaintext"
        # e-books, word-processor / office documents and every other document
        # suffix: crack the container for its text layer (text model / extractor).
        return "text_native"

    def register_ai_model(self, hook: str, fn: Callable[..., str]) -> None:
        """Register an optional converter backend under a hook key.

        Recognized hooks: ``text`` (document / text-to-text extraction),
        ``ocr`` (scanned page / image -> text), ``image`` (image caption /
        description), ``audio`` (speech-to-text) and ``notation`` (music score
        -> text). Each backend is a callable ``fn(path, ext, target) -> str``.
        """
        self._ai_models[hook] = fn

    @staticmethod
    def _as_target(text: str, path: Path, target: str) -> str:
        """Shape extracted text for the requested target: ``txt`` verbatim; ``md``
        gains a single top-level title heading when it has none."""
        text = text or ""
        if target == "txt":
            return text
        if text.lstrip().startswith("#"):
            return text
        title = Path(path).stem or "document"
        return f"# {title}\n\n{text}" if text else f"# {title}\n"

    def _converter(
        self,
        path: Union[str, Path],
        ext: Optional[str] = None,
        *,
        target: str = "md",
        ai_models: Optional[Dict[str, Callable[..., str]]] = None,
        encoding: str = "utf-8",
        max_bytes: int = 25_000_000,
    ) -> Dict[str, Any]:
        """Convert one document-format file to plain text (``txt``) or Markdown (``md``).

        Extraction is attempted best-first through a real chain (see
        :meth:`_extractor_chain`):

          * **stdlib, always available** -- Office Open XML (``.docx`` family) via
            ``word/document.xml``; OpenDocument (``.odt`` family) via
            ``content.xml``; EPUB via its OPF spine of XHTML; RTF via a full
            de-RTF pass; (X)HTML via an HTML->text parser; MusicXML / MuseScore
            (``.mxl`` / ``.mscz``) title + lyrics; and plain text decoded directly.
          * **optional libraries / CLIs, used when present** -- PDF via ``pypdf``
            then PyMuPDF (``fitz``) then ``pdftotext``; XPS/OXPS via ``fitz``;
            PostScript via ``ps2ascii``; DjVu via ``djvutxt``; scanned pages via
            ``pytesseract`` / the ``tesseract`` CLI; and ``pandoc`` / LibreOffice
            (``soffice``) as broad last-resort converters.
          * **optional AI backends** -- registered via :meth:`register_ai_model`
            or the ``ai_models`` argument (``text`` / ``ocr`` / ``image`` /
            ``audio`` / ``notation``), tried only after every real extractor.

        Nothing is fabricated: if no extractor and no AI backend can handle the
        file the result is ``status == "needs_ai"`` (or ``"unsupported"``) naming
        what would unlock it, plus the errors from any backend that was tried.

        Returns a result dict with keys ``source, extension, target_format,
        modality, status, model, text, chars, detail`` where ``status`` is one of
        ``converted`` / ``empty`` / ``needs_ai`` / ``unsupported`` / ``error`` and
        ``model`` names the extractor that produced the text.
        """
        p = Path(path)
        ext = (ext if ext is not None else self._true_ext(p)).lower()
        if ext and not ext.startswith("."):
            ext = "." + ext
        target = (target or "md").lower()
        if target not in ("md", "txt"):
            target = "md"

        modality = self._conversion_modality(ext)
        models: Dict[str, Callable[..., str]] = dict(self._ai_models)
        if ai_models:
            models.update(ai_models)

        result: Dict[str, Any] = {
            "source": str(p),
            "extension": ext.lstrip("."),
            "target_format": target,
            "modality": modality,
            "status": "error",
            "model": None,
            "text": None,
            "chars": 0,
            "detail": "",
        }

        if not p.exists():
            result["detail"] = "file not found"
            return result

        # 1) Plain text: a real, dependency-free conversion.
        if modality == "plaintext":
            try:
                raw = p.read_bytes()[:max_bytes]
            except OSError as err:
                result["detail"] = f"read failed: {err}"
                return result
            text = raw.decode(encoding, errors="replace")
            out = self._as_target(text, p, target)
            result.update(
                status="converted" if text.strip() else "empty",
                text=out,
                chars=len(out),
                detail="decoded plain text (no model needed)",
            )
            return result

        # 2) Real extractors, best-first. Each returns the extracted text, or
        #    None to mean "not me / backend unavailable / no text found" so the
        #    chain falls through to the next strategy.
        errors: List[str] = []
        for name, extractor in self._extractor_chain(ext, modality):
            try:
                extracted = extractor(p, ext, target, max_bytes)
            except Exception as err:  # a backend must never crash the plane
                errors.append(f"{name}: {err}")
                continue
            if extracted is None:
                continue
            out = self._as_target(extracted, p, target)
            result.update(
                status="converted" if extracted.strip() else "empty",
                model=name,
                text=out,
                chars=len(out),
                detail=f"extracted via {name}",
            )
            return result

        # 3) Optional AI backends, first registered hook for the modality wins.
        for hook in self._MODALITY_HOOKS.get(modality, ("text",)):
            fn = models.get(hook)
            if fn is None:
                continue
            try:
                produced = fn(p, ext, target)
            except Exception as err:
                result.update(
                    status="error",
                    model=f"ai:{hook}",
                    detail=f"{hook} model raised: {err}",
                )
                return result
            text = "" if produced is None else str(produced)
            out = self._as_target(text, p, target)
            result.update(
                status="converted" if text.strip() else "empty",
                model=f"ai:{hook}",
                text=out,
                chars=len(out),
                detail=f"converted via {hook} AI model",
            )
            return result

        # 4) No native extractor and no AI backend could handle it: be honest
        #    about which model would unlock it, and surface any backend errors.
        needed = list(self._MODALITY_HOOKS.get(modality, ("text",)))
        detail = (
            f"no native extractor available for .{result['extension']} "
            f"({modality}); register an AI model for one of {needed} "
            f"via register_ai_model() or pass ai_models=..."
        )
        if errors:
            detail += " | tried: " + "; ".join(errors)
        result.update(
            status="needs_ai" if needed else "unsupported",
            detail=detail,
        )
        return result

    # ------------------------------------------------------------------
    # extractor chain + individual real extractors
    # ------------------------------------------------------------------
    def _extractor_chain(
        self, ext: str, modality: str
    ) -> List[Tuple[str, Callable[..., Optional[str]]]]:
        """Ordered ``(name, extractor)`` strategies for this suffix / modality.

        Each extractor has signature ``fn(path, ext, target, max_bytes) -> str |
        None`` and returns ``None`` when it does not apply or its backend is
        absent, so the chain simply falls through to the next candidate.
        """
        chain: List[Tuple[str, Callable[..., Optional[str]]]] = []
        if ext in _HTML_EXTS:
            chain.append(("stdlib:html", self._extract_html))
        if ext in _RTF_EXTS:
            chain.append(("stdlib:rtf", self._extract_rtf))
        if ext in _OOXML_WORD_EXTS:
            chain.append(("stdlib:ooxml", self._extract_ooxml))
        if ext in _ODF_EXTS:
            chain.append(("stdlib:odf", self._extract_odf))
        if ext in _EPUB_ZIP_EXTS:
            chain.append(("stdlib:epub", self._extract_epub))
        if ext in _MUSICXML_EXTS:
            chain.append(("stdlib:musicxml", self._extract_musicxml))
        if ext in _PDF_EXTS:
            chain.append(("pdf", self._extract_pdf))
        if ext in _XPS_EXTS:
            chain.append(("xps", self._extract_xps))
        if ext in _PS_EXTS:
            chain.append(("postscript", self._extract_postscript))
        if ext in _DJVU_EXTS:
            chain.append(("djvu", self._extract_djvu))
        if modality in ("image", "ocr") or ext in _IMAGE_EXTS:
            chain.append(("ocr", self._extract_ocr_image))
        # Broad real fallbacks -- self-skip when the binary is not installed.
        if modality in ("text_native", "layout", "ocr", "notation"):
            chain.append(("pandoc", self._extract_pandoc))
            chain.append(("libreoffice", self._extract_libreoffice))
        return chain

    # -- shared CLI helper --------------------------------------------------
    @staticmethod
    def _run_cli(
        args: List[str],
        *,
        timeout: int = 180,
        stdin_bytes: Optional[bytes] = None,
    ) -> Optional[str]:
        """Run ``args`` and return decoded stdout, or ``None`` if the tool is
        missing / fails / produces nothing. Never raises for the caller."""
        exe = shutil.which(args[0])
        if exe is None:
            return None
        try:
            proc = subprocess.run(
                [exe, *args[1:]],
                input=stdin_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode != 0:
            return None
        text = proc.stdout.decode("utf-8", errors="replace")
        return text if text.strip() else None

    # -- stdlib extractors (no third-party dependency) ---------------------
    @staticmethod
    def _extract_html(
        path: Path, ext: str, target: str, max_bytes: int
    ) -> Optional[str]:
        data = path.read_bytes()[:max_bytes]
        return _html_to_text(data)

    @staticmethod
    def _extract_rtf(
        path: Path, ext: str, target: str, max_bytes: int
    ) -> Optional[str]:
        data = path.read_bytes()[:max_bytes]
        if not data.lstrip().startswith(b"{\\rtf"):
            return None
        return _rtf_to_text(data)

    @staticmethod
    def _extract_ooxml(
        path: Path, ext: str, target: str, max_bytes: int
    ) -> Optional[str]:
        """Pull paragraph text out of an OOXML wordprocessing document."""
        try:
            with zipfile.ZipFile(path) as zf:
                xml = zf.read("word/document.xml")
        except (zipfile.BadZipFile, KeyError, OSError):
            return None
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return None
        w = _OOXML_W
        paragraphs: List[str] = []
        for para in root.iter(w + "p"):
            buf: List[str] = []
            for node in para.iter():
                tag = node.tag
                if tag == w + "t":
                    buf.append(node.text or "")
                elif tag == w + "tab":
                    buf.append("\t")
                elif tag in (w + "br", w + "cr"):
                    buf.append("\n")
            paragraphs.append("".join(buf))
        return "\n".join(paragraphs).strip()

    @staticmethod
    def _extract_odf(
        path: Path, ext: str, target: str, max_bytes: int
    ) -> Optional[str]:
        """Pull heading / paragraph text out of an OpenDocument text file."""
        try:
            with zipfile.ZipFile(path) as zf:
                xml = zf.read("content.xml")
        except (zipfile.BadZipFile, KeyError, OSError):
            return None
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return None
        blocks: List[str] = []
        for el in root.iter():
            if _localname(el.tag) in ("p", "h"):
                text = "".join(el.itertext())
                if text:
                    blocks.append(text)
        return "\n".join(blocks).strip()

    @classmethod
    def _extract_epub(
        cls, path: Path, ext: str, target: str, max_bytes: int
    ) -> Optional[str]:
        """Concatenate an EPUB's spine documents in reading order."""
        try:
            zf = zipfile.ZipFile(path)
        except (zipfile.BadZipFile, OSError):
            return None
        with zf:
            names = set(zf.namelist())
            # 1) locate the OPF via META-INF/container.xml (fall back to search).
            opf_name: Optional[str] = None
            if "META-INF/container.xml" in names:
                try:
                    container = ET.fromstring(zf.read("META-INF/container.xml"))
                    for rf in container.iter():
                        if _localname(rf.tag) == "rootfile":
                            opf_name = rf.attrib.get("full-path")
                            break
                except ET.ParseError:
                    opf_name = None
            if opf_name is None:
                opf_name = next((n for n in names if n.lower().endswith(".opf")), None)
            if opf_name is None or opf_name not in names:
                return None
            # 2) parse manifest (id -> href) and the spine order (idrefs).
            try:
                opf = ET.fromstring(zf.read(opf_name))
            except (ET.ParseError, KeyError, OSError):
                return None
            manifest: Dict[str, str] = {}
            spine: List[str] = []
            for el in opf.iter():
                ln = _localname(el.tag)
                if ln == "item":
                    iid = el.attrib.get("id")
                    href = el.attrib.get("href")
                    if iid and href:
                        manifest[iid] = href
                elif ln == "itemref":
                    idref = el.attrib.get("idref")
                    if idref:
                        spine.append(idref)
            base = posixpath.dirname(opf_name)
            hrefs = [manifest[i] for i in spine if i in manifest] or list(
                manifest.values()
            )
            # 3) extract text from each XHTML document, in order.
            chapters: List[str] = []
            for href in hrefs:
                full = posixpath.normpath(posixpath.join(base, href)) if base else href
                if full not in names:
                    continue
                if (
                    not href.lower()
                    .split("#", 1)[0]
                    .endswith((".htm", ".html", ".xhtml"))
                ):
                    continue
                try:
                    chapter = _html_to_text(zf.read(full))
                except (KeyError, OSError):
                    continue
                if chapter.strip():
                    chapters.append(chapter)
            return "\n\n".join(chapters).strip() or None

    @classmethod
    def _extract_musicxml(
        cls, path: Path, ext: str, target: str, max_bytes: int
    ) -> Optional[str]:
        """Recover title / composer / part names / lyrics from a score file."""
        xml_bytes: Optional[bytes] = None
        if ext in (".mxl", ".mscz"):
            try:
                with zipfile.ZipFile(path) as zf:
                    names = zf.namelist()
                    target_name = None
                    if ext == ".mxl" and "META-INF/container.xml" in names:
                        container = ET.fromstring(zf.read("META-INF/container.xml"))
                        for rf in container.iter():
                            if _localname(rf.tag) == "rootfile":
                                target_name = rf.attrib.get("full-path")
                                break
                    if target_name is None:
                        wanted = ".mscx" if ext == ".mscz" else ".xml"
                        target_name = next(
                            (
                                n
                                for n in names
                                if n.lower().endswith(wanted)
                                and not n.startswith("META-INF")
                            ),
                            None,
                        )
                    if target_name is None:
                        return None
                    xml_bytes = zf.read(target_name)
            except (zipfile.BadZipFile, KeyError, OSError, ET.ParseError):
                return None
        else:
            xml_bytes = path.read_bytes()[:max_bytes]
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError:
            return None

        headings: List[str] = []
        lyrics: List[str] = []
        parts: List[str] = []
        for el in root.iter():
            ln = _localname(el.tag)
            txt = (el.text or "").strip()
            if ln in ("work-title", "movement-title", "credit-words") and txt:
                headings.append(txt)
            elif ln == "creator" and txt:
                headings.append(txt)
            elif ln == "part-name" and txt:
                parts.append(txt)
            elif ln == "text" and txt:
                # MusicXML nests lyric syllables in <lyric><text>; MuseScore
                # nests them in <Lyrics><text>. Both surface here as a "text" tag.
                lyrics.append(txt)
            elif ln == "metaTag":  # MuseScore .mscx metadata
                if (
                    el.attrib.get("name") in ("workTitle", "composer", "lyricist")
                    and txt
                ):
                    headings.append(txt)
        # MuseScore lyrics live under <Lyrics><text>; those are captured by the
        # generic ``text`` sweep above. Join everything we found.
        chunks: List[str] = []
        if headings:
            chunks.append("\n".join(dict.fromkeys(headings)))
        if parts:
            chunks.append("Parts: " + ", ".join(dict.fromkeys(parts)))
        if lyrics:
            chunks.append(" ".join(lyrics))
        result = "\n\n".join(chunks).strip()
        return result or None

    # -- optional third-party / CLI extractors -----------------------------
    @staticmethod
    def _extract_pdf(
        path: Path, ext: str, target: str, max_bytes: int
    ) -> Optional[str]:
        """PDF text via pypdf, then PyMuPDF (fitz), then the pdftotext CLI."""
        # 1) pypdf
        try:
            import pypdf  # type: ignore

            reader = pypdf.PdfReader(str(path))
            pages = [(pg.extract_text() or "") for pg in reader.pages]
            text = "\n".join(pages).strip()
            if text:
                return text
        except ImportError:
            pass
        except Exception:
            pass
        # 2) PyMuPDF
        try:
            import fitz  # type: ignore

            with fitz.open(str(path)) as doc:
                text = "\n".join(page.get_text() for page in doc).strip()
            if text:
                return text
        except ImportError:
            pass
        except Exception:
            pass
        # 3) poppler's pdftotext ("-" = write to stdout)
        return DocumentParser._run_cli(["pdftotext", "-q", "-layout", str(path), "-"])

    @staticmethod
    def _extract_xps(
        path: Path, ext: str, target: str, max_bytes: int
    ) -> Optional[str]:
        """XPS / OpenXPS text via PyMuPDF, which opens these natively."""
        try:
            import fitz  # type: ignore

            with fitz.open(str(path)) as doc:
                text = "\n".join(page.get_text() for page in doc).strip()
            return text or None
        except ImportError:
            return None
        except Exception:
            return None

    @staticmethod
    def _extract_postscript(
        path: Path, ext: str, target: str, max_bytes: int
    ) -> Optional[str]:
        """PostScript text via ghostscript's ps2ascii."""
        return DocumentParser._run_cli(["ps2ascii", str(path)])

    @staticmethod
    def _extract_djvu(
        path: Path, ext: str, target: str, max_bytes: int
    ) -> Optional[str]:
        """DjVu text layer via djvulibre's djvutxt."""
        return DocumentParser._run_cli(["djvutxt", str(path)])

    @staticmethod
    def _extract_ocr_image(
        path: Path, ext: str, target: str, max_bytes: int
    ) -> Optional[str]:
        """OCR a raster image via pytesseract, else the tesseract CLI."""
        try:
            import pytesseract  # type: ignore
            from PIL import Image  # type: ignore

            with Image.open(str(path)) as img:
                text = pytesseract.image_to_string(img).strip()
            if text:
                return text
        except ImportError:
            pass
        except Exception:
            pass
        return DocumentParser._run_cli(["tesseract", str(path), "stdout"])

    @staticmethod
    def _extract_pandoc(
        path: Path, ext: str, target: str, max_bytes: int
    ) -> Optional[str]:
        """Broad fallback: pandoc converting to plain text / gfm when installed.

        pandoc infers the input format from the extension and cannot read binary
        page-description formats (PDF/PS), so it simply fails there and returns
        ``None`` -- it only actually helps for markup / office inputs it supports.
        """
        to_fmt = "gfm" if target == "md" else "plain"
        return DocumentParser._run_cli(
            ["pandoc", str(path), "-t", to_fmt, "--wrap=none"]
        )

    @staticmethod
    def _extract_libreoffice(
        path: Path, ext: str, target: str, max_bytes: int
    ) -> Optional[str]:
        """Broad fallback: headless LibreOffice converting to text when installed."""
        exe = shutil.which("soffice") or shutil.which("libreoffice")
        if exe is None:
            return None
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            try:
                proc = subprocess.run(
                    [
                        exe,
                        "--headless",
                        "--convert-to",
                        "txt:Text",
                        "--outdir",
                        tmp,
                        str(path),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=240,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                return None
            if proc.returncode != 0:
                return None
            out_file = Path(tmp) / (path.stem + ".txt")
            if not out_file.exists():
                return None
            text = out_file.read_text(encoding="utf-8", errors="replace").strip()
            return text or None

    # ==================================================================
    # Concordance primitives (Database 1 source)
    # ==================================================================
    def read_text_best_effort(
        self, path: Union[str, Path], ext: Optional[str] = None
    ) -> Tuple[str, str, Optional[str]]:
        """Return ``(text, status, model)`` for any file.

        Document formats go through :meth:`_converter` (real extraction / honest
        ``needs_ai``); every other file is decoded directly as text and skipped
        (``status="binary"``) when it does not look like text. This is what lets
        Database 1 index *all* repository files, not just document formats.
        """
        path = Path(path)
        ext = (ext or self._true_ext(path)).lower()
        if ext in self._known_exts():
            conv = self._converter(path, ext, target="txt")
            return (
                conv.get("text") or "",
                conv.get("status", "unknown"),
                conv.get("model"),
            )
        # Non-document file: decode as text, best effort. Recognized code-source
        # families (source_code / script / shader / makefile) are reported with a
        # ``status="code"`` marker and their family in the model slot so Database 1
        # records what kind of code each indexed file is; everything else that
        # decodes cleanly is plain ``"decoded"`` text. The NUL-byte guard still
        # applies -- a compiled object masquerading under a text-family suffix is
        # skipped as ``binary`` rather than dumped into the concordance.
        try:
            raw = path.read_bytes()[: self.concordance_max_bytes]
        except OSError:
            return "", "error", None
        if b"\x00" in raw[:4096]:
            return "", "binary", None
        try:
            text = raw.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            text = raw.decode("latin-1", errors="replace")
            encoding = "latin-1"
        family = self.code_family(ext)
        if family and family != "object_code":
            return text, "code", family
        return text, "decoded", encoding

    def _iter_token_positions(self, text: str):
        """Yield ``(token, kind, line, start_col, end_col)`` for ``text``.

        ``line`` is 1-based; ``start_col`` is the 0-based column of the first
        character and ``end_col`` is the exclusive column just past the last
        (so ``end_col - start_col`` is the token length). Words are always
        emitted; single non-space characters are emitted too when
        :attr:`index_chars` is set (making the registry a genuine
        word/character index).
        """
        for line_no, line in enumerate(text.split("\n"), start=1):
            for m in _WORD_RE.finditer(line):
                yield m.group(0).lower(), "word", line_no, m.start(), m.end()
            if self.index_chars:
                for col, ch in enumerate(line):
                    if ch.isspace():
                        continue
                    yield ch, "char", line_no, col, col + 1

    def concord_text(self, text: str) -> List[Dict[str, Any]]:
        """Tokenize ``text`` into per-occurrence concordance rows (Database 1)."""
        rows: List[Dict[str, Any]] = []
        for token, kind, line, start, end in self._iter_token_positions(text):
            rows.append(
                {
                    "token": token,
                    "token_kind": kind,
                    "line": line,
                    "start_col": start,
                    "end_col": end,
                }
            )
        return rows

    # ==================================================================
    # Database-1 grep sweep (structural / forensic detail extraction)
    # ==================================================================
    # Cap the match text stored per hit so the table stays compact even when a
    # pattern matches a very long line (a minified bundle, a base64 asset).
    GREP_MATCH_TEXT_CAP = 240

    @classmethod
    def grep_pattern_catalog(cls) -> List[Dict[str, Any]]:
        """The static catalogue of grep patterns (dimension table for DB 1).

        One row per pattern with a 1-based ``pattern_id`` matching the order the
        battery runs in, its ``category``, whether it flags sensitive content,
        a human description and the source regex string.
        """
        return [
            {
                "pattern_id": i + 1,
                "pattern_name": name,
                "category": category,
                "is_sensitive": int(sensitive),
                "description": desc,
                "regex": rx,
            }
            for i, (name, category, sensitive, desc, rx) in enumerate(_GREP_SPECS)
        ]

    def grep_file(self, text: str) -> List[Dict[str, Any]]:
        """Run the grep battery over ``text`` line by line (Database 1).

        Returns one row per match: ``pattern_name``, ``category``,
        ``is_sensitive``, 1-based ``line``, 0-based ``start_col`` / exclusive
        ``end_col`` and the (capped) ``match_text`` -- the columns a
        ``grep -n -b -o`` pass would give, for every registered pattern. The
        battery is line-oriented, so ``^`` anchors mean line start and each hit
        has a real position. Per-file, per-pattern hits are capped by
        :attr:`grep_max_matches_per_pattern` to bound pathological files.
        """
        if not self.enable_grep or not text:
            return []
        cap = self.grep_max_matches_per_pattern or 0
        text_cap = self.GREP_MATCH_TEXT_CAP
        rows: List[Dict[str, Any]] = []
        counts: Dict[str, int] = {}
        for line_no, line in enumerate(text.split("\n"), start=1):
            if not line:
                continue
            for name, category, sensitive, pattern in _GREP_PATTERNS:
                if cap and counts.get(name, 0) >= cap:
                    continue
                for m in pattern.finditer(line):
                    matched = m.group(0)
                    if not matched:
                        continue
                    if cap and counts.get(name, 0) >= cap:
                        break
                    counts[name] = counts.get(name, 0) + 1
                    rows.append(
                        {
                            "pattern_name": name,
                            "category": category,
                            "is_sensitive": int(sensitive),
                            "line": line_no,
                            "start_col": m.start(),
                            "end_col": m.end(),
                            "match_text": matched[:text_cap],
                        }
                    )
        return rows

    # ==================================================================
    # Database-1 language-aware construct sweep (per-language grammar)
    # ==================================================================
    @classmethod
    def language_for_ext(cls, ext: Optional[str]) -> Optional[str]:
        """Return the programming language a file suffix belongs to, or ``None``.

        ``ext`` is the last-component suffix (with or without a leading dot);
        the mapping is the deliberate 1:1 :data:`_LANGUAGE_EXTS` table, so an
        ambiguous tail resolves to its documented default language."""
        if not ext:
            return None
        ext = ext.lower()
        if not ext.startswith("."):
            ext = "." + ext
        return _EXT_TO_LANGUAGE.get(ext)

    @classmethod
    def languages(cls) -> Tuple[str, ...]:
        """All languages the construct sweep recognizes, in catalogue order."""
        return tuple(lang for lang, _specs in _LANG_SPECS)

    @classmethod
    def language_construct_catalog(cls) -> List[Dict[str, Any]]:
        """Static catalogue of language constructs (dimension table for DB 1).

        One row per ``(language, construct)`` with a 1-based global
        ``construct_id`` matching the order the batteries run in, the
        ``language``, the ``construct_name`` (unique within its language), its
        ``kind``, a human ``description`` and the source ``regex``.
        """
        rows: List[Dict[str, Any]] = []
        cid = 0
        for lang, specs in _LANG_SPECS:
            for cname, kind, desc, rx in specs:
                cid += 1
                rows.append(
                    {
                        "construct_id": cid,
                        "language": lang,
                        "construct_name": cname,
                        "kind": kind,
                        "description": desc,
                        "regex": rx,
                    }
                )
        return rows

    def lang_scan(self, text: str, ext: Optional[str]) -> List[Dict[str, Any]]:
        """Run the construct battery for ``ext``'s language over ``text``.

        Resolves ``ext`` to a language (returns ``[]`` when the extension is not
        a recognised programming-language suffix), then runs only that
        language's construct battery line by line. Each row carries the
        ``language``, ``construct_name``, ``kind``, 1-based ``line``, 0-based
        ``start_col`` / exclusive ``end_col`` and the (capped) ``match_text`` --
        the same positional shape as :meth:`grep_file`. Per-file, per-construct
        hits are capped by :attr:`grep_max_matches_per_pattern`.
        """
        if not self.enable_lang_scan or not text:
            return []
        language = self.language_for_ext(ext)
        if language is None:
            return []
        patterns = _LANG_PATTERNS.get(language)
        if not patterns:
            return []
        cap = self.grep_max_matches_per_pattern or 0
        text_cap = self.GREP_MATCH_TEXT_CAP
        rows: List[Dict[str, Any]] = []
        counts: Dict[str, int] = {}
        for line_no, line in enumerate(text.split("\n"), start=1):
            if not line:
                continue
            for cname, kind, pattern in patterns:
                if cap and counts.get(cname, 0) >= cap:
                    continue
                for m in pattern.finditer(line):
                    matched = m.group(0)
                    if not matched:
                        continue
                    if cap and counts.get(cname, 0) >= cap:
                        break
                    counts[cname] = counts.get(cname, 0) + 1
                    rows.append(
                        {
                            "language": language,
                            "construct_name": cname,
                            "kind": kind,
                            "line": line_no,
                            "start_col": m.start(),
                            "end_col": m.end(),
                            "match_text": matched[:text_cap],
                        }
                    )
        return rows

    # ==================================================================
    # Part-A static metrics (Database 2 source)
    # ==================================================================
    @staticmethod
    def _magic_family(raw: bytes) -> str:
        """Coarse magic-byte family for the A1 extension/content cross-check."""
        if raw[:5] == b"%PDF-":
            return "pdf"
        if raw[:2] == b"PK":
            return "zip"
        if raw[:4] == b"{\\rt":
            return "rtf"
        if raw[:2] == b"\xd0\xcf":
            return "ole"
        if raw[:2] == b"%!":
            return "postscript"
        head = raw[:512].lstrip().lower()
        if head[:5] == b"<?xml" or head[:5] == b"<html" or head[:9] == b"<!doctype":
            return "xml_html"
        if raw[:4] in (b"AT&T",) or raw[:4] == b"\x41\x54\x26\x54":
            return "djvu"
        return "text_or_other"

    @staticmethod
    def _ext_family(ext: str) -> str:
        ext = ext.lower()
        if ext in _PDF_EXTS:
            return "pdf"
        if ext in _OOXML_WORD_EXTS or ext in _ODF_EXTS or ext in _EPUB_ZIP_EXTS:
            return "zip"
        if ext in _RTF_EXTS:
            return "rtf"
        if ext in _HTML_EXTS or ext in _MUSICXML_EXTS:
            return "xml_html"
        if ext in _PS_EXTS:
            return "postscript"
        if ext in _DJVU_EXTS:
            return "djvu"
        if ext == ".doc":
            return "ole"
        return "text_or_other"

    def _a1_container(self, path: Path, ext: str, raw: bytes) -> Dict[str, Any]:
        magic = self._magic_family(raw)
        import mimetypes

        mime, _ = mimetypes.guess_type(path.name)
        info: Dict[str, Any] = {
            "file_size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "md5": hashlib.md5(raw).hexdigest(),
            "magic_family": magic,
            "mime_type": mime,
            "ext_matches_magic": magic == self._ext_family(ext),
            "entropy": _shannon_entropy(raw[: 1 << 20]),
            "format_version": None,
            "encrypted": False,
            "embedded_file_count": 0,
            "compression_ratio": None,
            "object_counts": {},
            "incremental_updates": 0,
        }
        if magic == "pdf":
            m = re.match(rb"%PDF-(\d+\.\d+)", raw[:16])
            if m:
                info["format_version"] = "PDF-" + m.group(1).decode("ascii")
            info["encrypted"] = b"/Encrypt" in raw
            info["incremental_updates"] = max(0, raw.count(b"%%EOF") - 1)
            info["object_counts"] = {
                "pages": len(re.findall(rb"/Type\s*/Page\b(?!s)", raw)),
                "streams": raw.count(b"stream"),
                "fonts": raw.count(b"/Font"),
                "images": raw.count(b"/Image") + raw.count(b"/XObject"),
                "annotations": raw.count(b"/Annot"),
                "objects": len(re.findall(rb"\b\d+\s+\d+\s+obj\b", raw)),
            }
            info["linearized"] = b"/Linearized" in raw[:2048]
        elif magic == "zip":
            try:
                with zipfile.ZipFile(path) as z:
                    infos = z.infolist()
                    stored = sum(i.compress_size for i in infos) or 0
                    uncompressed = sum(i.file_size for i in infos) or 0
                    info["embedded_file_count"] = len(infos)
                    info["compression_ratio"] = (
                        round(uncompressed / stored, 3) if stored else None
                    )
                    info["encrypted"] = any(i.flag_bits & 0x1 for i in infos)
                    info["object_counts"] = {"members": len(infos)}
                    if ext in _OOXML_WORD_EXTS:
                        info["format_version"] = "OOXML"
                    elif ext in _EPUB_ZIP_EXTS:
                        info["format_version"] = "EPUB"
                    elif ext in _ODF_EXTS:
                        info["format_version"] = "ODF"
            except (zipfile.BadZipFile, OSError):
                pass
        return info

    def _a2_active_content(
        self, path: Path, ext: str, raw: bytes, text: str, dpf_id: int
    ) -> Dict[str, Any]:
        summary: Dict[str, Any] = {
            "pdf_flags": {},
            "macro_present": False,
            "dde_present": bool(re.search(rb"DDE(?:AUTO)?\b", raw)),
            "url_count": 0,
            "ip_count": 0,
            "domains": [],
        }
        if self._magic_family(raw) == "pdf":
            for name, token, category in _PDF_KEYWORD_FLAGS:
                count = raw.count(token)
                if count:
                    summary["pdf_flags"][name] = count
                    self.document_keyword_flags_table.append(
                        {
                            "flag_id": self._next("flag"),
                            "document_parser_file_id": dpf_id,
                            "flag": name,
                            "category": category,
                            "count": count,
                        }
                    )
        if ext in _OOXML_WORD_EXTS or ext in _ODF_EXTS:
            try:
                with zipfile.ZipFile(path) as z:
                    names = z.namelist()
                    if any("vbaProject.bin" in n for n in names):
                        summary["macro_present"] = True
            except (zipfile.BadZipFile, OSError):
                pass
        urls = _ENTITY_PATTERNS["url"].findall(text)
        ips = _ENTITY_PATTERNS["ipv4"].findall(text)
        domains = sorted(
            {re.sub(r"^https?://", "", u).split("/")[0].lower() for u in urls}
        )
        summary["url_count"] = len(urls)
        summary["ip_count"] = len(ips)
        summary["domains"] = domains[:50]
        return summary

    def _a3_metadata(self, path: Path, ext: str, raw: bytes) -> Dict[str, Any]:
        meta: Dict[str, Any] = {"source": None, "fields": {}, "anomalies": []}
        if self._magic_family(raw) == "pdf":
            meta["source"] = "pdf_info"
            blob = raw.decode("latin-1", errors="replace")
            for key in ("Title", "Author", "Subject", "Creator", "Producer"):
                m = re.search(r"/%s\s*\(((?:[^()\\]|\\.)*)\)" % key, blob)
                if m:
                    meta["fields"][key.lower()] = m.group(1)
            for key in ("CreationDate", "ModDate"):
                m = re.search(r"/%s\s*\(([^)]*)\)" % key, blob)
                if m:
                    meta["fields"][key.lower()] = m.group(1)
            cd = meta["fields"].get("creationdate")
            md = meta["fields"].get("moddate")
            if cd and md and md < cd:
                meta["anomalies"].append("moddate_before_creationdate")
            meta["xmp_present"] = b"<x:xmpmeta" in raw
            meta["pdfa_id"] = b"pdfaid:part" in raw
        elif ext in _OOXML_WORD_EXTS:
            meta["source"] = "ooxml"
            try:
                with zipfile.ZipFile(path) as z:
                    names = set(z.namelist())
                    if "docProps/core.xml" in names:
                        root = ET.fromstring(z.read("docProps/core.xml"))
                        for el in root.iter():
                            tag = _localname(el.tag)
                            if el.text and tag in (
                                "creator",
                                "lastModifiedBy",
                                "created",
                                "modified",
                                "revision",
                                "title",
                                "subject",
                                "keywords",
                            ):
                                meta["fields"][tag] = el.text.strip()
                    if "docProps/app.xml" in names:
                        root = ET.fromstring(z.read("docProps/app.xml"))
                        for el in root.iter():
                            tag = _localname(el.tag)
                            if el.text and tag in (
                                "Application",
                                "Words",
                                "Pages",
                                "Characters",
                                "Lines",
                                "Paragraphs",
                                "TotalTime",
                            ):
                                meta["fields"][tag.lower()] = el.text.strip()
            except (zipfile.BadZipFile, OSError, ET.ParseError):
                pass
            created = meta["fields"].get("created", "")
            modified = meta["fields"].get("modified", "")
            if created and modified and modified < created:
                meta["anomalies"].append("modified_before_created")
        return meta

    def _extract_fonts_pdf(self, path: Path) -> List[Dict[str, Any]]:
        """A5 fonts: real when pypdf is installed, else an empty list (honest)."""
        try:
            from pypdf import PdfReader
        except Exception:
            return []
        try:
            reader = PdfReader(str(path))
        except Exception:
            return []
        fonts: List[Dict[str, Any]] = []
        seen = set()
        for page in getattr(reader, "pages", []):
            try:
                res = page.get("/Resources")
                font_dict = res.get("/Font") if res else None
            except Exception:
                font_dict = None
            if not font_dict:
                continue
            try:
                items = font_dict.items()
            except Exception:
                continue
            for _, ref in items:
                try:
                    fobj = ref.get_object()
                    base = str(fobj.get("/BaseFont", ""))
                    subtype = str(fobj.get("/Subtype", ""))
                    encoding = str(fobj.get("/Encoding", ""))
                except Exception:
                    continue
                if base in seen:
                    continue
                seen.add(base)
                base_clean = base.lstrip("/")
                subset = (
                    base_clean[:7] if re.match(r"^[A-Z]{6}\+", base_clean) else None
                )
                fonts.append(
                    {
                        "font_name": base_clean,
                        "subtype": subtype.lstrip("/"),
                        "embedded": bool(
                            fobj.get("/FontDescriptor")
                            if hasattr(fobj, "get")
                            else False
                        ),
                        "subset_prefix": subset,
                        "encoding": encoding.lstrip("/") or None,
                    }
                )
        return fonts

    @staticmethod
    def _text_quality(text: str) -> Dict[str, Any]:
        n = len(text) or 1
        fffd = text.count("�")
        pua = sum(
            1
            for ch in text
            if 0xE000 <= ord(ch) <= 0xF8FF
            or 0xF0000 <= ord(ch) <= 0xFFFFD
            or 0x100000 <= ord(ch) <= 0x10FFFD
        )
        nonprint = sum(
            1
            for ch in text
            if unicodedata.category(ch).startswith("C") and ch not in "\n\t\r"
        )
        return {
            "replacement_char_ratio": round(fffd / n, 5),
            "pua_ratio": round(pua / n, 5),
            "nonprintable_ratio": round(nonprint / n, 5),
        }

    def _a5_text_layer(self, text: str, word_tokens: List[str]) -> Dict[str, Any]:
        lines = text.split("\n")
        sentences = [s for s in _SENTENCE_SPLIT_RE.split(text) if s.strip()]
        paragraphs = [p for p in _PARAGRAPH_SPLIT_RE.split(text) if p.strip()]
        script = _dominant_script(text)
        info = {
            "char_count": len(text),
            "word_count": len(word_tokens),
            "line_count": len(lines),
            "sentence_count": max(len(sentences), 1 if text.strip() else 0),
            "paragraph_count": len(paragraphs),
            "dominant_script": script,
            "language_guess": "unknown",
        }
        info.update(self._text_quality(text))
        return info

    def _a8_layout(self, text: str) -> Dict[str, Any]:
        headings: Dict[str, int] = {}
        list_items = 0
        for line in text.split("\n"):
            s = line.strip()
            hm = re.match(r"^(#{1,6})\s+\S", s)
            if hm:
                lvl = "h%d" % len(hm.group(1))
                headings[lvl] = headings.get(lvl, 0) + 1
            elif re.match(r"^([-*+]|\d+[.)])\s+\S", s):
                list_items += 1
        return {
            "heading_counts": headings,
            "heading_levels": len(headings),
            "list_items": list_items,
            "has_toc": bool(
                re.search(r"(?im)^\s*(table of contents|contents)\s*$", text)
            ),
        }

    @staticmethod
    def _a9_tables(text: str) -> Dict[str, Any]:
        md_tables = len(re.findall(r"(?m)^\s*\|.*\|\s*$\n\s*\|[ :\-|]+\|\s*$", text))
        html_tables = len(re.findall(r"(?i)<table\b", text))
        return {"table_count": md_tables + html_tables}

    def _a11_entities(self, text: str, dpf_id: int) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        valid_counts: Dict[str, int] = {}
        seen: set = set()
        for category, pattern in _ENTITY_PATTERNS.items():
            for m in pattern.finditer(text):
                value = m.group(0).strip()
                if not value or (category, value) in seen:
                    continue
                seen.add((category, value))
                valid = _entity_valid(category, value)
                # Checksummed categories: only keep the ones that validate, to
                # keep false positives (e.g. any 13-19 digit run) out of the DB.
                if category in _CHECKSUMMED and not valid:
                    continue
                counts[category] = counts.get(category, 0) + 1
                if valid:
                    valid_counts[category] = valid_counts.get(category, 0) + 1
                if len(seen) <= 5000:
                    self.document_entities_table.append(
                        {
                            "entity_id": self._next("entity"),
                            "document_parser_file_id": dpf_id,
                            "category": category,
                            "value": value[:512],
                            "valid": valid,
                        }
                    )
        return {"counts": counts, "valid_counts": valid_counts, "total": len(seen)}

    def _a12_lexical(
        self, word_tokens: List[str], sentence_count: int, char_count: int
    ) -> Dict[str, Any]:
        words = [w for w in word_tokens if any(c.isalpha() for c in w)]
        n = len(words) or 0
        types = set(words)
        syllables = sum(_count_syllables(w) for w in words)
        complex_words = sum(1 for w in words if _count_syllables(w) >= 3)
        stop = sum(1 for w in words if w in _STOPWORDS)
        alpha_chars = sum(len(w) for w in words)
        stats = {
            "token_count": len(word_tokens),
            "type_count": len(types),
            "type_token_ratio": round(len(types) / n, 4) if n else 0.0,
            "avg_word_length": round(alpha_chars / n, 3) if n else 0.0,
            "avg_sentence_length": (
                round(n / sentence_count, 3) if sentence_count else 0.0
            ),
            "syllables_per_word": round(syllables / n, 3) if n else 0.0,
            "stopword_ratio": round(stop / n, 4) if n else 0.0,
            "complex_word_ratio": round(complex_words / n, 4) if n else 0.0,
        }
        stats["readability"] = _readability_suite(
            n, sentence_count, syllables, alpha_chars, complex_words
        )
        # Top unigrams (content words only), a compact keyword signal (A12).
        freq: Dict[str, int] = {}
        for w in words:
            if w in _STOPWORDS or len(w) < 3:
                continue
            freq[w] = freq.get(w, 0) + 1
        stats["top_terms"] = sorted(freq.items(), key=lambda kv: -kv[1])[:20]
        return stats

    def _a15_chunks(
        self, text: str, dpf_id: int, target_tokens: int = 256, overlap: int = 32
    ) -> Dict[str, Any]:
        # Token windows over word matches (with char offsets so we can test
        # mid-sentence boundaries). Real fixed-window chunker with overlap.
        matches = list(_WORD_RE.finditer(text))
        if not matches:
            return {"chunk_count": 0, "distribution": {}}
        step = max(1, target_tokens - overlap)
        token_counts: List[int] = []
        ordinal = 0
        i = 0
        while i < len(matches):
            window = matches[i : i + target_tokens]
            if not window:
                break
            start = window[0].start()
            end = window[-1].end()
            chunk_text = text[start:end]
            starts_mid = start > 0 and not text[start - 1].isspace()
            ends_mid = end < len(text) and text[end : end + 1] not in (
                "",
                ".",
                "!",
                "?",
                "\n",
            )
            ordinal += 1
            token_counts.append(len(window))
            self.document_chunks_table.append(
                {
                    "chunk_id": self._next("chunk"),
                    "document_parser_file_id": dpf_id,
                    "ordinal": ordinal,
                    "token_count": len(window),
                    "char_count": len(chunk_text),
                    "starts_mid_sentence": starts_mid,
                    "ends_mid_sentence": ends_mid,
                }
            )
            i += step
        token_counts.sort()

        def _pct(p: float) -> int:
            if not token_counts:
                return 0
            idx = min(len(token_counts) - 1, int(p * (len(token_counts) - 1)))
            return token_counts[idx]

        return {
            "chunk_count": ordinal,
            "orphan_chunks": sum(1 for c in token_counts if c < target_tokens // 4),
            "distribution": {
                "min": token_counts[0],
                "p50": _pct(0.5),
                "p95": _pct(0.95),
                "max": token_counts[-1],
            },
        }

    def _a14_forensics(
        self, raw: bytes, a1: Dict[str, Any], a3: Dict[str, Any]
    ) -> Dict[str, Any]:
        return {
            "incremental_saves": a1.get("incremental_updates", 0),
            "metadata_anomalies": a3.get("anomalies", []),
            "standards": {
                "pdf_a": b"pdfaid:part" in raw,
                "pdf_ua": b"pdfuaid:part" in raw,
                "pdf_x": b"GTS_PDFXVersion" in raw,
            },
            "tamper_suspected": bool(a3.get("anomalies")),
        }

    def _metrics_for_file(
        self,
        dpf_id: int,
        path: Path,
        ext: str,
        raw: bytes,
        text: str,
        conv: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Compute the full Part-A static metric row (+ children) for one file."""
        word_tokens = [m.group(0).lower() for m in _WORD_RE.finditer(text)]

        a1 = self._a1_container(path, ext, raw)
        a2 = self._a2_active_content(path, ext, raw, text, dpf_id)
        a3 = self._a3_metadata(path, ext, raw)
        a5 = self._a5_text_layer(text, word_tokens)
        a8 = self._a8_layout(text)
        a9 = self._a9_tables(text)
        a11 = self._a11_entities(text, dpf_id)
        a12 = self._a12_lexical(word_tokens, a5["sentence_count"], a5["char_count"])
        a15 = self._a15_chunks(text, dpf_id)
        a14 = self._a14_forensics(raw, a1, a3)

        # A4 page geometry (best-effort; pages from A1 for PDF, else 1 when text).
        pdf_pages = a1.get("object_counts", {}).get("pages", 0)
        page_count = pdf_pages or (1 if text.strip() else 0)
        born_digital = bool(text.strip())
        a4 = {
            "page_count": page_count,
            "born_digital": born_digital,
            "scanned_suspected": (ext in _PDF_EXTS and not born_digital),
        }
        # A10 forms from the A2 PDF flags.
        a10 = {
            "acroform": "acroform" in a2["pdf_flags"],
            "xfa": "xfa" in a2["pdf_flags"],
        }

        # A5 fonts (optional backend).
        for f in self._extract_fonts_pdf(path) if ext in _PDF_EXTS else []:
            self.document_fonts_table.append(
                {"font_id": self._next("font"), "document_parser_file_id": dpf_id, **f}
            )

        # A12 readability suite -> normalized child rows.
        for formula, score in a12["readability"].items():
            self.document_readability_table.append(
                {
                    "read_id": self._next("read"),
                    "document_parser_file_id": dpf_id,
                    "formula": formula,
                    "score": score,
                }
            )

        sections = {
            "A1_container": a1,
            "A2_active_content": a2,
            "A3_metadata": a3,
            "A4_page_geometry": a4,
            "A5_text_layer": a5,
            "A8_layout": a8,
            "A9_tables": a9,
            "A10_forms": a10,
            "A11_entities": a11,
            "A12_lexical": a12,
            "A14_forensics": a14,
            "A15_chunking": a15,
        }
        row = {
            "metric_id": self._next("metric"),
            "document_parser_file_id": dpf_id,
            # A1
            "file_size": a1["file_size"],
            "sha256": a1["sha256"],
            "md5": a1["md5"],
            "magic_family": a1["magic_family"],
            "mime_type": a1["mime_type"],
            "ext_matches_magic": a1["ext_matches_magic"],
            "format_version": a1["format_version"],
            "encrypted": a1["encrypted"],
            "entropy": a1["entropy"],
            "embedded_file_count": a1["embedded_file_count"],
            # A2
            "has_javascript": bool(
                a2["pdf_flags"].get("javascript") or a2["pdf_flags"].get("js")
            ),
            "has_openaction": bool(a2["pdf_flags"].get("openaction")),
            "macro_present": a2["macro_present"],
            "url_count": a2["url_count"],
            # A4
            "page_count": a4["page_count"],
            "born_digital": a4["born_digital"],
            # A5
            "char_count": a5["char_count"],
            "word_count": a5["word_count"],
            "line_count": a5["line_count"],
            "sentence_count": a5["sentence_count"],
            "paragraph_count": a5["paragraph_count"],
            "dominant_script": a5["dominant_script"],
            "replacement_char_ratio": a5["replacement_char_ratio"],
            # A9 / A11 / A12 / A15 headline scalars
            "table_count": a9["table_count"],
            "entity_total": a11["total"],
            "token_count": a12["token_count"],
            "type_token_ratio": a12["type_token_ratio"],
            "flesch_reading_ease": a12["readability"]["flesch_reading_ease"],
            "flesch_kincaid_grade": a12["readability"]["flesch_kincaid_grade"],
            "chunk_count": a15["chunk_count"],
            # provenance
            "conversion_status": conv.get("status"),
            "conversion_model": conv.get("model"),
            "sections_json": sections,
        }
        self.document_metrics_table.append(row)
        return row

    # ==================================================================
    # Public API
    # ==================================================================
    def analyze(self) -> Dict[str, List[Dict[str, Any]]]:
        """Convert + deep-parse every routed document file into the metric tables."""
        exts = self._known_exts()
        for local_fid, path in enumerate(self.file_paths, start=1):
            ext = self._true_ext(path)
            if ext not in exts:
                continue
            try:
                raw = path.read_bytes() if path.exists() else b""
            except OSError:
                raw = b""
            conv = (
                self._converter(path, ext, target="txt")
                if raw
                else {
                    "status": "error",
                    "text": "",
                    "model": None,
                }
            )
            text = conv.get("text") or ""
            dpf_id = self._next("file")
            self._text_cache[dpf_id] = text
            self.document_parser_files_table.append(
                {
                    "document_parser_file_id": dpf_id,
                    "file_name": path.name,
                    "extension": ext.lstrip("."),
                    "size_bytes": len(raw) if raw else None,
                    "analysis_status": conv.get("status", "unknown"),
                    "converter_model": conv.get("model"),
                    "extracted_chars": len(text),
                    "file_id": local_fid,
                }
            )
            try:
                self._metrics_for_file(dpf_id, path, ext, raw, text, conv)
            except Exception as exc:  # metrics must never abort the plane
                self.document_metrics_table.append(
                    {
                        "metric_id": self._next("metric"),
                        "document_parser_file_id": dpf_id,
                        "conversion_status": "metrics_error",
                        "sections_json": {"error": str(exc)},
                    }
                )

        result = self.get_tables()
        if self.dump_file_type != "memory":
            self._export(result)
        return result

    def get_tables(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            "document_parser_files_table": self.document_parser_files_table,
            "document_metrics_table": self.document_metrics_table,
            "document_keyword_flags_table": self.document_keyword_flags_table,
            "document_entities_table": self.document_entities_table,
            "document_readability_table": self.document_readability_table,
            "document_fonts_table": self.document_fonts_table,
            "document_chunks_table": self.document_chunks_table,
            "document_metric_catalog_table": self.document_metric_catalog_table,
            "document_parser_file_index": self.document_parser_file_index,
        }

    # ==================================================================
    # Database 3 -- dynamic layer (Part B #368-458): agent + code loop
    # ==================================================================
    #: Default extraction schemas per document type (B1 selects, B2 fills).
    #: (name, type, required) tuples; kept small and real so the deterministic
    #: validators (arithmetic/date/schema) have something concrete to check.
    _DYNAMIC_SCHEMAS: Dict[str, Tuple[Tuple[str, str, bool], ...]] = {
        "invoice": (
            ("invoice_number", "string", True),
            ("issue_date", "date", True),
            ("due_date", "date", False),
            ("vendor_name", "string", False),
            ("subtotal", "money", False),
            ("tax", "money", False),
            ("total", "money", True),
        ),
        "receipt": (
            ("merchant", "string", False),
            ("date", "date", False),
            ("total", "money", True),
        ),
        "contract": (
            ("party_a", "string", False),
            ("party_b", "string", False),
            ("effective_date", "date", False),
            ("expiry_date", "date", False),
            ("governing_law", "string", False),
        ),
        "bank_statement": (
            ("account_number", "string", False),
            ("statement_date", "date", False),
            ("closing_balance", "money", False),
        ),
        "resume": (
            ("name", "string", False),
            ("email", "email", False),
            ("phone", "phone", False),
        ),
        "research_paper": (
            ("title", "string", False),
            ("doi", "string", False),
        ),
        "lab_report": (
            ("patient", "string", False),
            ("collection_date", "date", False),
        ),
    }
    #: Fallback schema when the type is unknown -- still extracts the common
    #: high-value entities so the loop produces real rows for any document.
    _DYNAMIC_SCHEMA_DEFAULT: Tuple[Tuple[str, str, bool], ...] = (
        ("date", "date", False),
        ("email", "email", False),
        ("total", "money", False),
    )

    @classmethod
    def select_schema(cls, doc_type: str) -> List[Any]:
        """B1 pipeline+schema selection: map a document type to its FieldSpecs."""
        from .dynamic_engine import FieldSpec

        specs = cls._DYNAMIC_SCHEMAS.get(doc_type, cls._DYNAMIC_SCHEMA_DEFAULT)
        return [FieldSpec(name=n, type=t, required=r) for (n, t, r) in specs]

    def _build_doc_inputs(self, schema_by_type: bool = True) -> List[Any]:
        """Turn the analyzed per-file state into dynamic_engine.DocInput rows."""
        from .dynamic_engine import DocInput, HeuristicRunner

        # index the static children by document_parser_file_id
        metrics_by_dpf: Dict[int, Dict[str, Any]] = {
            m["document_parser_file_id"]: m for m in self.document_metrics_table
        }
        entities_by_dpf: Dict[int, List[Dict[str, Any]]] = {}
        for e in self.document_entities_table:
            entities_by_dpf.setdefault(e["document_parser_file_id"], []).append(e)

        docs: List[Any] = []
        classifier = HeuristicRunner()
        for f in self.document_parser_files_table:
            dpf_id = f["document_parser_file_id"]
            text = self._text_cache.get(dpf_id, "")
            metrics = metrics_by_dpf.get(dpf_id, {})
            doc = DocInput(
                file_id=f.get("file_id", dpf_id),
                name=f.get("file_name", ""),
                text=text,
                doc_parser_file_id=dpf_id,
                metrics=metrics,
                entities=entities_by_dpf.get(dpf_id, []),
                page_count=int(metrics.get("page_count") or 1),
            )
            if schema_by_type:
                guess = classifier.classify(doc)["doc_type"]
                doc.schema = self.select_schema(guess)
            docs.append(doc)
        return docs

    def dynamic_analyze(
        self,
        registry: Optional[Any] = None,
        roster: Optional[Any] = None,
        *,
        agents_include: Optional[Iterable[str]] = None,
        agents_exclude: Optional[Iterable[str]] = None,
        confidence_threshold: float = 0.7,
        max_repairs: int = 2,
        self_consistency_n: int = 1,
        reference_data: Optional[Dict[str, Any]] = None,
        discover_desktop: bool = False,
        project_dir: Optional[str] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Run the Part-B dynamic layer over the already-analyzed documents.

        Builds one :class:`~file_analyzer.document.dynamic_engine.DocInput` per analyzed
        file (extracted text + Part-A metrics + rule-based entities), selects a
        target schema by type (B1), then runs the agent+code loop
        (classify -> extract -> validate -> repair -> understand -> reason ->
        ground -> escalate). ``registry`` is a
        :class:`~file_analyzer.document.agent_mcp.AgentRegistry`; when a stage has no
        reachable provider it falls back to the deterministic
        :class:`~file_analyzer.document.dynamic_engine.HeuristicRunner`, so this method
        always produces real rows. Requires :meth:`analyze` to have run.

        When ``discover_desktop`` is set and no ``registry`` was passed, the
        MCP servers already configured in the Claude desktop app / ``claude``
        CLI / a project ``.mcp.json`` are discovered and used as providers over
        MCP (stdio or Streamable HTTP), so no separate API key is needed.

        ``agents_include`` / ``agents_exclude`` narrow the resolved registry to
        an allow-list (include, when non-empty) minus a deny-list (exclude) of
        provider names, matched case-insensitively; unknown names are ignored so
        the filter stays soft. They have no effect when no registry is in play.
        """
        from .agent_mcp import AgentRegistry
        from .dynamic_engine import DynamicAnalysisEngine, Validators

        if registry is None and discover_desktop:
            registry = AgentRegistry.from_desktop(project_dir=project_dir)
        if (agents_include or agents_exclude) and hasattr(registry, "select"):
            registry = registry.select(agents_include, agents_exclude)

        docs = self._build_doc_inputs()
        engine = DynamicAnalysisEngine(
            registry=registry,
            roster=roster,
            confidence_threshold=confidence_threshold,
            max_repairs=max_repairs,
            self_consistency_n=self_consistency_n,
            validators=Validators(reference_data=reference_data),
        )
        self.dynamic_tables = engine.run(docs)
        return self.dynamic_tables

    def get_dynamic_tables(self) -> Dict[str, List[Dict[str, Any]]]:
        """Return the Database-3 tables (empty until :meth:`dynamic_analyze`)."""
        if self.dynamic_tables:
            return self.dynamic_tables
        # provide the catalogue even if the loop has not been run, so the
        # schema/enumeration is always available to the DB generator.
        from .dynamic_engine import DynamicAnalysisEngine

        return DynamicAnalysisEngine().get_tables()

    # ==================================================================
    # Part C -- evaluation layer (Database 4)
    # ==================================================================
    def evaluate(
        self,
        cases: Optional[Sequence[Any]] = None,
        registry: Optional[Any] = None,
        *,
        judge: str = "",
        agents_include: Optional[Iterable[str]] = None,
        agents_exclude: Optional[Iterable[str]] = None,
        include_pipeline_cases: bool = True,
        discover_desktop: bool = False,
        project_dir: Optional[str] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Run the Part-C evaluation layer and build the Database-4 tables.

        ``cases`` is a sequence of
        :class:`~file_analyzer.document.evaluation_engine.EvalCase` (text/OCR, table,
        formula, layout, reading-order, extraction, retrieval, RAG, PII,
        calibration, KPI, drift). Deterministic families are scored directly
        from :mod:`~file_analyzer.document.evaluation_metrics`; the C3 RAG family (the
        Ragas metrics) is judged by the ``judge`` provider over the same
        multi-agent transport as Part B, falling back to a deterministic
        heuristic judge when no provider is reachable.

        When ``include_pipeline_cases`` is set and a Part-B run has already
        populated :attr:`dynamic_tables`, real calibration + operational-KPI
        cases are derived from that run so Database 4 has genuine rows even with
        no external gold set. ``discover_desktop`` resolves a judge from the
        desktop/CLI-configured MCP servers when no ``registry`` is passed.

        ``agents_include`` / ``agents_exclude`` narrow the resolved registry to
        an allow-list minus a deny-list of provider names (case-insensitive,
        unknown names ignored), so the C3 RAG judge is picked only from the
        permitted providers. They have no effect when no registry is in play.
        """
        from .agent_mcp import AgentRegistry
        from .evaluation_engine import EvaluationEngine

        if registry is None and discover_desktop:
            registry = AgentRegistry.from_desktop(project_dir=project_dir)
        if (agents_include or agents_exclude) and hasattr(registry, "select"):
            registry = registry.select(agents_include, agents_exclude)

        all_cases: List[Any] = list(cases or [])
        if include_pipeline_cases and self.dynamic_tables:
            all_cases.extend(EvaluationEngine.from_dynamic_tables(self.dynamic_tables))

        engine = EvaluationEngine(registry=registry, judge=judge)
        self.evaluation_tables = engine.run(all_cases)
        return self.evaluation_tables

    def get_evaluation_tables(self) -> Dict[str, List[Dict[str, Any]]]:
        """Return the Database-4 tables (empty until :meth:`evaluate`)."""
        if self.evaluation_tables:
            return self.evaluation_tables
        # provide the catalogue even if nothing was scored, so the
        # schema/enumeration is always available to the DB generator.
        from .evaluation_engine import EvaluationEngine

        return EvaluationEngine().get_tables()

    # ==================================================================
    # Repository linkage (LOCAL file_id -> repository file_id + file index)
    # ==================================================================
    @staticmethod
    def _build_repo_index(
        repository_tables: Tuple[
            List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]
        ],
    ) -> Tuple[Dict[str, int], Dict[str, List[int]], Dict[int, List[int]]]:
        """Build the relpath / basename -> file_id lookups and the per-file
        repository *location* chain ``[root_folder_id, ..., file_id]`` (the key
        type Database 1 uses)."""
        folders, extensions, files = repository_tables
        ext_by_id = {e["extension_id"]: e["extension_name"] for e in extensions}
        folder_by_id = {f["folder_id"]: f["folder_name"] for f in folders}
        repo_by_relpath: Dict[str, int] = {}
        repo_by_basename: Dict[str, List[int]] = {}
        location_by_fid: Dict[int, List[int]] = {}
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
            # The RepositoryAnalyzer location is the folder chain; Database 1's
            # location key appends the file_id (root_folder_id, ..., file_id).
            location_by_fid[f["file_id"]] = list(location) + [f["file_id"]]
        return repo_by_relpath, repo_by_basename, location_by_fid

    @staticmethod
    def _match_repo_file(
        posix: str,
        name: str,
        repo_by_relpath: Dict[str, int],
        repo_by_basename: Dict[str, List[int]],
    ) -> Optional[int]:
        matched = None
        best_len = -1
        for rel, fid in repo_by_relpath.items():
            if posix == rel or posix.endswith("/" + rel):
                if len(rel) > best_len:
                    best_len = len(rel)
                    matched = fid
        if matched is None:
            cands = repo_by_basename.get(name, [])
            if len(cands) == 1:
                matched = cands[0]
        return matched

    def map_paths_to_locations(
        self,
        repository_tables: Tuple[
            List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]
        ],
        paths: List[Union[str, Path]],
    ) -> List[Optional[Dict[str, Any]]]:
        """For each path, return ``{file_id, location_ids, location_key}`` (or
        ``None`` when it cannot be matched to a repository file). ``location_key``
        is the ``/``-joined location chain used as Database 1's dict key."""
        by_rel, by_base, loc_by_fid = self._build_repo_index(repository_tables)
        out: List[Optional[Dict[str, Any]]] = []
        for p in paths:
            p = Path(p)
            fid = self._match_repo_file(p.as_posix(), p.name, by_rel, by_base)
            if fid is None:
                out.append(None)
                continue
            loc = loc_by_fid.get(fid, [fid])
            out.append(
                {
                    "file_id": fid,
                    "location_ids": loc,
                    "location_key": "/".join(str(x) for x in loc),
                }
            )
        return out

    def link_repository(
        self,
        repository_tables: Tuple[
            List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]
        ],
        analyzed_file_paths: Optional[List[Union[str, Path]]] = None,
    ) -> List[Dict[str, Any]]:
        repo_by_relpath, repo_by_basename, _loc = self._build_repo_index(
            repository_tables
        )
        analyzed = [Path(p) for p in (analyzed_file_paths or self.file_paths)]
        local_to_repo: Dict[int, Optional[int]] = {}
        for idx, p in enumerate(analyzed, start=1):
            local_to_repo[idx] = self._match_repo_file(
                p.as_posix(), p.name, repo_by_relpath, repo_by_basename
            )

        # Map each analyzer-local document file (its 1-based file_id) to its repo
        # file_id and build the file index bridging both the file census rows and
        # their metric rows into the repository.
        dpf_to_repo: Dict[int, Optional[int]] = {}
        self.document_parser_file_index.clear()
        for row in self.document_parser_files_table:
            repo_id = local_to_repo.get(row.get("file_id"))
            row["file_id"] = repo_id
            dpf_to_repo[row["document_parser_file_id"]] = repo_id
            if repo_id is not None:
                self.document_parser_file_index.append(
                    {
                        "dpfi_id": self._next("dpfi"),
                        "file_id": repo_id,
                        "entity_kind": self.KIND_FILE,
                        "entity_id": row["document_parser_file_id"],
                    }
                )
        # Stamp the repository file_id onto every metric row so Database 2 rows
        # join straight to file_details, and bridge them into the file index.
        for m in self.document_metrics_table:
            repo_id = dpf_to_repo.get(m.get("document_parser_file_id"))
            m["file_id"] = repo_id
            if repo_id is not None:
                self.document_parser_file_index.append(
                    {
                        "dpfi_id": self._next("dpfi"),
                        "file_id": repo_id,
                        "entity_kind": self.KIND_METRIC,
                        "entity_id": m["metric_id"],
                    }
                )
        return self.document_parser_file_index

    # ==================================================================
    # export
    # ==================================================================
    def _export(self, result: Dict[str, List[Dict[str, Any]]]) -> None:
        try:
            with open(self.dump_file_path, "w", encoding="utf-8") as fh:
                json.dump(result, fh, ensure_ascii=False, indent=2, default=str)
        except OSError as err:
            print(f"Warning: DocumentParser export failed: {err}")
