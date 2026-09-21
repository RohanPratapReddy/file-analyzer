# Shared plumbing for the hand-written (regex / heuristic) language analyzers.
#
# This is the non-tree-sitter analog of ``BaseTreeSitterAnalyzer``: it owns id
# allocation, symbol indexing, introspection rows and the two-pass ``analyze``
# driver, so each concrete language analyzer only has to implement the two
# hooks ``_register_types`` and ``_extract_entities`` with the *real* syntax of
# its own language. It deliberately contains NO per-language / per-paradigm
# parsing logic -- that lives, fully independent, in each ``<lang>_analyzer.py``.
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from .base_code_analyzer import BaseCodeAnalyzer


class RegexCodeAnalyzer(BaseCodeAnalyzer):
    """Base engine for grammar-free language analyzers.

    Subclasses set ``LANG_KEY`` / ``EXTENSIONS`` (and optionally the comment
    delimiters) and implement ``_register_types`` (pass 1, collect declared type
    names so cross-references resolve) and ``_extract_entities`` (pass 2, emit
    imports / variables / functions / classes for one file).
    """

    LANG_KEY: str = "generic"
    EXTENSIONS: Tuple[str, ...] = ()
    LINE_COMMENTS: Tuple[str, ...] = ("//",)
    BLOCK_COMMENTS: Tuple[Tuple[str, str], ...] = (("/*", "*/"),)
    STRING_DELIMS: Tuple[str, ...] = ('"', "'")

    def __init__(self, file_paths: Optional[List[Union[str, Path]]] = None,
                 dump_file_path: str = "code_analysis.json",
                 dump_file_type: str = "json", **kwargs):
        super().__init__(file_paths=file_paths, dump_file_path=dump_file_path,
                         dump_file_type=dump_file_type, language_name=self.LANG_KEY)
        self.extensions = list(self.EXTENSIONS)
        self.introspection_source = f"regex:{self.LANG_KEY}"
        self._emitted_class_rows: Dict[int, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Relational row builders (mirror BaseTreeSitterAnalyzer, parser-free).
    # ------------------------------------------------------------------
    def _add_import(self, file_id, import_name, import_source, alias=None):
        imp_id = self._import_counter
        self._import_counter += 1
        self.imports_table.append({
            "import_id": imp_id, "import_name": import_name,
            "import_source": import_source, "alias": alias,
        })
        self._record_symbol(file_id, "import", imp_id)
        return imp_id

    def _add_variable(self, file_id, name, value=None, scope="module",
                      is_imported=False, source_import_id=None):
        vid = self._var_counter
        self._var_counter += 1
        self.variables_table.append({
            "variable_id": vid, "variable_name": name, "variable_value": value,
            "scope": scope, "is_imported": is_imported,
            "source_import_id": source_import_id,
        })
        self._record_symbol(file_id, "variable", vid)
        return vid

    def _add_arg(self, name, arg_type=None, default_value=None):
        aid = self._arg_counter
        self._arg_counter += 1
        self.args_table.append({
            "args_id": aid, "args_name": name, "args_type": arg_type,
            "default_value": default_value, "permitted_values": None,
        })
        return aid

    def _add_output(self, output_type, description=None):
        oid = self._output_counter
        self._output_counter += 1
        self.outputs_table.append({
            "output_id": oid, "output_type": output_type, "description": description,
        })
        return oid

    def _add_function(self, file_id, name, arg_ids=None, output_ids=None,
                      class_id=None, description=None, forward=None,
                      backward=None, is_imported=False, source_import_id=None):
        fn_id = self._func_counter
        self._func_counter += 1
        lang = self.LANG_KEY
        self.functions_table.append({
            "function_id": fn_id, "function_name": name,
            "args_ids": arg_ids or [], "function_outputs_ids": output_ids or [],
            "class_id": class_id, "function_description": description,
            "function_forward_pass": forward if forward is not None else
                f"```pseudocode\n// {lang} forward pass: {name}\nRESULT = {name}(ARGS...)\nRETURN RESULT\n```",
            "function_backward_pass": backward if backward is not None else
                f"```pseudocode\n// {lang} backward pass: {name}\nPROPAGATE_GRADIENTS()\n```",
            "is_imported": is_imported, "source_import_id": source_import_id,
        })
        self._record_symbol(file_id, "function", fn_id)
        return fn_id

    def _register_class(self, name):
        """Pass-1: reserve a class id for a declared type name."""
        if name and name not in self._class_registry:
            self._class_registry[name] = self._class_counter
            self._class_counter += 1
        return self._class_registry.get(name)

    def _add_class(self, file_id, name, description=None, parent_ids=None,
                   method_ids=None, attr_ids=None, tensor_member_ids=None,
                   is_imported=False, source_import_id=None, introspect=True):
        cls_id = self._class_registry.get(name)
        if cls_id is None:
            cls_id = self._class_counter
            self._class_counter += 1
            if name:
                self._class_registry[name] = cls_id
        if cls_id in self._emitted_class_rows:
            row = self._emitted_class_rows[cls_id]

            def _union(dst, src):
                for x in src or []:
                    if x not in dst:
                        dst.append(x)

            _union(row["parent_class_ids"], parent_ids)
            _union(row["method_ids"], method_ids)
            _union(row["attr_ids"], attr_ids)
            _union(row["tensor_member_ids"], tensor_member_ids)
            if description and not row.get("class_description"):
                row["class_description"] = description
            return cls_id
        row = {
            "class_id": cls_id, "class_name": name, "class_description": description,
            "parent_class_ids": parent_ids or [], "method_ids": method_ids or [],
            "args_ids": [], "attr_ids": attr_ids or [],
            "tensor_member_ids": tensor_member_ids or [],
            "is_imported": is_imported, "source_import_id": source_import_id,
        }
        self.classes_table.append(row)
        self._emitted_class_rows[cls_id] = row
        self._record_symbol(file_id, "class/struct/interface", cls_id)
        if introspect:
            self.record_introspection_metadata(
                file_id=file_id, entity_id=cls_id, entity_type="class",
                inspection_source=self.introspection_source,
                structural_properties={"declared_fields": len(attr_ids or []),
                                       "declared_methods": len(method_ids or [])},
            )
        return cls_id

    # ------------------------------------------------------------------
    # Shared text utilities (comment/string aware, language-agnostic).
    # ------------------------------------------------------------------
    def _strip_comments(self, text: str) -> str:
        """Remove block and line comments while preserving newlines (so line
        based patterns keep working). String literals are NOT stripped."""
        out = []
        i, n = 0, len(text)
        line_cs = self.LINE_COMMENTS
        block_cs = self.BLOCK_COMMENTS
        delims = self.STRING_DELIMS
        while i < n:
            ch = text[i]
            # string literal: copy verbatim to closing delimiter
            if ch in delims:
                q = ch
                out.append(ch)
                i += 1
                while i < n:
                    c = text[i]
                    out.append(c)
                    if c == "\\" and i + 1 < n:
                        out.append(text[i + 1])
                        i += 2
                        continue
                    i += 1
                    if c == q:
                        break
                continue
            # block comment
            matched_block = False
            for op, cl in block_cs:
                if op and text.startswith(op, i):
                    j = text.find(cl, i + len(op))
                    if j == -1:
                        j = n
                    else:
                        j += len(cl)
                    # keep newlines inside the comment to preserve line numbers
                    out.append("".join(c if c == "\n" else " " for c in text[i:j]))
                    i = j
                    matched_block = True
                    break
            if matched_block:
                continue
            # line comment
            matched_line = False
            for lc in line_cs:
                if lc and text.startswith(lc, i):
                    j = text.find("\n", i)
                    if j == -1:
                        j = n
                    out.append(" " * (j - i))
                    i = j
                    matched_line = True
                    break
            if matched_line:
                continue
            out.append(ch)
            i += 1
        return "".join(out)

    @staticmethod
    def _split_top_level(s: str, sep: str = ",",
                         opens: str = "([{<", closes: str = ")]}>") -> List[str]:
        """Split ``s`` on ``sep`` only at bracket depth 0."""
        parts, buf, depth = [], [], 0
        instr = None
        for ch in s:
            if instr:
                buf.append(ch)
                if ch == instr:
                    instr = None
                continue
            if ch in ('"', "'"):
                instr = ch
                buf.append(ch)
                continue
            if ch in opens:
                depth += 1
            elif ch in closes:
                depth = max(0, depth - 1)
            if ch == sep and depth == 0:
                parts.append("".join(buf))
                buf = []
            else:
                buf.append(ch)
        if buf:
            parts.append("".join(buf))
        return [p.strip() for p in parts if p.strip()]

    @staticmethod
    def _find_matching(text: str, open_pos: int, opener: str = "{",
                       closer: str = "}") -> int:
        """Given the index of an opening bracket, return the index just past its
        matching close (string-literal aware). Returns ``len(text)`` if
        unbalanced."""
        depth = 0
        i, n = open_pos, len(text)
        instr = None
        while i < n:
            ch = text[i]
            if instr:
                if ch == "\\":
                    i += 2
                    continue
                if ch == instr:
                    instr = None
                i += 1
                continue
            if ch in ('"', "'", "`"):
                instr = ch
            elif ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return n

    @staticmethod
    def _indent_of(line: str) -> int:
        """Number of leading whitespace columns (tabs count as one)."""
        return len(line) - len(line.lstrip(" \t"))

    @staticmethod
    def _read_source(path) -> str:
        """Decode a source file to text, honouring a byte-order mark.

        The default ``utf-8``/``errors='ignore'`` decode turns a UTF-16 file
        (very common for tool-generated headers, e.g. MetaTrader ``.mqh``)
        into null-interleaved garbage that no anchored regex can match.  Sniff
        the BOM first and only fall back to utf-8 when there is none."""
        raw = path.read_bytes()
        if raw[:3] == b"\xef\xbb\xbf":
            text = raw[3:].decode("utf-8", errors="ignore")
        elif raw[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"):
            enc = "utf-32-le" if raw[:2] == b"\xff\xfe" else "utf-32-be"
            text = raw[4:].decode(enc, errors="ignore")
        elif raw[:2] == b"\xff\xfe":
            text = raw[2:].decode("utf-16-le", errors="ignore")
        elif raw[:2] == b"\xfe\xff":
            text = raw[2:].decode("utf-16-be", errors="ignore")
        else:
            text = raw.decode("utf-8", errors="ignore")
        # Normalise line endings so that ``^``/``$``-anchored regexes (which do
        # not treat a bare ``\r`` as an end-of-line) behave identically on
        # CRLF (Windows) and lone-CR sources.  Without this, e.g. the Lex/Yacc
        # ``^%%$`` section split silently fails on CRLF files and every symbol
        # in the file is lost.
        return text.replace("\r\n", "\n").replace("\r", "\n")

    # ------------------------------------------------------------------
    # Two-pass driver.
    # ------------------------------------------------------------------
    def analyze(self) -> Dict[str, List[Dict[str, Any]]]:
        exts = {e.lower() for e in self.extensions}
        valid_files = [p for p in self.file_paths
                       if p.suffix.lower() in exts and p.exists()]
        for file_id, path in enumerate(valid_files, start=1):
            text = self._read_source(path)
            try:
                self._register_types(file_id, text, path)
            except Exception:
                pass
        for file_id, path in enumerate(valid_files, start=1):
            text = self._read_source(path)
            try:
                self._extract_entities(file_id, text, path)
            except Exception:
                pass
        self._prune_dangling_parents()
        self._build_temp_kind_details_table()
        self.export()
        return self.get_tables()

    def _prune_dangling_parents(self):
        """Drop inheritance edges whose parent was referenced (e.g. ``extends
        Base``) but never emitted as a class row -- an external/undefined base
        gets a reserved id in ``_class_registry`` but no row, which would leave
        a dangling FK in ``junction_class_inheritance``. Keep only edges to
        parents that actually materialised."""
        emitted = self._emitted_class_rows
        for row in self.classes_table:
            parents = row.get("parent_class_ids")
            if parents:
                row["parent_class_ids"] = [p for p in parents if p in emitted]

    def _register_types(self, file_id: int, text: str, path: Path):
        pass

    def _extract_entities(self, file_id: int, text: str, path: Path):
        pass
