# UPC (.upc) Unified Parallel C analyzer.
#
# UPC is ISO C extended with a PGAS shared-memory model: the `shared` /
# `strict` / `relaxed` type qualifiers, `upc_forall`, and the `THREADS` /
# `MYTHREAD` built-ins.  The grammar is C.  Real constructs (regex):
#
#     #include <upc.h>                                  -> import
#     #define N 1024                                    -> variable (macro)
#     shared [N] double A[N];                           -> variable (shared)
#     shared int total;                                 -> variable
#     typedef struct { int x, y; } point_t;             -> class (typedef record)
#     struct node { int v; struct node *next; };        -> class
#     enum color { RED, GREEN };                        -> class
#     double dot(shared double *x, shared double *y) {  -> function (+ output)
#       upc_forall (int i = 0; i < N; i++; i) { ... }
#       return s;
#     }
#     int main() { ... }                                -> function
#
# `upc_forall`/`upc_barrier`/etc. are call sites, not definitions.  Comments
# are '//' and '/* */'.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"
# UPC shared-model qualifiers erased before the (type name) heuristics run
_UPCQ = r"(?:shared|strict|relaxed)(?:\s*\[[^\]]*\])?"


class UPCAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "upc"
    EXTENSIONS = (".upc",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _INCLUDE = re.compile(r'(?m)^\s*#\s*include\s+[<"]([^>"]+)[>"]')
    _DEFINE = re.compile(r"(?m)^\s*#\s*define\s+(" + _ID + r")\b")
    # typedef ... NAME;   (name is the last identifier before ';')
    _TYPEDEF = re.compile(r"(?m)^\s*typedef\b[^;{]*?\b(" + _ID + r")\s*;")
    # typedef struct/union/enum { ... } NAME;  (alias for an inline record body)
    _TYPEDEF_ALIAS = re.compile(
        r"(?ms)^\s*typedef\s+(?:struct|union|enum)\b"
        r"[^{;]*\{(?:[^{}]|\{[^{}]*\})*\}\s*(" + _ID + r")\s*;"
    )
    _TYPEDEF_REC = re.compile(r"(?m)^\s*typedef\s+(?:struct|union|enum)\b")
    _RECORD = re.compile(
        r"(?m)^\s*(?:typedef\s+)?(struct|union|enum)\s+("
        + _ID
        + r")\s*(?:\{|;|"
        + _ID
        + r")"
    )
    # shared/strict/relaxed-qualified or plain top-level data declarations
    _SHARED_VAR = re.compile(
        r"(?m)^\s*"
        + _UPCQ
        + r"\s+[\w\*\s]*?\b("
        + _ID
        + r")\s*(?:\[[^\]]*\])?\s*(?:=|;)"
    )

    _CALL = re.compile(r"\b(" + _ID + r")\s*\(")
    _NOT_FUNC = {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "sizeof",
        "defined",
        "upc_forall",
        "upc_barrier",
        "upc_notify",
        "upc_wait",
        "upc_fence",
        "upc_lock",
        "upc_unlock",
        "upc_memget",
        "upc_memput",
        "upc_memcpy",
        "upc_all_alloc",
        "upc_alloc",
        "upc_free",
        "assert",
        "static_assert",
    }
    _STORAGE = re.compile(
        r"^\s*(?:static|extern|inline|register|const|volatile|"
        r"shared|strict|relaxed|_Noreturn)\b"
    )

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._RECORD.finditer(clean):
            self._register_class(m.group(2))
        for m in self._TYPEDEF_ALIAS.finditer(clean):
            self._register_class(m.group(1))
        for m in self._TYPEDEF.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INCLUDE.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, re.split(r"[\\/]", src)[-1], src)
        for m in self._DEFINE.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="macro")

        typedef_names = set()
        for m in self._RECORD.finditer(clean):
            self._add_class(file_id, m.group(2), description="upc " + m.group(1))
        for m in self._TYPEDEF_ALIAS.finditer(clean):
            typedef_names.add(m.group(1))
            self._add_class(file_id, m.group(1), description="upc typedef record")
        for m in self._TYPEDEF.finditer(clean):
            if m.group(1) in typedef_names:
                continue
            typedef_names.add(m.group(1))
            self._add_class(file_id, m.group(1), description="upc typedef")

        seen_var = set()
        for m in self._SHARED_VAR.finditer(clean):
            nm = m.group(1)
            if nm and nm not in seen_var and nm not in typedef_names:
                seen_var.add(nm)
                self._add_variable(file_id, nm, scope="shared")

        self._scan_functions(file_id, clean, typedef_names)

    def _scan_functions(self, file_id, clean, typedef_names):
        emitted = set()
        for m in self._CALL.finditer(clean):
            bare = m.group(1)
            if bare in self._NOT_FUNC:
                continue
            open_paren = m.end() - 1
            close = self._find_matching(clean, open_paren, "(", ")")
            if close <= open_paren:
                continue
            j = close
            while j < len(clean) and clean[j] in " \t\r\n":
                j += 1
            if j >= len(clean) or clean[j] != "{":
                continue
            # the token before the name must look like a return type, not a
            # control-flow keyword / another call
            line_start = clean.rfind("\n", 0, m.start()) + 1
            pre = clean[line_start : m.start()].strip()
            if not pre or pre.endswith((")", ",", "&&", "||", "=")):
                continue
            key = (m.start(), bare)
            if key in emitted:
                continue
            emitted.add(key)
            args = self._paren_args(clean, open_paren, close)
            outs = self._return_output(pre, bare)
            self._add_function(file_id, bare, args, outs, description="upc function")

    def _paren_args(self, clean, open_paren, close):
        body = clean[open_paren + 1 : close - 1].strip()
        if not body or body == "void":
            return []
        arg_ids = []
        for part in self._split_top_level(body):
            part = re.sub(_UPCQ, " ", part).strip()
            if not part or part == "...":
                continue
            toks = re.findall(_ID, part)
            if not toks:
                continue
            name = toks[-1]
            atype = part[: part.rfind(name)].strip().rstrip("*&") or None
            arg_ids.append(self._add_arg(name, atype))
        return arg_ids

    def _return_output(self, pre, bare):
        pre = re.sub(r"\b(?:static|extern|inline|_Noreturn)\b", " ", pre)
        pre = re.sub(_UPCQ, " ", pre).strip()
        if not pre:
            return []
        return [self._add_output(pre)]
