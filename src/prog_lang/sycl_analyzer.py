# SYCL (.sycl) heterogeneous C++ analyzer.
#
# SYCL is standard C++ with the Khronos SYCL library surface, so the grammar
# is C++.  Real constructs (regex; '//' and '/* */' comments):
#
#     #include <sycl/sycl.hpp>                          -> import
#     using namespace sycl;                             -> import
#     using data_t = float;                             -> variable (type alias)
#     namespace app { ... }                             -> class (namespace)
#     class VectorAdd;                                  -> class (kernel-name tag)
#     struct Params { int n; };                         -> class
#     template <typename T> T reduce(T* p, size_t n){}  -> function (+ output)
#     void run(queue& q) {                              -> function
#       q.submit([&](handler& h) {
#         h.parallel_for<VectorAdd>(range<1>(N), [=](id<1> i){ ... });
#       });
#     }
#     T Accessor<T>::read() const { ... }               -> function (method, owner)
#
# Kernel lambdas are anonymous and not emitted; the `class KName;` kernel tags,
# named functions and record types are the entities.  Comments are '//','/* */'.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"
_QNAME = r"~?" + _ID + r"(?:\s*::\s*~?" + _ID + r")*"


class SyclAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "sycl"
    EXTENSIONS = (".sycl",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _INCLUDE = re.compile(r'(?m)^\s*#\s*include\s+[<"]([^>"]+)[>"]')
    _USING_NS = re.compile(r"(?m)^\s*using\s+namespace\s+([\w:]+)\s*;")
    _USING_ALIAS = re.compile(r"(?m)^\s*(?:export\s+)?using\s+(" + _ID +
                              r")\s*=\s*([^;]+);")
    _DEFINE = re.compile(r"(?m)^\s*#\s*define\s+(" + _ID + r")\b")

    _NAMESPACE = re.compile(r"(?m)^\s*(?:inline\s+)?namespace\s+(" +
                            _ID + r"(?:\s*::\s*" + _ID + r")*)\s*\{")
    _RECORD = re.compile(r"(?m)^\s*(?:template\s*<[^;{]*>\s*)?"
                         r"(?:class|struct|union)\s+(?:\[\[[^\]]*\]\]\s*)?(" +
                         _ID + r")\b(?!\s*::)"
                         r"(?:\s+final)?\s*(?:(;)|(?::\s*([^{}]+?))?\s*\{)")
    _ENUM = re.compile(r"(?m)^\s*enum\s+(?:class\s+|struct\s+)?(" + _ID + r")\b")

    _VAR = re.compile(r"(?m)^\s*(?:constexpr|constinit|consteval|inline|static|"
                      r"const|extern|thread_local)\s+"
                      r"[\w:<>,\*&\[\]\s]*?\b(" + _ID + r")\s*(?:=|\{)")

    _CALL = re.compile(r"(" + _QNAME + r")\s*\(")
    _NOT_FUNC = {"if", "for", "while", "switch", "catch", "return", "sizeof",
                 "new", "delete", "throw", "and", "or", "not", "static_cast",
                 "dynamic_cast", "reinterpret_cast", "const_cast", "decltype",
                 "noexcept", "alignof", "alignas", "typeid", "requires",
                 "assert", "static_assert", "defined", "operator", "sycl",
                 "parallel_for", "single_task", "submit", "for_each"}
    _TRAILING = re.compile(r"\s*(?:const|noexcept(?:\([^)]*\))?|override|final|"
                           r"mutable|volatile|&|&&|\[\[[^\]]*\]\]|"
                           r"->\s*[\w:<>,\*&\[\] ]+|"
                           r"requires\s+[^({]+|"
                           r":\s*[^{;]+)*\s*")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._NAMESPACE.finditer(clean):
            self._register_class(m.group(1).split("::")[-1].strip())
        for m in self._RECORD.finditer(clean):
            self._register_class(m.group(1))
        for m in self._ENUM.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INCLUDE.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, re.split(r"[\\/]", src)[-1], src)
        for m in self._USING_NS.finditer(clean):
            self._add_import(file_id, m.group(1).split("::")[-1], m.group(1))
        for m in self._DEFINE.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="macro")
        alias_names = set()
        for m in self._USING_ALIAS.finditer(clean):
            alias_names.add(m.group(1))
            self._add_variable(file_id, m.group(1), value=m.group(2).strip(),
                               scope="type-alias")

        for m in self._NAMESPACE.finditer(clean):
            self._add_class(file_id, m.group(1).split("::")[-1].strip(),
                            description="c++ namespace")
        for m in self._RECORD.finditer(clean):
            parents = self._parse_bases(m.group(3))
            self._add_class(file_id, m.group(1),
                            description="sycl kernel tag" if m.group(2) else "c++ type",
                            parent_ids=parents or None)
        for m in self._ENUM.finditer(clean):
            self._add_class(file_id, m.group(1), description="c++ enum")

        seen_var = set(alias_names)
        for m in self._VAR.finditer(clean):
            if m.group(1) in seen_var:
                continue
            seen_var.add(m.group(1))
            self._add_variable(file_id, m.group(1), scope="module")

        self._scan_functions(file_id, clean)

    def _parse_bases(self, group):
        if not group:
            return []
        parents = []
        for p in self._split_top_level(group.strip()):
            p = re.sub(r"\b(?:public|private|protected|virtual)\b", " ", p)
            p = p.split("<")[0].split("::")[-1].strip()
            if p:
                pid = self._register_class(p)
                if pid is not None:
                    parents.append(pid)
        return parents

    def _scan_functions(self, file_id, clean):
        emitted = set()
        for m in self._CALL.finditer(clean):
            qname = re.sub(r"\s+", "", m.group(1))
            segs = qname.split("::")
            bare = segs[-1]
            if not bare or bare in self._NOT_FUNC or bare.startswith("__"):
                continue
            open_paren = m.end() - 1
            close = self._find_matching(clean, open_paren, "(", ")")
            if close <= open_paren:
                continue
            tm = self._TRAILING.match(clean, close)
            after = tm.end() if tm else close
            if after >= len(clean) or clean[after] != "{":
                continue
            key = (m.start(), bare)
            if key in emitted:
                continue
            emitted.add(key)
            owner = segs[-2] if len(segs) >= 2 else None
            cls_id = None
            if owner:
                owner = re.sub(r"<.*", "", owner).strip("~")
                if owner:
                    cls_id = self._register_class(owner)
            args = self._paren_args(clean, open_paren, close)
            outs = self._return_output(clean, m.start(), bare, owner)
            self._add_function(file_id, bare, args, outs, class_id=cls_id,
                               description="sycl function")

    def _paren_args(self, clean, open_paren, close):
        body = clean[open_paren + 1:close - 1].strip()
        if not body or body == "void":
            return []
        arg_ids = []
        for part in self._split_top_level(body):
            part = part.split("=")[0].strip()
            if not part or part == "...":
                continue
            toks = re.findall(_ID, part)
            if not toks:
                continue
            name = toks[-1]
            atype = part[:part.rfind(name)].strip().rstrip("*&") or None
            arg_ids.append(self._add_arg(name, atype))
        return arg_ids

    def _return_output(self, clean, name_start, bare, owner):
        line_start = clean.rfind("\n", 0, name_start) + 1
        pre = clean[line_start:name_start].strip()
        pre = re.sub(r"^\s*template\s*<[^>]*>\s*", "", pre)
        pre = re.sub(r"\b(?:inline|static|virtual|explicit|constexpr|consteval|"
                     r"friend|extern|SYCL_EXTERNAL|[A-Z]+_API)\b", " ", pre)
        pre = pre.strip()
        if not pre or bare == owner or bare.startswith("~"):
            return []
        return [self._add_output(pre)]
