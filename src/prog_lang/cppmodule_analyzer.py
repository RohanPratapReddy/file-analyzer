# C++ module / template-impl (.cppm, .ixx, .ipp, .tpp, .inl) analyzer.
#
# Covers the C++20 module surface plus the classic template/inline
# implementation headers that carry the same grammar:
#
#     export module math.linalg;                  -> import (module unit)
#     module math.linalg:detail;                  -> import (partition)
#     import std;   import <vector>;              -> import
#     export import :interface;                    -> import
#     #include <cmath>   /  #include "vec.hpp"     -> import
#     using namespace std;                         -> import
#     using Real = double;                         -> variable (type alias)
#     namespace la { ... }                         -> class (namespace)
#     export class Matrix : public Base { ... }    -> class (+ parents)
#     struct Vec3 { ... };  enum class Axis { };   -> class
#     template<class T> T dot(Vec<T> a, Vec<T> b){ -> function
#     Matrix Matrix::transpose() const { ... }     -> function (method, owner Matrix)
#     constexpr double PI = 3.14159;               -> variable
#
# Comments are '//' and '/* */'; strings use '"', '\'' and raw R"()".
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"
_QNAME = r"~?" + _ID + r"(?:\s*::\s*~?" + _ID + r")*"


class CppModuleAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "cppmodule"
    EXTENSIONS = (".cppm", ".ixx", ".ipp", ".tpp", ".inl")
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    # ---- imports / module machinery -------------------------------------
    _INCLUDE = re.compile(r'(?m)^\s*#\s*include\s+[<"]([^>"]+)[>"]')
    # `export module a.b:part;`  |  `module a.b;`  (a bare `module;` has no name)
    _MODULE = re.compile(r"(?m)^\s*(?:export\s+)?module\s+([\w.:]+)\s*;")
    # `export import :part;` | `import a.b;` | `import <vector>;` | `import \"x\";`
    _IMPORT = re.compile(
        r'(?m)^\s*(?:export\s+)?import\s+(?:<([^>]+)>|"([^"]+)"|([\w.:]+))\s*;'
    )
    _USING_NS = re.compile(r"(?m)^\s*using\s+namespace\s+([\w:]+)\s*;")
    _USING_ALIAS = re.compile(
        r"(?m)^\s*(?:export\s+)?using\s+(" + _ID + r")\s*=\s*([^;]+);"
    )
    _DEFINE = re.compile(r"(?m)^\s*#\s*define\s+(" + _ID + r")\b")

    # ---- types ----------------------------------------------------------
    _NAMESPACE = re.compile(
        r"(?m)^\s*(?:export\s+)?(?:inline\s+)?namespace\s+("
        + _ID
        + r"(?:\s*::\s*"
        + _ID
        + r")*)\s*\{"
    )
    _RECORD = re.compile(
        r"(?m)^\s*(?:export\s+)?(?:template\s*<[^;{]*>\s*)?"
        r"(?:class|struct|union)\s+(?:\[\[[^\]]*\]\]\s*)?(" + _ID + r")\b(?!\s*[;,)])"
        r"(?:\s+final)?\s*(?::\s*([^{}]+?))?\s*\{"
    )
    _ENUM = re.compile(
        r"(?m)^\s*(?:export\s+)?enum\s+(?:class\s+|struct\s+)?(" + _ID + r")\b"
    )

    # ---- variables ------------------------------------------------------
    _VAR = re.compile(
        r"(?m)^\s*(?:export\s+)?"
        r"(?:constexpr|constinit|consteval|inline|static|const|"
        r"extern|thread_local|register)\s+"
        r"[\w:<>,\*&\[\]\s]*?\b(" + _ID + r")\s*(?:=|\{)"
    )

    # ---- function scan --------------------------------------------------
    _CALL = re.compile(r"(" + _QNAME + r")\s*\(")
    _NOT_FUNC = {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "return",
        "sizeof",
        "new",
        "delete",
        "throw",
        "and",
        "or",
        "not",
        "static_cast",
        "dynamic_cast",
        "reinterpret_cast",
        "const_cast",
        "decltype",
        "noexcept",
        "alignof",
        "alignas",
        "typeid",
        "co_await",
        "co_yield",
        "co_return",
        "requires",
        "assert",
        "static_assert",
        "defined",
        "__attribute__",
        "operator",
    }
    _TRAILING = re.compile(
        r"\s*(?:const|noexcept(?:\([^)]*\))?|override|final|"
        r"mutable|volatile|&|&&|\[\[[^\]]*\]\]|"
        r"->\s*[\w:<>,\*&\[\] ]+|"
        r"requires\s+[^({]+|"
        r":\s*[^{;]+)*\s*"
    )

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
            leaf = re.split(r"[\\/]", src)[-1]
            self._add_import(file_id, leaf, src)
        for m in self._MODULE.finditer(clean):
            name = m.group(1)
            leaf = re.split(r"[.:]", name)[-1] or name
            self._add_import(file_id, leaf, name)
        for m in self._IMPORT.finditer(clean):
            src = m.group(1) or m.group(2) or m.group(3)
            leaf = re.split(r"[\\/.:]", src)[-1] or src
            self._add_import(file_id, leaf, src)
        for m in self._USING_NS.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, src.split("::")[-1], src)
        for m in self._DEFINE.finditer(clean):
            self._add_variable(file_id, m.group(1), scope="macro")
        alias_names = set()
        for m in self._USING_ALIAS.finditer(clean):
            alias_names.add(m.group(1))
            self._add_variable(
                file_id, m.group(1), value=m.group(2).strip(), scope="type-alias"
            )

        for m in self._NAMESPACE.finditer(clean):
            self._add_class(
                file_id, m.group(1).split("::")[-1].strip(), description="c++ namespace"
            )
        for m in self._RECORD.finditer(clean):
            parents = self._parse_bases(m.group(2))
            self._add_class(
                file_id, m.group(1), description="c++ type", parent_ids=parents or None
            )
        for m in self._ENUM.finditer(clean):
            self._add_class(file_id, m.group(1), description="c++ enum")

        seen_var = set(alias_names)
        for m in self._VAR.finditer(clean):
            name = m.group(1)
            if name in seen_var:
                continue
            seen_var.add(name)
            self._add_variable(file_id, name, scope="module")

        self._scan_functions(file_id, clean)

    # --------------------------------------------------------------------
    def _parse_bases(self, group):
        if not group:
            return []
        parents = []
        for p in self._split_top_level(group.strip()):
            p = p.strip()
            p = re.sub(r"\b(?:public|private|protected|virtual)\b", " ", p)
            p = p.split("<")[0].strip()  # drop template args
            p = p.split("::")[-1].strip()
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
            # what follows the argument list, past trailing specifiers?
            tm = self._TRAILING.match(clean, close)
            after_pos = tm.end() if tm else close
            if after_pos >= len(clean) or clean[after_pos] != "{":
                continue  # declaration / call, not a def
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
            self._add_function(
                file_id, bare, args, outs, class_id=cls_id, description="c++ function"
            )

    def _paren_args(self, clean, open_paren, close):
        body = clean[open_paren + 1 : close - 1].strip()
        if not body or body == "void":
            return []
        arg_ids = []
        for part in self._split_top_level(body):
            part = part.strip()
            if not part or part == "...":
                continue
            part = part.split("=")[0].strip()  # drop default value
            # last identifier token is the parameter name
            toks = re.findall(_ID, part)
            if not toks:
                continue
            name = toks[-1]
            # a bare type (e.g. `int`, `std::string`) has the type as last tok;
            # keep it anyway -- best effort, mirrors other analyzers
            atype = part[: part.rfind(name)].strip().rstrip("*&") or None
            arg_ids.append(self._add_arg(name, atype))
        return arg_ids

    def _return_output(self, clean, name_start, bare, owner):
        line_start = clean.rfind("\n", 0, name_start) + 1
        pre = clean[line_start:name_start].strip()
        pre = re.sub(r"^\s*template\s*<[^>]*>\s*", "", pre)
        pre = re.sub(
            r"\b(?:export|inline|static|virtual|explicit|constexpr|"
            r"consteval|constinit|friend|extern|[A-Z]+_API)\b",
            " ",
            pre,
        )
        pre = pre.strip()
        if not pre or bare == owner or bare.startswith("~"):
            return []  # ctor / dtor -> no return type
        return [self._add_output(pre)]
