# LiveScript (.ls) analyzer.
#
# LiveScript is a functional language that compiles to JavaScript.  Unlike JS it
# is indentation-based, uses `->`/`~>` (bound) arrows for functions, `!` to mark
# a procedure (no implicit return), hyphenated identifiers (`my-fn` -> `myFn`),
# and `require!` sugar for imports.  Salient declaration forms:
#
#   add     = (a, b) -> a + b          -> function (+ args)
#   log     = !(msg) -> console.log msg -> function (bang / procedure)
#   bound   = (x) ~> @val + x           -> function (bound arrow)
#   noop    = ->                        -> function (no params)
#   class Point extends Shape           -> class (+ parent)
#   fs       = require 'fs'             -> import (aliased)
#   require! 'prelude-ls'              -> import
#   require! {fs, path}                -> imports
#   {readFile} = require 'fs'          -> import (destructured)
#   PI      = 3.14159                   -> variable
#
# Comments: `#` to EOL, `/* ... */`; backticks embed raw JS (treated as a string
# so their contents are not mis-parsed).
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_$][A-Za-z0-9_$-]*"


class LiveScriptAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "livescript"
    EXTENSIONS = (".ls",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'", "`")

    # name = [!] [(params)] [!] ->|~>        (arrow may be preceded by `!`)
    _FUNC = re.compile(r"(?m)^\s*(" + _ID + r")\s*=\s*!?\s*(\([^)]*\))?\s*!?\s*(?:~>|->)")
    # bare arrow assigned via `:` inside a class/object:  name: (params) -> ...
    _METHOD = re.compile(r"(?m)^\s+(" + _ID + r")\s*:\s*!?\s*(\([^)]*\))?\s*!?\s*(?:~>|->)")
    _CLASS = re.compile(r"(?m)^\s*class\s+(" + _ID + r")"
                        r"(?:\s+extends\s+(" + _ID + r"(?:\.[A-Za-z0-9_$]+)*))?")
    # imports
    _REQ_ALIAS = re.compile(r"(?m)^\s*(" + _ID + r")\s*=\s*require\s*!?\s*['\"]([^'\"]+)['\"]")
    _REQ_BANG_STR = re.compile(r"(?m)\brequire!\s*['\"]([^'\"]+)['\"]")
    # bareword sugar:  require! optionator   /   require! prelude-ls
    _REQ_BANG_BARE = re.compile(r"(?m)\brequire!\s+(" + _ID + r")(?![\w$-]*\s*[:={])")
    _REQ_BANG_OBJ = re.compile(r"(?m)\brequire!\s*\{([^}]*)\}")
    _REQ_BANG_LIST = re.compile(r"(?m)\brequire!\s*<\[([^\]]*)\]>")
    _REQ_DESTRUCT = re.compile(r"(?m)^\s*\{([^}]*)\}\s*=\s*require\s*['\"]([^'\"]+)['\"]")
    # any top-level assignment (variable candidate)
    _ASSIGN = re.compile(r"(?m)^([ \t]*)(" + _ID + r")\s*=\s*(\S.*)$")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._CLASS.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        imports = set()
        # aliased:  fs = require 'fs'
        for m in self._REQ_ALIAS.finditer(clean):
            self._add_import(file_id, m.group(1), m.group(2), alias=m.group(1))
            imports.add(m.group(1))
        # require! 'mod'
        for m in self._REQ_BANG_STR.finditer(clean):
            src = m.group(1)
            name = re.split(r"[\\/]", src)[-1]
            self._add_import(file_id, name, src)
            imports.add(name)
        # require! optionator   (bareword, no quotes / braces / list)
        for m in self._REQ_BANG_BARE.finditer(clean):
            nm = m.group(1)
            if nm not in imports:
                self._add_import(file_id, nm, nm)
                imports.add(nm)
        # require! {a, b}
        for m in self._REQ_BANG_OBJ.finditer(clean):
            for raw in m.group(1).split(","):
                nm = raw.strip().split(":")[0].strip()
                if re.fullmatch(_ID, nm or ""):
                    self._add_import(file_id, nm, nm)
                    imports.add(nm)
        # require! <[ a b c ]>
        for m in self._REQ_BANG_LIST.finditer(clean):
            for nm in m.group(1).split():
                if re.fullmatch(_ID, nm):
                    self._add_import(file_id, nm, nm)
                    imports.add(nm)
        # {a, b} = require 'mod'
        for m in self._REQ_DESTRUCT.finditer(clean):
            src = m.group(2)
            for raw in m.group(1).split(","):
                nm = raw.strip().split(":")[0].strip()
                if re.fullmatch(_ID, nm or ""):
                    self._add_import(file_id, nm, src)
                    imports.add(nm)

        classes = set()
        for m in self._CLASS.finditer(clean):
            parents = []
            if m.group(2):
                pid = self._register_class(m.group(2).split(".")[-1])
                parents = [pid] if pid is not None else []
            self._add_class(file_id, m.group(1), description="livescript class",
                            parent_ids=parents)
            classes.add(m.group(1))

        functions = set()
        for m in self._FUNC.finditer(clean):
            name = m.group(1)
            if name in imports or name in functions:
                continue
            functions.add(name)
            self._add_function(file_id, name, self._ls_args(m.group(2)), [],
                               description="livescript function")
        for m in self._METHOD.finditer(clean):
            name = m.group(1)
            key = "method:" + name
            if name in functions:
                continue
            functions.add(name)
            self._add_function(file_id, name, self._ls_args(m.group(2)), [],
                               description="livescript method")

        seen_var = set()
        for m in self._ASSIGN.finditer(clean):
            name, rhs = m.group(2), m.group(3)
            if name in imports or name in functions or name in classes:
                continue
            if name in seen_var:
                continue
            # a function/require assignment already handled above
            if re.match(r"!?\s*(\([^)]*\))?\s*!?\s*(?:~>|->)", rhs) or \
                    rhs.lstrip().startswith("require"):
                continue
            seen_var.add(name)
            self._add_variable(file_id, name, rhs.strip()[:120], scope="module")

    def _ls_args(self, group):
        if not group or not group.strip("() "):
            return []
        inner = group.strip()[1:-1]
        arg_ids = []
        for part in self._split_top_level(inner):
            part = part.strip()
            if not part:
                continue
            # drop default (`x = 1`), splats (`...rest`), and `@`-bound params
            nm = part.split("=")[0].strip().lstrip("@").lstrip(".")
            toks = re.findall(_ID, nm)
            if toks:
                arg_ids.append(self._add_arg(toks[-1]))
        return arg_ids
