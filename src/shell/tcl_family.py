# Tcl and the languages that ARE Tcl at the syntax level: Tk (Tcl + widget
# commands), Expect (Tcl + spawn/expect/send), and the MacPorts Portfile
# (Tcl + port.* commands).  One analyzer parses all four because they share the
# identical `command arg arg ...` grammar; the dialect-specific commands only
# add extra recognised keywords, they never change how the file is tokenised.
#
#   proc name {args} { ... }              -> function (args parsed from the list)
#   set var value        variable v       -> variable
#   global v / upvar / namespace eval n   -> variable(scope)
#   source file.tcl   /   package require -> import
#   namespace eval NAME { ... }           -> class (a Tcl namespace ~ a module)
import re

from .shell_base import ShellScriptBase


class TclAnalyzer(ShellScriptBase):
    LANG_KEY = "tcl"
    EXTENSIONS = (".tcl", ".tk", ".expect", ".port")
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)     # Tcl uses {} for literal blocks, only "" quote

    # proc name {arg1 {arg2 default} args} {
    _PROC = re.compile(r"(?m)^[ \t]*proc[ \t]+(\S+)[ \t]+\{([^}]*)\}")
    _SET = re.compile(r"(?m)^[ \t]*set[ \t]+([A-Za-z_:][\w:()]*)[ \t]+(.*)")
    _VAR = re.compile(r"(?m)^[ \t]*(variable|global|upvar)[ \t]+(.+)$")
    _SOURCE = re.compile(r"(?m)^[ \t]*source[ \t]+(\S+)")
    _REQUIRE = re.compile(r"(?m)^[ \t]*package[ \t]+require[ \t]+(?:-exact[ \t]+)?(\S+)")
    _NAMESPACE = re.compile(r"(?m)^[ \t]*namespace[ \t]+eval[ \t]+(\S+)")
    # Expect-specific commands worth surfacing.
    _SPAWN = re.compile(r"(?m)^[ \t]*spawn[ \t]+(.+)$")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._NAMESPACE.finditer(clean):
            self._register_class(m.group(1).strip(":"))

    def _extract_entities(self, file_id, text, path):
        self._record_shebang(file_id, text)
        clean = self._strip_comments(text)

        # Namespaces -> classes (a namespace groups procs & variables).
        for m in self._NAMESPACE.finditer(clean):
            self._add_class(file_id, m.group(1).strip(":"),
                            description="tcl namespace")

        seen_fn = set()
        for m in self._PROC.finditer(clean):
            name = m.group(1).strip(":")
            if name in seen_fn:
                continue
            seen_fn.add(name)
            params = []
            for tok in self._tcl_arglist(m.group(2)):
                params.append(tok)
            self._add_shell_function(file_id, name, params=params,
                                     description="tcl proc")

        seen_var = set()
        for m in self._SET.finditer(clean):
            name = m.group(1)
            if name in seen_var:
                continue
            seen_var.add(name)
            self._add_variable(file_id, name, m.group(2).strip()[:120] or None,
                               scope="tcl")
        for m in self._VAR.finditer(clean):
            kw = m.group(1)
            toks = m.group(2).split()
            # `variable n v n v ...` declares name/value PAIRS; `global`/`upvar`
            # take a plain list of names (no values).
            if kw == "variable":
                pairs = [(toks[i], toks[i + 1] if i + 1 < len(toks) else None)
                         for i in range(0, len(toks), 2)]
            else:
                pairs = [(t, None) for t in toks]
            for name, value in pairs:
                name = name.strip("{}$")
                if name and name not in seen_var and not name.startswith("-"):
                    seen_var.add(name)
                    self._add_variable(file_id, name,
                                       (value or "").strip("{}\"") or None, scope=kw)

        seen_imp = set()
        for m in self._SOURCE.finditer(clean):
            tgt = m.group(1)
            if tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword="source")
        for m in self._REQUIRE.finditer(clean):
            pkg = m.group(1)
            if pkg not in seen_imp:
                seen_imp.add(pkg)
                self._add_import(file_id, pkg, "package", alias="require")

        dialect = "tcl"
        suf = path.suffix.lower()
        if suf == ".tk":
            dialect = "tk"
        elif suf == ".expect":
            dialect = "expect"
        elif suf == ".port":
            dialect = "macports-portfile"
        spawns = self._uniq(x.strip() for x in self._SPAWN.findall(clean))
        self._record_module_meta(
            file_id, dialect=dialect, procs=len(seen_fn),
            variables=len(seen_var), spawns=spawns or None,
        )

    @staticmethod
    def _tcl_arglist(block: str):
        """Split a Tcl proc arg list into parameter names.  Each element is
        either ``name`` or ``{name default}``; nested braces give the default."""
        out, i, n = [], 0, len(block)
        while i < n:
            ch = block[i]
            if ch.isspace():
                i += 1
                continue
            if ch == "{":
                depth, j = 1, i + 1
                while j < n and depth:
                    if block[j] == "{":
                        depth += 1
                    elif block[j] == "}":
                        depth -= 1
                    j += 1
                inner = block[i + 1:j - 1].strip()
                out.append(inner.split()[0] if inner.split() else inner)
                i = j
            else:
                j = i
                while j < n and not block[j].isspace():
                    j += 1
                out.append(block[i:j])
                i = j
        return [t for t in out if t]
