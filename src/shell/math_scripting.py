# Computer-algebra / numerical scripting languages: GAP (.g), PARI/GP (.gp) and
# Maple (.mpl).  Each has genuine function definitions, assignments and file
# reads that are parsed here with the language's own syntax.
import re

from .shell_base import ShellScriptBase


class GapAnalyzer(ShellScriptBase):
    """GAP computational-algebra scripts (.g).

    ``name := function(args) ... end;``   -> function
    ``name := value;``                    -> variable
    ``Read("file");`` / ``Reread(...)``   -> import
    ``LoadPackage("pkg");``               -> import
    """
    LANG_KEY = "gap"
    EXTENSIONS = (".g",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _FUNC = re.compile(r"(?m)([A-Za-z_]\w*)[ \t]*:=[ \t]*function[ \t]*\(([^)]*)\)")
    _ASSIGN = re.compile(r"(?m)^[ \t]*([A-Za-z_]\w*)[ \t]*:=[ \t]*(.+)")
    _READ = re.compile(r'(?m)(?:Read|Reread)[ \t]*\([ \t]*"([^"]+)"')
    _LOAD = re.compile(r'(?m)LoadPackage[ \t]*\([ \t]*"([^"]+)"')

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._FUNC.finditer(clean):
            name = m.group(1)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            params = self._split_top_level(m.group(2) or "")
            self._add_shell_function(file_id, name, params=params,
                                     description="gap function")

        seen_var = set()
        for m in self._ASSIGN.finditer(clean):
            name, val = m.group(1), m.group(2).strip()
            if name in seen_fn or name in seen_var or val.startswith("function"):
                continue
            seen_var.add(name)
            self._add_variable(file_id, name, val[:120] or None, scope="gap")

        seen_imp = set()
        for m in self._READ.finditer(clean):
            tgt = m.group(1)
            if tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword="Read")
        for m in self._LOAD.finditer(clean):
            pkg = m.group(1)
            if pkg not in seen_imp:
                seen_imp.add(pkg)
                self._add_import(file_id, pkg, "package", alias="LoadPackage")

        self._record_module_meta(file_id, functions=len(seen_fn),
                                 variables=len(seen_var))


class PariGpAnalyzer(ShellScriptBase):
    """PARI/GP scripts (.gp).

    ``name(args) = expr`` / ``name(args) = { ... }``  -> function
    ``name = value``                                  -> variable
    ``read("file")`` / ``\\r file``                    -> import
    ``install(sym, ...)``                             -> import
    """
    LANG_KEY = "pari-gp"
    EXTENSIONS = (".gp",)
    LINE_COMMENTS = ("\\\\",)       # \\ starts a line comment in GP
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _FUNC = re.compile(r"(?m)^[ \t]*([A-Za-z_]\w*)[ \t]*\(([^)]*)\)[ \t]*=(?!=)")
    _ASSIGN = re.compile(r"(?m)^[ \t]*([A-Za-z_]\w*)[ \t]*=(?!=)[ \t]*(.+)")
    _READ = re.compile(r'(?m)read[ \t]*\([ \t]*"([^"]+)"')
    _READCMD = re.compile(r"(?m)^[ \t]*\\r[ \t]+(\S+)")
    _INSTALL = re.compile(r"(?m)install[ \t]*\([ \t]*(\w+)")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._FUNC.finditer(clean):
            name = m.group(1)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            params = self._split_top_level(m.group(2) or "")
            self._add_shell_function(file_id, name, params=params,
                                     description="gp function")

        seen_var = set()
        for m in self._ASSIGN.finditer(clean):
            name = m.group(1)
            # skip the `name(...) = ...` function form (already handled)
            if name in seen_fn or name in seen_var:
                continue
            line_start = clean.rfind("\n", 0, m.start()) + 1
            head = clean[line_start:m.start(2)]
            if "(" in head.split("=")[0]:
                continue
            seen_var.add(name)
            self._add_variable(file_id, name, m.group(2).strip()[:120] or None,
                               scope="gp")

        seen_imp = set()
        for rx, kw in ((self._READ, "read"), (self._READCMD, "read")):
            for m in rx.finditer(clean):
                tgt = m.group(1)
                if tgt not in seen_imp:
                    seen_imp.add(tgt)
                    self._add_sourced(file_id, tgt, keyword=kw)
        for m in self._INSTALL.finditer(clean):
            sym = m.group(1)
            if sym not in seen_imp:
                seen_imp.add(sym)
                self._add_import(file_id, sym, "install", alias="install")

        self._record_module_meta(file_id, functions=len(seen_fn),
                                 variables=len(seen_var))


class MapleAnalyzer(ShellScriptBase):
    """Maple scripts (.mpl).

    ``name := proc(args) ... end proc;``  -> function
    ``name := module() ... end module;``  -> class
    ``name := value;``                    -> variable
    ``with(pkg):`` / ``read "file";``     -> import
    """
    LANG_KEY = "maple"
    EXTENSIONS = (".mpl",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = (("(*", "*)"),)
    STRING_DELIMS = ('"',)

    _PROC = re.compile(r"(?m)([A-Za-z_]\w*)[ \t]*:=[ \t]*proc[ \t]*\(([^)]*)\)")
    _MODULE = re.compile(r"(?m)([A-Za-z_]\w*)[ \t]*:=[ \t]*module[ \t]*\(")
    _ASSIGN = re.compile(r"(?m)^[ \t]*([A-Za-z_]\w*)[ \t]*:=[ \t]*(.+)")
    _WITH = re.compile(r"(?m)with[ \t]*\([ \t]*([A-Za-z_]\w*)")
    _READ = re.compile(r'(?m)read[ \t]+"([^"]+)"')

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._MODULE.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_cls = set()
        for m in self._MODULE.finditer(clean):
            name = m.group(1)
            if name not in seen_cls:
                seen_cls.add(name)
                self._add_class(file_id, name, description="maple module")

        seen_fn = set()
        for m in self._PROC.finditer(clean):
            name = m.group(1)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            params = self._split_top_level(m.group(2) or "")
            self._add_shell_function(file_id, name, params=params,
                                     description="maple proc")

        seen_var = set()
        for m in self._ASSIGN.finditer(clean):
            name, val = m.group(1), m.group(2).strip()
            if name in seen_fn or name in seen_cls or name in seen_var:
                continue
            if val.startswith(("proc", "module")):
                continue
            seen_var.add(name)
            self._add_variable(file_id, name, val[:120] or None, scope="maple")

        seen_imp = set()
        for m in self._WITH.finditer(clean):
            pkg = m.group(1)
            if pkg not in seen_imp:
                seen_imp.add(pkg)
                self._add_import(file_id, pkg, "package", alias="with")
        for m in self._READ.finditer(clean):
            tgt = m.group(1)
            if tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword="read")

        self._record_module_meta(file_id, procs=len(seen_fn),
                                 modules=len(seen_cls), variables=len(seen_var))
