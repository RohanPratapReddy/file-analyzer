# Application-specific scripting formats: Foundry Nuke node scripts (.nk/.nknc),
# Elasticsearch Painless (.painless), WezTerm Lua config (.wezterm) and the
# browser proxy auto-config scripts (.pac/.wpad, JavaScript).
import re

from .shell_base import ShellScriptBase


class NukeAnalyzer(ShellScriptBase):
    """Foundry Nuke compositing scripts (.nk, .nknc).

    A .nk file is a tree of nodes: ``NodeClass { name Foo knob value ... }``.
    ``NodeClass { ... }``   -> class (a node instance, keyed by its `name` knob)
    top-level ``push $name`` / ``set n [...]``  -> variable
    """
    LANG_KEY = "nuke"
    EXTENSIONS = (".nk", ".nknc")
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _NODE = re.compile(r"(?m)^(?P<cls>[A-Z][A-Za-z0-9_]*)[ \t]*\{")
    _NAMEKNOB = re.compile(r"(?m)^[ \t]*name[ \t]+(\S+)")
    _SET = re.compile(r"(?m)^[ \t]*set[ \t]+(\w+)[ \t]+(.*)")
    _PUSH = re.compile(r"(?m)^[ \t]*push[ \t]+(\$?\w+)")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        # Walk each top-level node block and read its `name` knob.
        node_count = 0
        classes = {}
        for m in self._NODE.finditer(clean):
            cls = m.group("cls")
            if cls in ("set", "push", "add_layer", "version", "define_window_layout_xml"):
                continue
            end = self._find_matching(clean, m.end() - 1, "{", "}")
            body = clean[m.end():end]
            nm = self._NAMEKNOB.search(body)
            label = nm.group(1) if nm else f"{cls}{node_count}"
            node_count += 1
            classes[cls] = classes.get(cls, 0) + 1
            self._add_class(file_id, label, description="nuke node: " + cls)

        seen_var = set()
        for m in self._SET.finditer(clean):
            name = m.group(1)
            if name not in seen_var:
                seen_var.add(name)
                self._add_variable(file_id, name, m.group(2).strip()[:120] or None,
                                   scope="nuke")

        self._record_module_meta(
            file_id, kind="non-commercial" if path.suffix.lower() == ".nknc" else "nuke",
            nodes=node_count, node_classes=classes or None)


class PainlessAnalyzer(ShellScriptBase):
    """Elasticsearch Painless scripts (.painless) -- a Java-like DSL.

    ``ReturnType name(args) { ... }``   -> function
    ``def x = ...`` / ``Type x = ...``  -> variable
    Painless has no imports; access to `params`, `doc`, `ctx` is recorded.
    """
    LANG_KEY = "painless"
    EXTENSIONS = (".painless",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _FUNC = re.compile(r"(?m)^[ \t]*(?:[\w<>\[\].]+)[ \t]+([A-Za-z_]\w*)[ \t]*\(([^)]*)\)[ \t]*\{")
    _VAR = re.compile(r"(?m)^[ \t]*(?:def|[\w<>\[\].]+)[ \t]+([A-Za-z_]\w*)[ \t]*=[ \t]*[^=]")
    _CONTEXT = re.compile(r"\b(params|doc|ctx|_score|_source|field)\b")
    _KW = {"if", "for", "while", "return", "else", "catch"}

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._FUNC.finditer(clean):
            name = m.group(1)
            if name in self._KW or name in seen_fn:
                continue
            seen_fn.add(name)
            params = [p.strip().split()[-1]
                      for p in self._split_top_level(m.group(2) or "") if p.strip()]
            self._add_shell_function(file_id, name, params=params,
                                     description="painless function")

        seen_var = set()
        for m in self._VAR.finditer(clean):
            name = m.group(1)
            if name in self._KW or name in seen_var:
                continue
            seen_var.add(name)
            self._add_variable(file_id, name, None, scope="painless")

        contexts = self._uniq(self._CONTEXT.findall(clean))
        self._record_module_meta(file_id, functions=len(seen_fn),
                                 variables=len(seen_var),
                                 context_vars=contexts or None)


class WeztermAnalyzer(ShellScriptBase):
    """WezTerm configuration scripts (.wezterm) -- Lua.

    ``function name(args) ... end`` / ``local function name`` -> function
    ``local x = ...`` / ``x = ...``                           -> variable
    ``require 'mod'``                                         -> import
    """
    LANG_KEY = "wezterm-lua"
    EXTENSIONS = (".wezterm",)
    LINE_COMMENTS = ("--",)
    BLOCK_COMMENTS = (("--[[", "]]"),)
    STRING_DELIMS = ('"', "'")

    _FUNC = re.compile(r"(?m)^[ \t]*(?:local[ \t]+)?function[ \t]+([\w.:]+)[ \t]*\(([^)]*)\)")
    _ASSIGNFN = re.compile(r"(?m)^[ \t]*(?:local[ \t]+)?([\w.]+)[ \t]*=[ \t]*function[ \t]*\(([^)]*)\)")
    _LOCAL = re.compile(r"(?m)^[ \t]*local[ \t]+([A-Za-z_]\w*)[ \t]*=[ \t]*(.*)")
    _REQUIRE = re.compile(r"(?m)require[ \t]*\(?[ \t]*['\"]([^'\"]+)['\"]")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for rx in (self._FUNC, self._ASSIGNFN):
            for m in rx.finditer(clean):
                name = m.group(1)
                if name in seen_fn:
                    continue
                seen_fn.add(name)
                params = self._split_top_level(m.group(2) or "")
                self._add_shell_function(file_id, name, params=params,
                                         description="lua function")

        seen_var = set()
        for m in self._LOCAL.finditer(clean):
            name, val = m.group(1), m.group(2).strip()
            if name in seen_var or val.startswith("function") or name in seen_fn:
                continue
            seen_var.add(name)
            self._add_variable(file_id, name, val[:120] or None, scope="local")

        seen_imp = set()
        for m in self._REQUIRE.finditer(clean):
            mod = m.group(1)
            if mod not in seen_imp:
                seen_imp.add(mod)
                self._add_import(file_id, mod.split(".")[-1], mod, alias="require")

        self._record_module_meta(file_id, functions=len(seen_fn),
                                 variables=len(seen_var), requires=len(seen_imp))


class ProxyAutoConfigAnalyzer(ShellScriptBase):
    """Proxy auto-config / WPAD scripts (.pac, .wpad) -- JavaScript.

    ``function FindProxyForURL(url, host) { ... }`` -> function (the required entry)
    ``function name(args) { ... }``                 -> function
    ``var x = ...``                                 -> variable
    PAC helper calls (isInNet, dnsResolve, ...) are recorded as command deps.
    """
    LANG_KEY = "proxy-pac"
    EXTENSIONS = (".pac", ".wpad")
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _FUNC = re.compile(r"(?m)\bfunction[ \t]+([A-Za-z_]\w*)[ \t]*\(([^)]*)\)")
    _VAR = re.compile(r"(?m)^[ \t]*var[ \t]+([A-Za-z_]\w*)[ \t]*=[ \t]*(.*)")
    _HELPERS = ("isPlainHostName", "dnsDomainIs", "localHostOrDomainIs",
                "isResolvable", "isInNet", "dnsResolve", "myIpAddress",
                "dnsDomainLevels", "shExpMatch", "weekdayRange", "dateRange",
                "timeRange")

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
                                     description="pac function")

        seen_var = set()
        for m in self._VAR.finditer(clean):
            name = m.group(1)
            if name not in seen_var:
                seen_var.add(name)
                self._add_variable(file_id, name, m.group(2).strip()[:120] or None,
                                   scope="pac")

        seen_imp = set()
        for helper in self._HELPERS:
            if re.search(r"\b" + helper + r"\s*\(", clean):
                seen_imp.add(helper)
                self._add_command_dep(file_id, helper)

        self._record_module_meta(
            file_id, kind="wpad" if path.suffix.lower() == ".wpad" else "pac",
            has_entry_point=("FindProxyForURL" in seen_fn),
            functions=len(seen_fn), pac_helpers=sorted(seen_imp) or None)
