# AppleScript source (.applescript) -- the plain-text form (its compiled
# sibling .scpt is handled byte-wise by compiled_scripts.CompiledScriptAnalyzer).
import re

from .shell_base import ShellScriptBase


class AppleScriptAnalyzer(ShellScriptBase):
    """AppleScript source scripts (.applescript).

    ``on name(args)`` / ``to name(args)`` / ``on name given ...`` -> function (a handler)
    ``script Name ... end script``                               -> class
    ``property x : value`` / ``set x to value`` (top level)      -> variable
    ``tell application "Finder"``                                -> command dep
    ``use framework "Foundation"`` / ``use scripting additions`` -> import
    """

    LANG_KEY = "applescript"
    EXTENSIONS = (".applescript",)
    LINE_COMMENTS = ("--", "#")
    BLOCK_COMMENTS = (("(*", "*)"),)
    STRING_DELIMS = ('"',)

    _HANDLER = re.compile(
        r"(?m)^[ \t]*(?:on|to)[ \t]+([A-Za-z_]\w*)"
        r"[ \t]*(?:\(([^)]*)\)|[ \t]+(?:above|below|from|for|"
        r"given|into|of|through|thru|under|with|without)\b)?"
    )
    _SCRIPT = re.compile(r"(?m)^[ \t]*script[ \t]+([A-Za-z_]\w*)")
    _PROPERTY = re.compile(
        r"(?m)^[ \t]*(?:property|global|local)[ \t]+"
        r"([A-Za-z_]\w*)[ \t]*:?[ \t]*(.*)"
    )
    _SET = re.compile(r"(?m)^[ \t]*set[ \t]+([A-Za-z_]\w*)[ \t]+to[ \t]+(.*)")
    _TELL = re.compile(r'(?mi)^[ \t]*tell[ \t]+application[ \t]+"([^"]+)"')
    _USE = re.compile(r'(?mi)^[ \t]*use[ \t]+(?:framework[ \t]+)?"?([^"\n]+?)"?[ \t]*$')

    # AppleScript handler names that are actually control keywords / event stubs.
    _RESERVED = {"error", "return", "if", "repeat", "tell", "end"}

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._SCRIPT.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_cls = set()
        for m in self._SCRIPT.finditer(clean):
            name = m.group(1)
            if name not in seen_cls:
                seen_cls.add(name)
                self._add_class(file_id, name, description="applescript script object")

        seen_fn = set()
        for m in self._HANDLER.finditer(clean):
            name = m.group(1)
            if name in self._RESERVED or name in seen_fn:
                continue
            seen_fn.add(name)
            params = self._split_top_level(m.group(2) or "")
            self._add_shell_function(
                file_id, name, params=params, description="applescript handler"
            )

        seen_var = set()
        for rx, scope in ((self._PROPERTY, "property"), (self._SET, "local")):
            for m in rx.finditer(clean):
                name = m.group(1)
                if name in seen_var:
                    continue
                seen_var.add(name)
                self._add_variable(
                    file_id, name, m.group(2).strip()[:120] or None, scope=scope
                )

        seen_imp = set()
        for m in self._TELL.finditer(clean):
            app = m.group(1)
            if app not in seen_imp:
                seen_imp.add(app)
                self._add_command_dep(file_id, app)
        for m in self._USE.finditer(clean):
            mod = m.group(1).strip()
            if mod and mod not in seen_imp:
                seen_imp.add(mod)
                self._add_import(file_id, mod.split()[-1], mod, alias="use")

        self._record_module_meta(
            file_id,
            script_objects=len(seen_cls),
            handlers=len(seen_fn),
            tells=sorted(a for a in seen_imp) or None,
        )
