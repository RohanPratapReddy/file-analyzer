# Windows installer authoring languages: Inno Setup (.iss) and NSIS (.nsh/.nsi).
import re

from .shell_base import ShellScriptBase


class InnoSetupAnalyzer(ShellScriptBase):
    """Inno Setup scripts (.iss).

    ``[Section]`` headers ([Setup], [Files], [Code], ...)  -> class (a section)
    ``#define name value`` / ``#include "file"`` (ISPP)     -> variable / import
    ``procedure Name(...)`` / ``function Name(...)`` in [Code] (Pascal) -> function
    ``key=value`` inside [Setup]                            -> variable
    """

    LANG_KEY = "inno-setup"
    EXTENSIONS = (".iss",)
    LINE_COMMENTS = (";", "//")
    BLOCK_COMMENTS = (("{", "}"), ("(*", "*)"))  # Pascal comments in [Code]
    STRING_DELIMS = ('"', "'")

    _SECTION = re.compile(r"(?m)^[ \t]*\[([A-Za-z]+)\]")
    _DEFINE = re.compile(r"(?mi)^[ \t]*#define[ \t]+(\w+)[ \t]*(.*)")
    _INCLUDE = re.compile(r'(?mi)^[ \t]*#include[ \t]+[<"]([^>"]+)[>"]')
    _PROC = re.compile(
        r"(?mi)^[ \t]*(procedure|function)[ \t]+([A-Za-z_]\w*)[ \t]*(?:\(([^)]*)\))?"
    )
    _SETUPKEY = re.compile(r"(?m)^[ \t]*([A-Za-z]\w*)=(.*)")

    def _extract_entities(self, file_id, text, path):
        # Do NOT strip Pascal `{...}` comments globally: `{` is also used for
        # constants like {app}.  Strip only line comments for section scanning.
        raw = text

        # Sections -> classes.
        seen_cls = set()
        for m in self._SECTION.finditer(raw):
            name = m.group(1)
            if name not in seen_cls:
                seen_cls.add(name)
                self._add_class(file_id, name, description="inno-setup section")

        seen_var = set()
        for m in self._DEFINE.finditer(raw):
            name = m.group(1)
            if name not in seen_var:
                seen_var.add(name)
                self._add_variable(
                    file_id,
                    name,
                    m.group(2).strip()[:120] or None,
                    scope="preprocessor",
                )

        # [Setup] directives -> variables (only the well-known top-level keys).
        setup_body = self._section_body(raw, "Setup")
        for m in self._SETUPKEY.finditer(setup_body):
            name = m.group(1)
            if name not in seen_var:
                seen_var.add(name)
                self._add_variable(
                    file_id, name, m.group(2).strip()[:120] or None, scope="setup"
                )

        # [Code] Pascal procedures/functions -> functions.
        code_body = self._section_body(raw, "Code")
        seen_fn = set()
        for m in self._PROC.finditer(code_body):
            name = m.group(2)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            params = [
                p.split(":")[0].strip() for p in self._split_top_level(m.group(3) or "")
            ]
            self._add_shell_function(
                file_id,
                name,
                params=[p for p in params if p],
                description="inno-setup " + m.group(1).lower(),
            )

        seen_imp = set()
        for m in self._INCLUDE.finditer(raw):
            tgt = m.group(1)
            if tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword="#include")

        self._record_module_meta(
            file_id,
            sections=sorted(seen_cls) or None,
            code_functions=len(seen_fn),
            defines=len(seen_var),
        )

    @staticmethod
    def _section_body(text: str, name: str) -> str:
        """Return the text between ``[name]`` and the next ``[section]`` header."""
        m = re.search(r"(?mi)^[ \t]*\[" + re.escape(name) + r"\][ \t]*$", text)
        if not m:
            return ""
        start = m.end()
        nxt = re.search(r"(?m)^[ \t]*\[[A-Za-z]+\][ \t]*$", text[start:])
        return text[start : start + nxt.start()] if nxt else text[start:]


class NsisAnalyzer(ShellScriptBase):
    """NSIS installer scripts (.nsi) and header includes (.nsh).

    ``Function name ... FunctionEnd``   -> function
    ``!macro name ... !macroend``       -> function (a macro)
    ``Section "..." ... SectionEnd``    -> class (an install section)
    ``!define NAME value`` / ``Var x``  -> variable
    ``!include file``                   -> import
    """

    LANG_KEY = "nsis"
    EXTENSIONS = (".nsi", ".nsh")
    LINE_COMMENTS = (";", "#")
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'", "`")

    _FUNC = re.compile(r"(?mi)^[ \t]*Function[ \t]+(\.?[A-Za-z_!][\w.]*)")
    _MACRO = re.compile(r"(?mi)^[ \t]*!macro[ \t]+([A-Za-z_]\w*)[ \t]*(.*)")
    _SECTION = re.compile(
        r"(?mi)^[ \t]*Section(?:Group)?[ \t]+(?:/o[ \t]+)?" r'(?:"([^"]*)"|(\S+))'
    )
    _DEFINE = re.compile(r"(?mi)^[ \t]*!define[ \t]+(\w+)[ \t]*(.*)")
    _VAR = re.compile(r"(?mi)^[ \t]*Var[ \t]+(?:/GLOBAL[ \t]+)?([A-Za-z_]\w*)")
    _INCLUDE = re.compile(
        r'(?mi)^[ \t]*!include[ \t]+(?:/NONFATAL[ \t]+)?"?([^"\n]+?)"?[ \t]*$'
    )

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_cls = set()
        for m in self._SECTION.finditer(clean):
            name = (m.group(1) or m.group(2) or "").strip()
            if name and name not in seen_cls:
                seen_cls.add(name)
                self._add_class(file_id, name, description="nsis section")

        seen_fn = set()
        for m in self._FUNC.finditer(clean):
            name = m.group(1)
            if name not in seen_fn:
                seen_fn.add(name)
                self._add_shell_function(file_id, name, description="nsis function")
        for m in self._MACRO.finditer(clean):
            name = m.group(1)
            if name not in seen_fn:
                seen_fn.add(name)
                params = m.group(2).split()
                self._add_shell_function(
                    file_id, name, params=params, description="nsis macro"
                )

        seen_var = set()
        for m in self._DEFINE.finditer(clean):
            name = m.group(1)
            if name not in seen_var:
                seen_var.add(name)
                self._add_variable(
                    file_id, name, m.group(2).strip()[:120] or None, scope="define"
                )
        for m in self._VAR.finditer(clean):
            name = m.group(1)
            if name not in seen_var:
                seen_var.add(name)
                self._add_variable(file_id, name, None, scope="var")

        seen_imp = set()
        for m in self._INCLUDE.finditer(clean):
            tgt = m.group(1).strip()
            if tgt and tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword="!include")

        self._record_module_meta(
            file_id,
            kind="header" if path.suffix.lower() == ".nsh" else "installer",
            sections=len(seen_cls),
            functions=len(seen_fn),
            defines=len(seen_var),
        )
