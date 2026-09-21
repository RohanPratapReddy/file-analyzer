# Windows Script Host languages: VBScript (.vbs) and the XML Windows Script File
# wrapper (.wsf).
import re

from .shell_base import ShellScriptBase


class VbScriptAnalyzer(ShellScriptBase):
    """VBScript files (.vbs).

    ``Sub name(args)`` / ``Function name(args)``  -> function
    ``Class Name ... End Class``                  -> class
    ``Dim x`` / ``Const x = v`` / ``Public x``    -> variable
    ``Set x = CreateObject("...")``               -> variable + import (ProgID)
    """

    LANG_KEY = "vbscript"
    EXTENSIONS = (".vbs",)
    LINE_COMMENTS = ("'",)  # apostrophe comment; `Rem` handled below
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _PROC = re.compile(
        r"(?mi)^[ \t]*(?:public[ \t]+|private[ \t]+|default[ \t]+)?"
        r"(sub|function)[ \t]+([A-Za-z_]\w*)[ \t]*(?:\(([^)]*)\))?"
    )
    _CLASS = re.compile(r"(?mi)^[ \t]*class[ \t]+([A-Za-z_]\w*)")
    _DIM = re.compile(
        r"(?mi)^[ \t]*(dim|const|public|private)[ \t]+([A-Za-z_]\w*)"
        r"(?:[ \t]*=[ \t]*(.*))?"
    )
    _CREATE = re.compile(r'(?i)CreateObject[ \t]*\([ \t]*"([^"]+)"')

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._CLASS.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_cls = {}
        for m in self._CLASS.finditer(clean):
            name = m.group(1)
            if name not in seen_cls:
                seen_cls[name] = self._add_class(
                    file_id, name, description="vbscript class"
                )

        seen_fn = set()
        for m in self._PROC.finditer(clean):
            kind, name, args = m.group(1).lower(), m.group(2), m.group(3)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            params = self._split_top_level(args or "")
            params = [
                p.replace("ByVal", "").replace("ByRef", "").strip() for p in params
            ]
            self._add_shell_function(
                file_id, name, params=params, description="vbscript " + kind
            )

        seen_var = set()
        for m in self._DIM.finditer(clean):
            name = m.group(2)
            if name in seen_var:
                continue
            seen_var.add(name)
            self._add_variable(
                file_id,
                name,
                (m.group(3) or "").strip()[:120] or None,
                scope=m.group(1).lower(),
            )

        seen_imp = set()
        for m in self._CREATE.finditer(clean):
            prog = m.group(1)
            if prog not in seen_imp:
                seen_imp.add(prog)
                self._add_import(file_id, prog, "com-object", alias="CreateObject")

        self._record_module_meta(
            file_id,
            procedures=len(seen_fn),
            classes=len(seen_cls),
            variables=len(seen_var),
        )


class WsfAnalyzer(ShellScriptBase):
    """Windows Script Files (.wsf) -- an XML container around one or more script
    jobs written in VBScript / JScript.

    ``<job id="...">``                          -> class (a script job)
    ``<script language="..." src="...">``        -> import (external script)
    ``<reference object="..."/>`` / ``<object>`` -> import
    inline ``Function/Sub name`` (VBScript)      -> function
    """

    LANG_KEY = "wsf"
    EXTENSIONS = (".wsf",)
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = (("<!--", "-->"),)
    STRING_DELIMS = ('"', "'")

    _JOB = re.compile(r'(?i)<job[ \t]+id[ \t]*=[ \t]*"([^"]+)"')
    _SRC = re.compile(r'(?i)<script\b[^>]*\bsrc[ \t]*=[ \t]*"([^"]+)"')
    _LANG = re.compile(r'(?i)<script\b[^>]*\blanguage[ \t]*=[ \t]*"([^"]+)"')
    _REF = re.compile(r'(?i)<reference\b[^>]*\bobject[ \t]*=[ \t]*"([^"]+)"')
    _OBJ = re.compile(r'(?i)<object\b[^>]*\bprogid[ \t]*=[ \t]*"([^"]+)"')
    _PROC = re.compile(r"(?mi)^[ \t]*(?:function|sub)[ \t]+([A-Za-z_]\w*)")

    def _register_types(self, file_id, text, path):
        for m in self._JOB.finditer(text):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_cls = set()
        for m in self._JOB.finditer(clean):
            name = m.group(1)
            if name not in seen_cls:
                seen_cls.add(name)
                self._add_class(file_id, name, description="wsf job")

        seen_imp = set()
        for m in self._SRC.finditer(clean):
            tgt = m.group(1)
            if tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword="script-src")
        for rx, kw in ((self._REF, "reference"), (self._OBJ, "object")):
            for m in rx.finditer(clean):
                tgt = m.group(1)
                if tgt not in seen_imp:
                    seen_imp.add(tgt)
                    self._add_import(file_id, tgt, "com-object", alias=kw)

        seen_fn = set()
        for m in self._PROC.finditer(clean):
            name = m.group(1)
            if name not in seen_fn:
                seen_fn.add(name)
                self._add_shell_function(file_id, name, description="wsf procedure")

        langs = self._uniq(l.lower() for l in self._LANG.findall(clean))
        self._record_module_meta(
            file_id,
            jobs=len(seen_cls),
            script_languages=langs or None,
            procedures=len(seen_fn),
        )
