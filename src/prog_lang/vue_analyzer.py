# Vue single-file component (.vue) analyzer.
#
# A .vue file is an HTML-ish document with <template>, <script [setup]> and
# <style> blocks.  The behavioural code lives in <script>, which is JS or TS.
# This analyzer isolates the <script> region and extracts the same entities a
# JS/TS analyzer would (imports / functions / variables) plus the component's
# default-export object as a class row.  <template> / <style> are ignored (they
# carry no callable/type definitions), which is the honest scope for this ext.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class VueAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "vue"
    EXTENSIONS = (".vue",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)

    _SCRIPT = re.compile(r"<script\b[^>]*>(.*?)</script>", re.DOTALL | re.I)
    _IMPORT = re.compile(
        r"""^\s*import\s+(?:(.+?)\s+from\s+)?['"]([^'"]+)['"]""", re.MULTILINE)
    _FUNC = re.compile(
        r"^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)",
        re.MULTILINE)
    _ARROW = re.compile(
        r"^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?"
        r"\(([^)]*)\)\s*=>", re.MULTILINE)
    _VAR = re.compile(
        r"^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=(?!=)", re.MULTILINE)
    _NAME = re.compile(r"""\bname\s*:\s*['"](\w+)['"]""")

    def _script(self, text):
        return "\n".join(m.group(1) for m in self._SCRIPT.finditer(text))

    def _register_types(self, file_id, text, path):
        s = self._strip_comments(self._script(text))
        nm = self._NAME.search(s)
        if nm:
            self._register_class(nm.group(1))
        else:
            self._register_class(path.stem)

    def _extract_entities(self, file_id, text, path):
        s = self._strip_comments(self._script(text))

        for m in self._IMPORT.finditer(s):
            src = m.group(2)
            self._add_import(file_id, src.split("/")[-1], src,
                             alias=(m.group(1) or "").strip() or None)

        nm = self._NAME.search(s)
        comp = nm.group(1) if nm else path.stem
        self._add_class(file_id, comp, description="vue component")

        emitted = set()
        for m in self._FUNC.finditer(s):
            emitted.add(m.group(1))
            self._add_function(file_id, m.group(1), self._args(m.group(2)))
        for m in self._ARROW.finditer(s):
            if m.group(1) not in emitted:
                emitted.add(m.group(1))
                self._add_function(file_id, m.group(1), self._args(m.group(2)))
        for m in self._VAR.finditer(s):
            if m.group(1) not in emitted:
                self._add_variable(file_id, m.group(1))

    def _args(self, params):
        return [self._add_arg(p.split(":")[0].split("=")[0].strip())
                for p in self._split_top_level(params)
                if p.split(":")[0].split("=")[0].strip()]
