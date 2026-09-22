# Astro component (.astro) analyzer.
#
# An .astro file begins with an optional "code fence" -- a --- delimited block
# of JavaScript/TypeScript "component script" -- followed by HTML template
# markup.  All imports, functions and variables live in the fence (and in inline
# <script> tags); this analyzer isolates those regions and extracts the same
# entities a JS/TS analyzer would.  The HTML template carries no definitions.
import re

from .regex_base import RegexCodeAnalyzer


class AstroAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "astro"
    EXTENSIONS = (".astro",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)

    _FENCE = re.compile(r"^---\s*\n(.*?)\n---\s*$", re.DOTALL | re.MULTILINE)
    _SCRIPT = re.compile(r"<script\b[^>]*>(.*?)</script>", re.DOTALL | re.I)
    _IMPORT = re.compile(
        r"""^\s*import\s+(?:(.+?)\s+from\s+)?['"]([^'"]+)['"]""", re.MULTILINE
    )
    _FUNC = re.compile(
        r"^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)", re.MULTILINE
    )
    _ARROW = re.compile(
        r"^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*(?::[^=]+)?=\s*"
        r"(?:async\s+)?\(([^)]*)\)\s*=>",
        re.MULTILINE,
    )
    _VAR = re.compile(
        r"^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*(?::[^=]+)?=(?!=)", re.MULTILINE
    )
    _INTERFACE = re.compile(r"^\s*(?:export\s+)?interface\s+(\w+)", re.MULTILINE)

    def _code(self, text):
        parts = []
        fm = self._FENCE.search(text)
        if fm:
            parts.append(fm.group(1))
        for sm in self._SCRIPT.finditer(text):
            parts.append(sm.group(1))
        return "\n".join(parts)

    def _register_types(self, file_id, text, path):
        c = self._strip_comments(self._code(text))
        for m in self._INTERFACE.finditer(c):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        c = self._strip_comments(self._code(text))

        for m in self._IMPORT.finditer(c):
            src = m.group(2)
            self._add_import(
                file_id,
                src.split("/")[-1],
                src,
                alias=(m.group(1) or "").strip() or None,
            )

        for m in self._INTERFACE.finditer(c):
            self._add_class(file_id, m.group(1), description="astro interface")

        emitted = set()
        for m in self._FUNC.finditer(c):
            emitted.add(m.group(1))
            self._add_function(file_id, m.group(1), self._args(m.group(2)))
        for m in self._ARROW.finditer(c):
            if m.group(1) not in emitted:
                emitted.add(m.group(1))
                self._add_function(file_id, m.group(1), self._args(m.group(2)))
        for m in self._VAR.finditer(c):
            if m.group(1) not in emitted:
                self._add_variable(file_id, m.group(1))

    def _args(self, params):
        return [
            self._add_arg(p.split(":")[0].split("=")[0].strip())
            for p in self._split_top_level(params)
            if p.split(":")[0].split("=")[0].strip()
        ]
