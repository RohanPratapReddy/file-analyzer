# Svelte single-file component (.svelte) analyzer.
#
# A .svelte file mixes HTML markup with one or more <script> blocks holding the
# component logic (JS or TS).  This analyzer isolates the <script> region and
# extracts imports, functions and variables; `export let x` bindings are the
# component's props and are recorded as (exported) variables.  Markup and <style>
# are ignored -- they hold no callable/type definitions.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class SvelteAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "svelte"
    EXTENSIONS = (".svelte",)
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
    _PROP = re.compile(r"^\s*export\s+(?:let|const)\s+(\w+)", re.MULTILINE)
    _VAR = re.compile(
        r"^\s*(?:const|let|var)\s+(\w+)\s*=(?!=)", re.MULTILINE)

    def _script(self, text):
        return "\n".join(m.group(1) for m in self._SCRIPT.finditer(text))

    def _register_types(self, file_id, text, path):
        self._register_class(path.stem)

    def _extract_entities(self, file_id, text, path):
        s = self._strip_comments(self._script(text))

        for m in self._IMPORT.finditer(s):
            src = m.group(2)
            self._add_import(file_id, src.split("/")[-1], src,
                             alias=(m.group(1) or "").strip() or None)

        self._add_class(file_id, path.stem, description="svelte component")

        props = set()
        for m in self._PROP.finditer(s):
            props.add(m.group(1))
            self._add_variable(file_id, m.group(1), scope="prop", is_imported=False)

        emitted = set(props)
        for m in self._FUNC.finditer(s):
            if m.group(1) not in emitted:
                emitted.add(m.group(1))
                self._add_function(file_id, m.group(1), self._args(m.group(2)))
        for m in self._ARROW.finditer(s):
            if m.group(1) not in emitted:
                emitted.add(m.group(1))
                self._add_function(file_id, m.group(1), self._args(m.group(2)))
        for m in self._VAR.finditer(s):
            if m.group(1) not in emitted:
                emitted.add(m.group(1))
                self._add_variable(file_id, m.group(1))

    def _args(self, params):
        return [self._add_arg(p.split(":")[0].split("=")[0].strip())
                for p in self._split_top_level(params)
                if p.split(":")[0].split("=")[0].strip()]
