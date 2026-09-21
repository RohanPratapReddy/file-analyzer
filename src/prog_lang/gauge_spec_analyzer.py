# Gauge test specification (.spec).
#
# A Gauge `.spec` file is a Markdown-based acceptance test: one level-1 heading
# names the specification, each level-2 heading names a scenario, and `* `
# bullet lines are executable steps that bind to step implementations elsewhere.
# Both ATX (`#`, `##`) and setext (underlined with `===` / `---`) headings occur.
#
#     # User sign-up                       <- spec           -> class
#     tags: smoke, auth                    <- tags           -> variable (scope "tag")
#
#     ## Register with a valid email       <- scenario       -> function
#     * Navigate to "the sign-up page"     <- step           -> variable (scope "step")
#     * Enter <username> and <password>
#     * The account should be created
#
#     Search results          (setext H1)
#     =============
#     By keyword              (setext H2)
#     ----------
#
# `<!-- -->` are comments; `"` / `<param>` are step arguments (kept inline in
# the step text).  Step / heading names may contain spaces.
import re
from .regex_base import RegexCodeAnalyzer

_ATX_H1 = re.compile(r"^[ \t]*#(?!#)\s*(.+?)\s*#*\s*$")
_ATX_H2 = re.compile(r"^[ \t]*##(?!#)\s*(.+?)\s*#*\s*$")
_STEP = re.compile(r"^[ \t]*\*\s+(.+?)\s*$")
_TAGS = re.compile(r"^[ \t]*[Tt]ags?\s*:\s*(.+)$")
_SETEXT_1 = re.compile(r"^=+\s*$")
_SETEXT_2 = re.compile(r"^-+\s*$")


class GaugeSpecAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "gauge_spec"
    EXTENSIONS = (".spec",)
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = (("<!--", "-->"),)
    STRING_DELIMS = ()

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)
        lines = clean.splitlines()

        seen_c, seen_fn, seen_v = set(), set(), set()

        def add_spec(name):
            name = name.strip()
            if name and name not in seen_c:
                seen_c.add(name)
                self._add_class(file_id, name, description="Gauge specification")

        def add_scenario(name):
            name = name.strip()
            if name and name not in seen_fn:
                seen_fn.add(name)
                self._add_function(file_id, name, [], [],
                                   description="Gauge scenario")

        def add_var(name, scope):
            name = name.strip()
            key = (scope, name)
            if name and key not in seen_v:
                seen_v.add(key)
                self._add_variable(file_id, name, None, scope=scope)

        n = len(lines)
        for i, ln in enumerate(lines):
            nxt = lines[i + 1] if i + 1 < n else ""
            m = _ATX_H1.match(ln)
            if m:
                add_spec(m.group(1))
                continue
            m = _ATX_H2.match(ln)
            if m:
                add_scenario(m.group(1))
                continue
            # setext: a non-blank text line underlined by === or ---
            if ln.strip() and not ln.lstrip().startswith(("*", "|", "#")):
                if _SETEXT_1.match(nxt):
                    add_spec(ln.strip())
                    continue
                if _SETEXT_2.match(nxt):
                    add_scenario(ln.strip())
                    continue
            m = _TAGS.match(ln)
            if m:
                for tag in m.group(1).split(","):
                    add_var(tag, "tag")
                continue
            m = _STEP.match(ln)
            if m:
                add_var(m.group(1), "step")
