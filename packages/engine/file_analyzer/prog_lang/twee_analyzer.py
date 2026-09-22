# Twee (.twee, .tw) analyzer -- Twine interactive-fiction source (Twee3).
#
#     :: Passage Name                            -> function (passage)
#     :: Start [tag1 tag2]                       -> function (+ tag args)
#     :: StoryTitle                              -> function (special passage)
#     :: StoryData { "ifid": "..." }             -> function
#     [[Link->Target]] / [[Target]]              -> import (passage link)
#     <<set $health to 100>>                     -> variable
#     <<set _temp = 5>>                          -> variable
#
# Passages are emitted as FUNCTIONS, not classes: every Twine story reuses the
# names Start / StoryTitle / StoryData, and the base class registry dedups
# classes globally by name (which would blank out most files), whereas
# functions are per-file.  This also matches the Ink analyzer (knots->funcs).
#
# Comments: Harlowe/SugarCube macro comments vary; '/* */' inside passages.
# Strings use '"'. The '::' header marks passages.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class TweeAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "twee"
    EXTENSIONS = (".twee", ".tw")
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    # passage header:  :: Name  [optional tags]  {optional metadata}
    _PASSAGE = re.compile(
        r"(?m)^::\s*([^\[\{\n]+?)\s*(?:\[([^\]]*)\])?\s*(?:\{[^\}]*\})?\s*$"
    )
    # passage link:  [[label->target]] / [[target<-label]] / [[target]]
    _LINK = re.compile(r"\[\[([^\]]+?)\]\]")
    # SugarCube/Harlowe variable set:  <<set $var ...>>  or  (set: $var ...)
    _SETVAR = re.compile(r"[\$_](" + _ID + r")")

    def _register_types(self, file_id, text, path):
        # Passages are emitted as functions, so no class ids to reserve.
        return

    def _extract_entities(self, file_id, text, path):
        # NOTE: do not strip comments first -- passage bodies are prose and
        # '::' headers must be seen verbatim.  Only mine set-macros for vars.
        for m in self._PASSAGE.finditer(text):
            name = m.group(1).strip()
            if not name:
                continue
            arg_ids = []
            if m.group(2):
                for tag in m.group(2).split():
                    arg_ids.append(self._add_arg(tag, "tag"))
            self._add_function(file_id, name, arg_ids, [], description="twee passage")

        # passage links become imports (references to other passages)
        seen_links = set()
        for m in self._LINK.finditer(text):
            inner = m.group(1)
            # resolve display->target or target<-display or setter pipes
            target = inner
            if "->" in inner:
                target = inner.split("->", 1)[1]
            elif "<-" in inner:
                target = inner.split("<-", 1)[0]
            elif "|" in inner:
                target = inner.split("|", 1)[1]
            target = target.split("][")[0].strip()
            if target and target not in seen_links and not target.startswith("$"):
                seen_links.add(target)
                self._add_import(file_id, target, target)

        # variables from set-macros
        seen_vars = set()
        for block in re.findall(r"<<\s*set\b[^>]*>>", text) + re.findall(
            r"\(\s*set:[^)]*\)", text
        ):
            for vm in self._SETVAR.finditer(block):
                name = vm.group(1)
                if name not in seen_vars:
                    seen_vars.add(name)
                    self._add_variable(file_id, name, scope="story")
