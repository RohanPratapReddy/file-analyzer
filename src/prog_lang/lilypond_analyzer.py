# LilyPond (.ly, .ily) analyzer -- music engraving language.
#
#     \include "articulate.ly"                   -> import
#     melody = \relative c' { c d e f }          -> variable (music expression)
#     global = { \key c \major }                 -> variable
#     #(define (my-func x) (* x 2))              -> function (embedded Scheme)
#     #(define my-const 42)                      -> variable (embedded Scheme)
#     myMusic = \new Staff { ... }               -> variable
#
# Comments are '%' (line) and '%{ %}' (block); strings use '"'.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z][A-Za-z]*"  # LilyPond identifiers: letters only
_SCHEME_ID = r"[A-Za-z_][A-Za-z0-9_!?%*/+.<>=-]*"


class LilyPondAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "lilypond"
    EXTENSIONS = (".ly", ".ily")
    LINE_COMMENTS = ("%",)
    BLOCK_COMMENTS = (("%{", "%}"),)
    STRING_DELIMS = ('"',)

    _INCLUDE = re.compile(r'(?m)^\s*\\include\s+"([^"]+)"')
    # top-level assignment:  name = <value>
    _ASSIGN = re.compile(r"(?m)^\s*(" + _ID + r")\s*=\s*(\S)")
    # embedded Scheme function:  #(define (fname args) ...)
    _SCM_FUNC = re.compile(
        r"#\(\s*define(?:-public|-session-public|-session)?\s*"
        r"\(\s*(" + _SCHEME_ID + r")"
    )
    # LilyPond markup commands name the function as the first token:
    #   #(define-markup-command (name layout props ...) ...)
    #   #(define-markup-list-command (name ...) ...)
    _SCM_MARKUP = re.compile(
        r"#\(\s*define-markup(?:-list)?-command\s*" r"\(\s*(" + _SCHEME_ID + r")"
    )
    # embedded Scheme constant:  #(define name value)
    _SCM_VAR = re.compile(
        r"#\(\s*define(?:-public|-session-public|-session)?\s+(" + _SCHEME_ID + r")\b"
    )

    def _register_types(self, file_id, text, path):
        # LilyPond has no class-like constructs.
        return

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INCLUDE.finditer(clean):
            src = m.group(1)
            leaf = re.split(r"[\\/]", src)[-1]
            self._add_import(file_id, leaf, src)

        seen = set()
        for m in self._ASSIGN.finditer(clean):
            name = m.group(1)
            if name in seen:
                continue
            seen.add(name)
            self._add_variable(file_id, name, scope="music")

        for m in self._SCM_FUNC.finditer(clean):
            name = m.group(1)
            args = self._scm_args(clean, m.end())
            self._add_function(file_id, name, args, [], description="scheme definition")

        for m in self._SCM_MARKUP.finditer(clean):
            name = m.group(1)
            args = self._scm_args(clean, m.end())
            self._add_function(file_id, name, args, [], description="markup command")

        for m in self._SCM_VAR.finditer(clean):
            # skip if it was actually a function form `(define (name ...))`
            after = clean[m.start() : m.end() + 1]
            self._add_variable(file_id, m.group(1), scope="scheme")

    def _scm_args(self, clean, after_name):
        # cursor is just past fname inside `(define (fname `; collect until ')'
        end = clean.find(")", after_name)
        if end == -1:
            return []
        body = clean[after_name:end]
        arg_ids = []
        for tok in body.replace("(", " ").split():
            tok = tok.strip()
            if tok and re.match(r"[A-Za-z_]", tok):
                arg_ids.append(self._add_arg(tok))
        return arg_ids
