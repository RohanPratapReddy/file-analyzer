# Visual Basic 6 user control (.ctl).
#
# A .ctl file is a text-serialised VB6 UserControl: a `Begin VB.UserControl`
# object block describing the control and its child controls, followed by the
# `Attribute` header and the BASIC code module:
#
#     VERSION 5.00
#     Begin VB.UserControl Thermometer
#        ClientHeight = 3000
#        Begin VB.Label lblValue
#        End
#     End
#     Attribute VB_Name = "Thermometer"
#     Option Explicit
#     Private mValue As Double
#     Public Event Changed(ByVal v As Double)
#     Public Property Get Value() As Double
#     End Property
#     Private Sub Recalc()
#     End Sub
#
# Recovered symbols:
#   * `Begin VB.UserControl Name` / `Attribute VB_Name = "Name"`  -> class
#   * child `Begin VB.<Type> name` object blocks   -> variable, scope "control"
#   * `[modifiers] Sub|Function|Property Get|Let|Set Name(`       -> function
#   * module-level `Private|Public|Dim|Global|Friend [WithEvents] name As ...`
#     and `Const name = ...`                                      -> variable
# `'` and `REM` start comments; `"` delimits strings; keywords are
# case-insensitive.
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class VBUserControlAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "vb_usercontrol"
    EXTENSIONS = (".ctl",)
    LINE_COMMENTS = ("'",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _UC = re.compile(r"(?mi)^[ \t]*Begin\s+VB\.UserControl\s+(" + _ID + r")\b")
    _VBNAME = re.compile(r'(?mi)^[ \t]*Attribute\s+VB_Name\s*=\s*"([^"]+)"')
    _CHILD = re.compile(
        r"(?mi)^[ \t]*Begin\s+(?:VB|MSComctlLib|[A-Za-z0-9_]+)\."
        r"(?!UserControl\b)" + _ID + r"\s+(" + _ID + r")\b"
    )
    _PROC = re.compile(
        r"(?mi)^[ \t]*(?:(?:Public|Private|Friend|Static)\s+)*"
        r"(?:Sub|Function|Property\s+(?:Get|Let|Set))\s+(" + _ID + r")\s*\("
    )
    _DECL = re.compile(
        r"(?mi)^[ \t]*(?:Private|Public|Dim|Global|Friend)\s+"
        r"(?:WithEvents\s+)?(" + _ID + r")\s+As\b"
    )
    _CONST = re.compile(
        r"(?mi)^[ \t]*(?:(?:Private|Public|Global|Friend)\s+)?"
        r"Const\s+(" + _ID + r")\s*="
    )

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_c = set()
        for rx in (self._UC, self._VBNAME):
            for m in rx.finditer(clean):
                name = m.group(1)
                if name not in seen_c:
                    seen_c.add(name)
                    self._add_class(file_id, name, description="VB6 user control")

        seen_fn = set()
        for m in self._PROC.finditer(clean):
            name = m.group(1)
            if name not in seen_fn:
                seen_fn.add(name)
                self._add_function(file_id, name, [], [], description="VB6 procedure")

        seen_v = set()
        for m in self._CHILD.finditer(clean):
            name = m.group(1)
            if name not in seen_v:
                seen_v.add(name)
                self._add_variable(file_id, name, None, scope="control")
        for rx in (self._DECL, self._CONST):
            for m in rx.finditer(clean):
                name = m.group(1)
                if name not in seen_v:
                    seen_v.add(name)
                    self._add_variable(file_id, name, None, scope="module")
