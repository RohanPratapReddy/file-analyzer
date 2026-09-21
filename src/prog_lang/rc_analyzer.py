# Windows Resource Script (.rc).
#
# An `.rc` file feeds the resource compiler (rc.exe / windres); it mixes C
# preprocessor lines with resource-definition statements:
#
#     #include "resource.h"
#     #define IDD_ABOUT 103
#     IDD_ABOUT DIALOGEX 0, 0, 300, 200
#     CAPTION "About"
#     BEGIN
#         PUSHBUTTON "OK", IDOK, 120, 170, 50, 14
#     END
#     IDR_MAINFRAME MENU        BEGIN ... END
#     IDI_APP       ICON        "app.ico"
#     STRINGTABLE   BEGIN  IDS_TITLE "My App"  END
#
#   #include "x"                          -> import
#   #define NAME value                    -> variable
#   NAME <resource-type> ...              -> class   (DIALOG/MENU/TOOLBAR/...)
#   NAME ICON|BITMAP|CURSOR|FONT "file"   -> class + the file           -> import
#   STRINGTABLE entries  IDS_x "text"     -> variable
#
# Uses C comments (`//`, `/* */`).  Resource ids are C identifiers or numbers.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"
_RESTYPES = ("DIALOGEX", "DIALOG", "MENUEX", "MENU", "TOOLBAR", "ACCELERATORS",
             "VERSIONINFO", "RCDATA", "DLGINIT", "HTML", "MESSAGETABLE",
             "DESIGNINFO")
_FILETYPES = ("ICON", "BITMAP", "CURSOR", "FONT", "PNG", "WAVE", "AVI")


class RcAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "rc"
    EXTENSIONS = (".rc",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _INCLUDE = re.compile(r'(?m)^\s*#\s*include\s+[<"]([^>"]+)[>"]')
    _DEFINE = re.compile(r"(?m)^\s*#\s*define\s+(" + _ID + r")(?:\s+(.+))?$")
    _RES = re.compile(r"(?m)^(" + _ID + r"|\d+)[ \t]+(" + "|".join(_RESTYPES) + r")\b")
    _FILERES = re.compile(r'(?m)^(' + _ID + r'|\d+)[ \t]+(' + "|".join(_FILETYPES) +
                          r')[ \t]+(?:(?:MOVEABLE|PURE|DISCARDABLE|LOADONCALL|'
                          r'PRELOAD|FIXED)[ \t]+)*"([^"]+)"')
    _STRTAB = re.compile(r"(?m)^\s*STRINGTABLE\b")
    _STRENT = re.compile(r"(?m)^\s*(" + _ID + r")\s*,?\s*\"")

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._RES.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INCLUDE.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, src.split("/")[-1].split("\\")[-1], src)

        seen_v = set()
        for m in self._DEFINE.finditer(clean):
            nm = m.group(1)
            if nm in seen_v:
                continue
            seen_v.add(nm)
            self._add_variable(file_id, nm, (m.group(2) or "").strip()[:80],
                               scope="macro")

        seen_c = set()
        for m in self._RES.finditer(clean):
            nm, kind = m.group(1), m.group(2)
            if nm in seen_c:
                continue
            seen_c.add(nm)
            self._add_class(file_id, nm, description="resource " + kind.lower())

        for m in self._FILERES.finditer(clean):
            nm, kind, fn = m.group(1), m.group(2), m.group(3)
            if nm not in seen_c:
                seen_c.add(nm)
                self._add_class(file_id, nm, description="resource " + kind.lower())
            self._add_import(file_id, fn.split("\\")[-1].split("/")[-1], fn)

        # STRINGTABLE entries: identifiers followed by a quoted string inside a
        # BEGIN/END that opened right after a STRINGTABLE statement.
        for tab in self._STRTAB.finditer(clean):
            beg = clean.find("BEGIN", tab.end())
            if beg == -1:
                continue
            end = clean.find("END", beg)
            if end == -1:
                end = len(clean)
            body = clean[beg + 5:end]
            for m in self._STRENT.finditer(body):
                nm = m.group(1)
                if nm in seen_v:
                    continue
                seen_v.add(nm)
                self._add_variable(file_id, nm, "string-table entry", scope="string")
