# Microsoft Dynamics NAV / C-AL object file (.nav).
#
# A NAV text export holds one or more application objects written in C/AL:
#
#     OBJECT Table 18 Customer
#     {
#       PROPERTIES { ... }
#       FIELDS
#       {
#         { 1 ; ; No.          ; Code20    }
#         { 2 ; ; Name         ; Text50    }
#       }
#       CODE
#       {
#         VAR
#           CustLedgEntry@1000 : Record 21;
#         PROCEDURE CalcBalance@1(Date : Date) : Decimal;
#         BEGIN
#           ...
#         END;
#         LOCAL PROCEDURE Helper@2();
#         BEGIN END;
#       }
#     }
#
# The recovered symbols:
#   * `OBJECT <Type> <id> <Name>`             -> class (Type+id as description)
#   * `PROCEDURE` / `LOCAL PROCEDURE` / event `TRIGGER`  -> function
#   * `VAR`-block declarations `Name@n : Type;`          -> variable
#   * table `FIELDS { { n ; ; Name ; Type } }`           -> variable (a field)
# `//` starts a comment; `{ }` are structural braces (NOT comments in C/AL).
import re

from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class DynamicsNAVAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "dynamics_nav"
    EXTENSIONS = (".nav",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _OBJECT = re.compile(r"(?mi)^[ \t]*OBJECT\s+(" + _ID + r")\s+(\d+)\s+(.+?)\s*$")
    _PROC = re.compile(
        r"(?mi)^[ \t]*(?:LOCAL\s+)?PROCEDURE\s+([A-Za-z_][\w]*)" r"(?:@\d+)?\s*\("
    )
    _TRIGGER = re.compile(
        r"(?mi)^[ \t]*(?:LOCAL\s+)?TRIGGER\s+([A-Za-z_][\w]*)" r"(?:@\d+)?\s*\("
    )
    # a C/AL variable declaration inside a VAR block:  Name@1001 : Record 18;
    _VARDECL = re.compile(r"(?m)^[ \t]*(" + _ID + r")@\d+\s*:\s*([^;]+);")
    # a table field line:  { 2 ; ; Name ; Text50 ; ... }
    _FIELD = re.compile(r"(?m)^[ \t]*\{\s*\d+\s*;\s*;\s*([^;]+?)\s*;")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._OBJECT.finditer(clean):
            otype, oid, name = m.group(1), m.group(2), m.group(3).strip()
            self._add_class(file_id, name, description=f"NAV {otype} {oid}")

        seen_fn = set()
        for rx, desc in (
            (self._PROC, "C/AL procedure"),
            (self._TRIGGER, "C/AL trigger"),
        ):
            for m in rx.finditer(clean):
                name = m.group(1)
                if name in seen_fn:
                    continue
                seen_fn.add(name)
                self._add_function(file_id, name, [], [], description=desc)

        seen_v = set()
        for m in self._VARDECL.finditer(clean):
            name = m.group(1)
            if name in seen_v:
                continue
            seen_v.add(name)
            self._add_variable(file_id, name, m.group(2).strip(), scope="local")
        for m in self._FIELD.finditer(clean):
            name = m.group(1).strip()
            key = ("field", name)
            if not name or key in seen_v:
                continue
            seen_v.add(key)
            self._add_variable(file_id, name, None, scope="field")
