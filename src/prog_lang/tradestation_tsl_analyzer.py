# TradeStation EasyLanguage script (.tsl).
#
# EasyLanguage is TradeStation's strategy/indicator language.  A script
# declares inputs, variables and arrays, and may define Methods:
#
#     inputs: Length( 14 ), Price( Close );
#     variables: AvgVal( 0 ), Counter( 0 );
#     arrays: Buffer[100]( 0 );
#
#     Method double Smooth( double src )
#     begin
#         Return src * 0.5;
#     end;
#
#     AvgVal = Average( Price, Length );
#     if AvgVal > 0 then Buy next bar at market;
#
# The recovered symbols:
#   * `inputs:` / `variables:` (`vars:`) / `arrays:` (`array:`) declarations
#     -> variable (one per declared name)
#   * `Method <type> Name( ... )`  -> function
# Crucially, EasyLanguage uses `{ ... }` as a BLOCK COMMENT (not braces for
# scope); `//` is a line comment and `(* ... *)` an alternate block comment.
# Keywords are case-insensitive.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class TradeStationTSLAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "tradestation_el"
    EXTENSIONS = (".tsl",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("{", "}"), ("(*", "*)"))
    STRING_DELIMS = ('"',)

    # a declaration section header + its body up to the terminating `;`
    _SECTION = re.compile(r"(?mis)\b(inputs?|variables?|vars?|arrays?|array)\s*:"
                          r"\s*(.*?);")
    _METHOD = re.compile(r"(?mi)^[ \t]*Method\s+(?:" + _ID + r")\s+(" + _ID +
                         r")\s*\(")
    # one declared entry:  Name( default )   or   Name[ size ]( default )
    _DECL = re.compile(r"(" + _ID + r")\s*(?:\[[^\]]*\])?\s*\(")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_v = set()
        for sec in self._SECTION.finditer(clean):
            kind = sec.group(1).lower().rstrip("s")
            scope = "array" if kind.startswith("array") else \
                    "input" if kind == "input" else "variable"
            for d in self._DECL.finditer(sec.group(2)):
                name = d.group(1)
                if name.lower() in seen_v:
                    continue
                seen_v.add(name.lower())
                self._add_variable(file_id, name, None, scope=scope)

        seen_fn = set()
        for m in self._METHOD.finditer(clean):
            name = m.group(1)
            if name.lower() in seen_fn:
                continue
            seen_fn.add(name.lower())
            self._add_function(file_id, name, [], [],
                               description="EasyLanguage method")
