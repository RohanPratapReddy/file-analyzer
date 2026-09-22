# Visual Basic .NET (.vb / .bas / .frm) analyzer.
#
# Real parser for VB.NET / VB (case-insensitive; "'" and REM line comments; no
# block comments; strings "..."):
#   Imports System.Collections.Generic                   -> import
#   Public Class Widget : Inherits Control                -> class (+ parent)
#       Implements IDrawable                              -> parent (interface)
#       Private _w As Integer                             -> attribute
#       Public Property Width As Integer                  -> attribute
#       Public Sub New(w As Integer)                       -> method
#       Public Function Area(h As Integer) As Integer      -> method
#   End Class
#   Module Helpers ... End Module                          -> module (class row)
#   Structure Point ... End Structure                      -> struct (class row)
#   Enum Color : Red : Green : End Enum                    -> enum (class row)
import re

from .regex_base import RegexCodeAnalyzer

_TYPE_KW = ("class", "module", "structure", "interface", "enum")


class VBAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "vbnet"
    EXTENSIONS = (".vb", ".bas", ".frm")
    LINE_COMMENTS = ("'",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _MODS = (
        r"(?:(?:public|private|protected|friend|shared|overridable|"
        r"overrides|mustinherit|notinheritable|partial|readonly|"
        r"mustoverride|shadows|default|static|widening|narrowing|"
        r"protected\s+friend|friend\s+protected)\s+)*"
    )
    _IMPORT = re.compile(r"^\s*Imports\s+([\w.]+)(?:\s*=\s*[\w.]+)?", re.IGNORECASE)
    _TYPE = re.compile(
        r"^\s*" + _MODS + r"(" + "|".join(_TYPE_KW) + r")\s+([A-Za-z_]\w*)"
        r"(?:\s*\(\s*Of\s+[^)]*\))?"
        r"(?:\s+Inherits\s+([\w.]+))?",
        re.IGNORECASE,
    )
    _INHERITS = re.compile(r"^\s*(?:Inherits|Implements)\s+([\w.,\s]+)$", re.IGNORECASE)
    _END_TYPE = re.compile(r"^\s*End\s+(" + "|".join(_TYPE_KW) + r")\b", re.IGNORECASE)
    _METHOD = re.compile(
        r"^\s*" + _MODS + r"(?:async\s+|iterator\s+)?(Sub|Function|Operator)\s+"
        r"([A-Za-z_]\w*|New)\s*"
        r"(?:\(\s*Of\s+[^)]*\)\s*)?"
        r"(?:\(([^)]*)\))?"
        r"(?:\s+As\s+([\w.\[\]()]+))?",
        re.IGNORECASE,
    )
    _DECLARE = re.compile(
        r"^\s*" + _MODS + r"Declare\s+(?:Ansi\s+|Unicode\s+|Auto\s+)?"
        r"(?:Sub|Function)\s+([A-Za-z_]\w*)",
        re.IGNORECASE,
    )
    _PROPERTY = re.compile(
        r"^\s*" + _MODS + r"(?:readonly\s+|writeonly\s+|default\s+)*"
        r"Property\s+([A-Za-z_]\w*)(?:\s*\(([^)]*)\))?"
        r"(?:\s+As\s+([\w.\[\]()]+))?",
        re.IGNORECASE,
    )
    _FIELD = re.compile(
        r"^\s*(?:" + _MODS + r"|Dim\s+|Const\s+|Dim\s+Shared\s+)"
        r"([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+As\s+([\w.\[\]()]+)",
        re.IGNORECASE,
    )
    _DIM = re.compile(
        r"^\s*(?:Dim|Const|Private|Public|Friend|Protected)\s+"
        r"([A-Za-z_]\w*)\s*(?:As\s+[\w.\[\]()]+)?",
        re.IGNORECASE,
    )

    def _clean(self, text):
        text = self._strip_comments(text)
        # strip REM comments (whole line)
        out = []
        for line in text.splitlines():
            if re.match(r"^\s*REM\b", line, re.IGNORECASE):
                out.append("")
            else:
                out.append(line)
        return "\n".join(out)

    def _register_types(self, file_id, text, path):
        for line in self._clean(text).splitlines():
            m = self._TYPE.match(line)
            if m:
                self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        lines = self._clean(text).splitlines()

        for line in lines:
            im = self._IMPORT.match(line)
            if im:
                mod = im.group(1)
                self._add_import(file_id, mod.split(".")[-1], mod)

        stack = []  # container dicts
        containers = []
        i, n = 0, len(lines)
        while i < n:
            line = lines[i]

            tm = self._TYPE.match(line)
            if tm:
                kind, name, inh = tm.group(1).lower(), tm.group(2), tm.group(3)
                parents = []
                if inh:
                    for p in inh.split(","):
                        p = p.strip().split(".")[-1]
                        if p in self._class_registry:
                            parents.append(self._class_registry[p])
                d = {
                    "name": name,
                    "kind": kind,
                    "parents": parents,
                    "methods": [],
                    "attrs": [],
                    "enum": kind == "enum",
                }
                containers.append(d)
                stack.append(d)
                i += 1
                continue

            if self._END_TYPE.match(line):
                if stack:
                    stack.pop()
                i += 1
                continue

            ihm = self._INHERITS.match(line)
            if ihm and stack:
                for p in ihm.group(1).split(","):
                    p = p.strip().split(".")[-1]
                    if p in self._class_registry:
                        cid = self._class_registry[p]
                        if cid not in stack[-1]["parents"]:
                            stack[-1]["parents"].append(cid)
                i += 1
                continue

            dm = self._DECLARE.match(line)
            if dm:
                owner = stack[-1] if stack else None
                cid = self._class_registry.get(owner["name"]) if owner else None
                fid = self._add_function(
                    file_id, dm.group(1), [], [], class_id=cid, description="vb declare"
                )
                if owner:
                    owner["methods"].append(fid)
                i += 1
                continue

            mm = self._METHOD.match(line)
            if mm:
                name = mm.group(2)
                arg_ids = self._params(mm.group(3) or "")
                out_ids = [self._add_output(mm.group(4))] if mm.group(4) else []
                owner = stack[-1] if stack else None
                cid = self._class_registry.get(owner["name"]) if owner else None
                fid = self._add_function(file_id, name, arg_ids, out_ids, class_id=cid)
                if owner:
                    owner["methods"].append(fid)
                i += 1
                continue

            pm = self._PROPERTY.match(line)
            if pm and stack:
                stack[-1]["attrs"].append(self._add_arg(pm.group(1), pm.group(3)))
                i += 1
                continue

            if stack and stack[-1]["enum"]:
                em = re.match(r"^\s*([A-Za-z_]\w*)\s*(?:=\s*[^\n]+)?$", line)
                if em and em.group(1).lower() not in ("end",):
                    stack[-1]["attrs"].append(self._add_arg(em.group(1), "enumvalue"))
                i += 1
                continue

            fm = self._FIELD.match(line)
            if fm and not re.match(
                r"^\s*(Sub|Function|Property|End|If|For|While|"
                r"Select|Return|Set|Get)\b",
                line,
                re.IGNORECASE,
            ):
                names, ftype = fm.group(1), fm.group(2)
                owner = stack[-1] if stack else None
                for nm in names.split(","):
                    nm = nm.strip()
                    if not nm:
                        continue
                    if owner is not None:
                        owner["attrs"].append(self._add_arg(nm, ftype))
                    else:
                        self._add_variable(file_id, nm, None)
                i += 1
                continue

            i += 1

        for c in containers:
            self._add_class(
                file_id,
                c["name"],
                description=f"vb {c['kind']}",
                parent_ids=c["parents"],
                method_ids=c["methods"],
                attr_ids=c["attrs"],
            )

    def _params(self, params):
        arg_ids = []
        for part in self._split_top_level(params):
            part = part.strip()
            if not part:
                continue
            part = re.sub(
                r"(?i)^(byval|byref|optional|paramarray)\s+", "", part
            ).strip()
            part = re.sub(
                r"(?i)^(byval|byref|optional|paramarray)\s+", "", part
            ).strip()
            m = re.match(
                r"([A-Za-z_]\w*)\s*(?:As\s+([\w.\[\]()]+))?", part, re.IGNORECASE
            )
            if m:
                default = None
                if "=" in part:
                    default = part.split("=", 1)[1].strip()
                arg_ids.append(self._add_arg(m.group(1), m.group(2), default))
        return arg_ids
