# ColdFusion Component (.cfc) analyzer -- CFML, script and tag syntaxes.
#
#   script syntax:
#     import com.util.Logger                        -> import
#     component extends="Base" {                     -> class (+ parent)
#         property name="count" type="numeric";      -> variable
#         public numeric function add(numeric a) {}  -> function (+ output)
#         function init() { ... }                    -> function
#     }
#   tag syntax:
#     <cfcomponent extends="Base">                   -> class (+ parent)
#       <cfproperty name="count">                    -> variable
#       <cffunction name="add" returntype="numeric"> -> function
#         <cfargument name="a" type="numeric">       -> arg
#       </cffunction>
#     </cfcomponent>
#
# Comments: '//' and '/* */' (script), '<!--- --->' (tag); strings '"' and '\''.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"
_TYPE = r"(?:any|array|binary|boolean|component|date|guid|numeric|query|string|" \
        r"struct|uuid|void|xml|" + _ID + r")"


class ColdFusionAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "coldfusion"
    EXTENSIONS = (".cfc",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"), ("<!---", "--->"))
    STRING_DELIMS = ('"', "'")

    _IMPORT = re.compile(r"(?im)^\s*import\s+([\w.]+)\s*;?")
    _CFIMPORT = re.compile(r'(?i)<cfimport\b[^>]*\btaglib\s*=\s*["\']([^"\']+)["\']')

    _COMPONENT = re.compile(r"(?im)^\s*(?:(?:public|private|final|abstract|"
                            r"remote)\s+)*component\b([^\{]*)\{")
    _CFCOMPONENT = re.compile(r"(?i)<cfcomponent\b([^>]*)>")

    _FUNC = re.compile(r"(?im)^\s*(?:(?:public|private|package|remote|static|"
                       r"final|abstract)\s+)*(?:(" + _TYPE + r")\s+)?function\s+("
                       + _ID + r")\s*\(([^)]*)\)")
    _CFFUNCTION = re.compile(r"(?i)<cffunction\b([^>]*)>")
    _CFARGUMENT = re.compile(r"(?i)<cfargument\b([^>]*)>")

    _PROPERTY = re.compile(r"(?im)^\s*property\b([^;>\{]*);")
    _CFPROPERTY = re.compile(r"(?i)<cfproperty\b([^>]*)>")

    _ATTR = re.compile(r'(?i)\b(name|type|extends|returntype|default)\s*=\s*'
                       r'["\']([^"\']*)["\']')

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        stem = Path(path).stem
        if self._COMPONENT.search(clean) or self._CFCOMPONENT.search(text):
            self._register_class(stem)

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)
        stem = Path(path).stem

        for m in self._IMPORT.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, src.split(".")[-1], src)
        for m in self._CFIMPORT.finditer(text):
            src = m.group(1)
            self._add_import(file_id, re.split(r"[\\/.]", src)[-1], src)

        cls_id = None
        parent = None
        cm = self._COMPONENT.search(clean)
        if cm:
            attrs = dict(self._ATTR.findall(cm.group(1)))
            parent = attrs.get("extends")
        else:
            tm = self._CFCOMPONENT.search(text)
            if tm:
                attrs = dict(self._ATTR.findall(tm.group(1)))
                parent = attrs.get("extends")
        if cm or self._CFCOMPONENT.search(text):
            pids = None
            if parent:
                pids = [self._register_class(parent.split(".")[-1])]
            cls_id = self._register_class(stem)
            self._add_class(file_id, stem, description="cfc component",
                            parent_ids=pids)

        # script-syntax functions
        for m in self._FUNC.finditer(clean):
            args = self._script_args(m.group(3))
            outs = [self._add_output(m.group(1))] if m.group(1) else []
            self._add_function(file_id, m.group(2), args, outs, class_id=cls_id,
                               description="cfc function")
        # tag-syntax functions (with their nested <cfargument> tags)
        for m in self._CFFUNCTION.finditer(text):
            fattrs = dict(a.lower() for a in ()) or dict(
                (k.lower(), v) for k, v in self._ATTR.findall(m.group(1)))
            fname = fattrs.get("name")
            if not fname:
                continue
            end = self._tag_block_end(text, m.end(), "cffunction")
            arg_ids = []
            for am in self._CFARGUMENT.finditer(text[m.end():end]):
                aattrs = dict((k.lower(), v) for k, v in
                              self._ATTR.findall(am.group(1)))
                if aattrs.get("name"):
                    arg_ids.append(self._add_arg(aattrs["name"],
                                                 aattrs.get("type")))
            outs = ([self._add_output(fattrs["returntype"])]
                    if fattrs.get("returntype") else [])
            self._add_function(file_id, fname, arg_ids, outs, class_id=cls_id,
                               description="cfc function")

        # properties
        seen = set()
        for m in self._PROPERTY.finditer(clean):
            name = self._prop_name(m.group(1))
            if name and name not in seen:
                seen.add(name)
                self._add_variable(file_id, name, scope="property")
        for m in self._CFPROPERTY.finditer(text):
            attrs = dict((k.lower(), v) for k, v in
                         self._ATTR.findall(m.group(1)))
            name = attrs.get("name")
            if name and name not in seen:
                seen.add(name)
                self._add_variable(file_id, name, scope="property")

    def _prop_name(self, body):
        attrs = dict((k.lower(), v) for k, v in self._ATTR.findall(body))
        if attrs.get("name"):
            return attrs["name"]
        # `property numeric count;` positional form
        toks = re.findall(_ID, body)
        return toks[-1] if toks else None

    def _script_args(self, group):
        if not group or not group.strip():
            return []
        arg_ids = []
        for part in self._split_top_level(group):
            part = part.strip()
            if not part:
                continue
            part = re.sub(r"(?i)^required\s+", "", part)
            part = part.split("=")[0].strip()
            toks = re.findall(_ID, part)
            if not toks:
                continue
            name = toks[-1]
            atype = toks[0] if len(toks) >= 2 else None
            arg_ids.append(self._add_arg(name, atype))
        return arg_ids

    def _tag_block_end(self, text, start, tag):
        m = re.compile(r"(?i)</" + tag + r"\s*>").search(text, start)
        return m.start() if m else len(text)
