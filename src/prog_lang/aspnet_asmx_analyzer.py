# ASP.NET web service (.asmx).
#
# An .asmx file starts with a `WebService` directive and may carry the service
# implementation inline (or delegate it to a code-behind file):
#
#     <%@ WebService Language="C#" Class="Acme.Services.Quote" %>
#     using System;
#     using System.Web.Services;
#     namespace Acme.Services {
#       public class Quote : WebService {
#         [WebMethod]
#         public double GetPrice(string sym) { return 1.0; }
#       }
#     }
#
# Recovered symbols:
#   * the `Class="..."` directive attribute        -> class (the service class)
#   * `CodeBehind|CodeFile|Src="..."` attribute     -> import (code-behind file)
#   * inline `using Ns;`                             -> import
#   * inline `class Name` / `namespace Name`         -> class
#   * inline `[modifiers] Type Name( ... )` methods  -> function
# `//` and `/* ... */` are the inline-C# comments; the directive itself is a
# single `<%@ ... %>` tag.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"
_QUAL = _ID + r"(?:\." + _ID + r")*"
_DIRECTIVE_KW = "WebService"
_DIRECTIVE_DESC = "ASP.NET web service"


class AspNetAsmxAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "aspnet_asmx"
    EXTENSIONS = (".asmx",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _CLASS_ATTR = re.compile(r'(?is)<%@\s*' + _DIRECTIVE_KW +
                             r'\b[^%]*?\bClass\s*=\s*"([^"]+)"')
    _CODE_ATTR = re.compile(r'(?is)<%@\s*' + _DIRECTIVE_KW +
                            r'\b[^%]*?\b(?:CodeBehind|CodeFile|Src)\s*=\s*'
                            r'"([^"]+)"')
    _USING = re.compile(r"(?m)^[ \t]*using\s+(?:static\s+)?(" + _QUAL + r")\s*;")
    _NS = re.compile(r"(?m)^[ \t]*namespace\s+(" + _QUAL + r")\b")
    _CLASS = re.compile(r"(?m)\b(?:class|struct|interface|enum)\s+(" + _ID +
                        r")\b")
    _METHOD = re.compile(r"(?m)^[ \t]*(?:\[[^\]]*\]\s*)*"
                         r"(?:public|private|protected|internal|static|"
                         r"virtual|override|async|sealed|new|\s)+"
                         r"(?:" + _QUAL + r"(?:<[^>]+>)?(?:\[\])?)\s+"
                         r"(" + _ID + r")\s*\(")

    def _extract_entities(self, file_id, text, path):
        # Directive attributes must be read from the raw text (the comment
        # stripper is tuned for the inline C#, not the `<%@ %>` tag).
        seen_c = set()
        for m in self._CLASS_ATTR.finditer(text):
            qual = m.group(1)
            name = qual.split(",")[0].strip().split(".")[-1]
            if name and name not in seen_c:
                seen_c.add(name)
                self._add_class(file_id, name, description=_DIRECTIVE_DESC)

        seen_i = set()
        for m in self._CODE_ATTR.finditer(text):
            src = m.group(1)
            if src not in seen_i:
                seen_i.add(src)
                self._add_import(file_id, src.replace("\\", "/").split("/")[-1],
                                 src)

        clean = self._strip_comments(text)

        for m in self._USING.finditer(clean):
            src = m.group(1)
            if src not in seen_i:
                seen_i.add(src)
                self._add_import(file_id, src.split(".")[-1], src)

        for rx, desc in ((self._NS, "C# namespace"), (self._CLASS, "C# type")):
            for m in rx.finditer(clean):
                name = m.group(1).split(".")[-1]
                if name not in seen_c:
                    seen_c.add(name)
                    self._add_class(file_id, name, description=desc)

        seen_fn = set()
        _KW = {"if", "for", "foreach", "while", "switch", "catch", "using",
               "lock", "return", "get", "set", "new", "fixed"}
        for m in self._METHOD.finditer(clean):
            name = m.group(1)
            if name in _KW or name in seen_fn:
                continue
            seen_fn.add(name)
            self._add_function(file_id, name, [], [], description="C# method")
