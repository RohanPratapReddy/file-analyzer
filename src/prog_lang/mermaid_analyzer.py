# Mermaid diagram (.mermaid) analyzer.
#
# A Mermaid file opens with a diagram-type keyword and then declares structure.
# We map the structural declarations onto the relational model:
#
#     classDiagram
#       class Animal { +int age; +run() }      -> class Animal (+attr/+method)
#       Animal : +String name                    -> attr on Animal (external member)
#       Animal : +run()                          -> method on Animal
#       Animal <|-- Dog                          -> parent link (Dog : Animal)
#       Animal o-- Leg                            -> both endpoints are classes
#     sequenceDiagram
#       participant Alice as A                   -> class (participant)
#       actor Bob                                -> class
#       Alice ->> John : Hi                      -> lifelines (variables)
#     flowchart LR
#       subgraph cluster ... end                 -> class (subgraph)
#       A[Start] --> B{Choice}                   -> variable (node, each)
#       A --> B                                  -> bare-edge nodes (variables)
#     erDiagram
#       CUSTOMER { string name }                 -> class (entity, fields=attrs)
#     stateDiagram-v2
#       state Foo                                -> variable (state)
#
# A leading `--- ... ---` YAML front-matter block (title/config) is skipped when
# detecting the diagram type.  Comments are '%%'; strings use '"'.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_][A-Za-z0-9_]*"


class MermaidAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "mermaid"
    EXTENSIONS = (".mermaid",)
    LINE_COMMENTS = ("%%",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _CLASSDEF = re.compile(r"(?m)^\s*class\s+(" + _ID + r")\s*(?:\[[^\]]*\])?\s*(\{)?")
    _MEMBER = re.compile(r"(?m)^\s*[+\-#~]?\s*([A-Za-z_][\w]*)\s*(\()?")
    # `Class : member` external member declaration (attribute or method).
    _CMEMBER = re.compile(r"(?m)^\s*(" + _ID + r")\s*:\s*(\S.*)$")
    _INHERIT = re.compile(r"(?m)^\s*(" + _ID + r")\s*<\|(?:--|\.\.)\s*(" + _ID + r")")
    # Any class relation: association/composition/aggregation/dependency/realization.
    _REL = re.compile(
        r"(?m)^\s*(" + _ID + r")\s*(?:\"[^\"]*\"\s*)?"
        r"[<*o|}]?[.\-]{2,}[|>*o{]?\s*(?:\"[^\"]*\"\s*)?(" + _ID + r")\b")
    _PARTICIPANT = re.compile(r"(?m)^\s*(?:participant|actor)\s+(" + _ID + r")")
    _SEQ_MSG = re.compile(
        r"(?m)^\s*(" + _ID + r")\s*"
        r"(?:<<)?[-x]?(?:--?|==?)[>x)]{1,2}(?:>>)?\s*"
        r"([+\-]?\s*" + _ID + r")")
    _SUBGRAPH = re.compile(r"(?m)^\s*subgraph\s+(?:\"([^\"]+)\"|(" + _ID + r"))")
    _ENTITY = re.compile(r"(?m)^\s*([A-Za-z_][\w]*)\s*\{")
    # er relation: `CUSTOMER ||--o{ ORDER : places` (entities need no {} body)
    _ER_REL = re.compile(
        r"(?m)^\s*(" + _ID + r")\s+[|}o{][ox|}{.\-]*\s+(" + _ID + r")\b")
    _STATE = re.compile(r"(?m)^\s*state\s+(?:\"[^\"]*\"\s+as\s+)?(" + _ID + r")")
    # state transition: `[*] --> Still`, `Moving --> Crash` (states are implicit)
    _STATE_TRANS = re.compile(
        r"(?m)^\s*(\[\*\]|" + _ID + r")\s*-->\s*(\[\*\]|" + _ID + r")")
    _NODE = re.compile(
        r"(?<![\w>])(" + _ID + r")\s*(?:\[[^\]]*\]|\(\([^)]*\)\)|\([^)]*\)|"
        r"\{[^}]*\}|\>[^\]]*\])")

    # Flowchart edge operators (-->, ---, -.->, ==>, --x, --o, <-->, ~~~, ...).
    _EDGEOP = re.compile(r"[ox<]?[.\-=~]{2,}[->ox]?")
    # Node shapes and piped edge labels, stripped before mining bare edge ids.
    _SHAPES = re.compile(
        r"\(\([^()]*\)\)|\[\[[^\]]*\]\]|\[\([^\]]*\)\]|\{\{[^{}]*\}\}|"
        r"\[/[^\]]*/\]|\[\\[^\]]*\\\]|\[[^\]]*\]|\([^()]*\)|\{[^{}]*\}|"
        r"\|[^|]*\||>[^\]]*\]")
    _FLOWSKIP = {"subgraph", "end", "graph", "flowchart", "direction", "tb", "td",
                 "bt", "rl", "lr", "class", "classdef", "style", "linkstyle",
                 "click", "call", "href", "callback", "acctitle", "accdescr",
                 "title", "default", "interpolate"}
    _CKW = {"class", "namespace", "direction", "note", "click", "callback",
            "link", "style", "cssclass", "classdef"}
    _SEQKW = {"note", "loop", "alt", "opt", "par", "and", "else", "end", "rect",
              "activate", "deactivate", "autonumber", "critical", "break", "box"}
    # directive lines in block diagrams that must not yield block ids
    _BLOCK_DIRECTIVE = {"block", "block-beta", "classdef", "class", "style",
                        "click", "linkstyle", "direction", "columns", "space",
                        "accdescr", "acctitle", "title"}

    def _diagram_type(self, clean):
        lines = clean.split("\n")
        i = 0
        while i < len(lines) and not lines[i].strip():
            i += 1
        # skip a leading `--- ... ---` YAML front-matter block
        if i < len(lines) and lines[i].strip() == "---":
            i += 1
            while i < len(lines) and lines[i].strip() != "---":
                i += 1
            i += 1
        for line in lines[i:]:
            s = line.strip()
            if s:
                return s.split()[0]
        return ""

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._CLASSDEF.finditer(clean):
            self._register_class(m.group(1))
        for m in self._PARTICIPANT.finditer(clean):
            self._register_class(m.group(1))
        for m in self._SUBGRAPH.finditer(clean):
            self._register_class(m.group(1) or m.group(2))
        dt = self._diagram_type(clean)
        if dt.startswith("erDiagram"):
            for m in self._ENTITY.finditer(clean):
                self._register_class(m.group(1))

    def _class_body(self, clean, brace_pos):
        end = self._find_matching(clean, brace_pos)
        return clean[brace_pos + 1:end - 1], end

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)
        dt = self._diagram_type(clean)

        if dt.startswith("classDiagram"):
            self._class_diagram(file_id, clean)
        elif dt.startswith("sequenceDiagram"):
            self._sequence_diagram(file_id, clean)
        elif dt.startswith("erDiagram"):
            self._er_diagram(file_id, clean)
        elif dt.startswith("stateDiagram"):
            seen = set()
            for m in self._STATE.finditer(clean):
                if m.group(1) not in seen:
                    seen.add(m.group(1))
                    self._add_variable(file_id, m.group(1), scope="state")
            for m in self._STATE_TRANS.finditer(clean):
                for g in (m.group(1), m.group(2)):
                    if g != "[*]" and g not in seen:
                        seen.add(g)
                        self._add_variable(file_id, g, scope="state")
        elif dt.startswith("block"):
            self._block_diagram(file_id, clean)
        else:  # flowchart / graph / gitGraph / others
            self._flow_diagram(file_id, clean)

    def _class_diagram(self, file_id, clean):
        # class Foo { members }
        for m in self._CLASSDEF.finditer(clean):
            name = m.group(1)
            methods, attrs = [], []
            if m.group(2):  # has a brace body
                body, _ = self._class_body(clean, m.end() - 1)
                for line in body.split("\n"):
                    s = line.strip()
                    if not s:
                        continue
                    mm = self._MEMBER.match(s)
                    if not mm:
                        continue
                    mname = mm.group(1)
                    if mm.group(2):  # '(' -> method
                        methods.append(self._add_function(
                            file_id, mname, [], [], description="mermaid method"))
                    else:
                        attrs.append(self._add_arg(mname))
            self._add_class(file_id, name, description="mermaid class",
                            method_ids=methods or None, attr_ids=attrs or None)
        # external members: `Animal : +int age` / `Animal : +run()`
        for m in self._CMEMBER.finditer(clean):
            cls = m.group(1)
            if cls.lower() in self._CKW:
                continue
            nm, is_method = self._member_name(m.group(2))
            if not nm:
                continue
            if is_method:
                fid = self._add_function(file_id, nm, [], [],
                                         description="mermaid method")
                self._add_class(file_id, cls, description="mermaid class",
                                method_ids=[fid])
            else:
                aid = self._add_arg(nm)
                self._add_class(file_id, cls, description="mermaid class",
                                attr_ids=[aid])
        # inheritance A <|-- B  (A base, B derived)
        for m in self._INHERIT.finditer(clean):
            base, derived = m.group(1), m.group(2)
            bid = self._add_class(file_id, base, description="mermaid class")
            self._add_class(file_id, derived, description="mermaid class",
                            parent_ids=[bid])
        # every other relation: both endpoints are classes
        for m in self._REL.finditer(clean):
            self._add_class(file_id, m.group(1), description="mermaid class")
            self._add_class(file_id, m.group(2), description="mermaid class")

    @staticmethod
    def _member_name(spec):
        # returns (name, is_method); name is the identifier before '(' for a
        # method, else the last identifier of a `[vis][type] name` attribute.
        spec = spec.strip()
        if "(" in spec:
            head = spec.split("(", 1)[0]
            ids = re.findall(_ID, head)
            return (ids[-1] if ids else None, True)
        ids = re.findall(_ID, spec)
        return (ids[-1] if ids else None, False)

    def _sequence_diagram(self, file_id, clean):
        for m in self._PARTICIPANT.finditer(clean):
            self._add_class(file_id, m.group(1), description="mermaid participant")
        # message arrows imply lifelines even when never declared as participants
        seen = set()
        for m in self._SEQ_MSG.finditer(clean):
            for g in (m.group(1), m.group(2)):
                nm = re.sub(r"[^\w]", "", g)
                if nm and nm.lower() not in self._SEQKW and nm not in seen:
                    seen.add(nm)
                    self._add_variable(file_id, nm, scope="lifeline")

    def _er_diagram(self, file_id, clean):
        for m in self._ENTITY.finditer(clean):
            body, _ = self._class_body(clean, m.end() - 1)
            attrs = []
            for line in body.split("\n"):
                parts = line.split()
                if len(parts) >= 2:            # "type name [PK]"
                    attrs.append(self._add_arg(parts[1]))
            self._add_class(file_id, m.group(1), description="mermaid entity",
                            attr_ids=attrs or None)
        # entities named only in relations (no {} body)
        for m in self._ER_REL.finditer(clean):
            self._add_class(file_id, m.group(1), description="mermaid entity")
            self._add_class(file_id, m.group(2), description="mermaid entity")

    def _block_diagram(self, file_id, clean):
        # block-beta: `columns 3`, bracketed `a["A"]`, and bare block ids `A`.
        seen = set()

        def emit(nm):
            if nm and nm.lower() not in self._FLOWSKIP and nm not in seen:
                seen.add(nm)
                self._add_variable(file_id, nm, scope="block")

        for m in self._NODE.finditer(clean):
            emit(m.group(1))
        for line in clean.split("\n"):
            s = line.strip()
            if not s:
                continue
            if s.split()[0].lower().rstrip(":") in self._BLOCK_DIRECTIVE:
                continue
            if self._EDGEOP.search(s):
                x = self._EDGEOP.sub(" ", self._SHAPES.sub(" ", s)).replace("&", " ")
                for tok in x.split():
                    if re.fullmatch(_ID, tok):
                        emit(tok)
                continue
            # bare block-id line(s): strip shapes/labels, keep leading ids
            x = self._SHAPES.sub(" ", re.sub(r":.*$", "", s))
            for tok in x.split():
                if re.fullmatch(_ID, tok):
                    emit(tok)

    def _flow_diagram(self, file_id, clean):
        for m in self._SUBGRAPH.finditer(clean):
            self._add_class(file_id, m.group(1) or m.group(2),
                            description="mermaid subgraph")
        seen = set()

        def emit(nm):
            if nm and nm.lower() not in self._FLOWSKIP and nm not in seen:
                seen.add(nm)
                self._add_variable(file_id, nm, scope="node")

        # bracketed node declarations anywhere
        for m in self._NODE.finditer(clean):
            emit(m.group(1))
        # bare-edge endpoints: `A --> B`, `a --> b & c`, `n0 --> n1`
        for line in clean.split("\n"):
            if not self._EDGEOP.search(line):
                continue
            s = self._SHAPES.sub(" ", line)
            s = self._EDGEOP.sub(" ", s)
            s = s.replace("&", " ")
            for tok in s.split():
                if re.fullmatch(_ID, tok):
                    emit(tok)
