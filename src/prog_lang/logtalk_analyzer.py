# Logtalk (.lgt / .logtalk) analyzer.
#
# Real parser for Logtalk (Prolog-based; '%' line and '/* */' block comments;
# quoted atoms '...' and strings "..."):
#   :- object(list, extends(compound)).  ... :- end_object.   -> object (class + parent)
#   :- protocol(listp).  ... :- end_protocol.                  -> protocol (class)
#   :- category(logging).  ... :- end_category.                -> category (class)
#   :- public(append/3).                                       -> predicate (method)
#   :- use_module(library(lists)).                             -> import
#   area(R, A) :- A is pi*R*R.                                  -> predicate clause (method)
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_ENTITY = ("object", "protocol", "category")


class LogtalkAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "logtalk"
    EXTENSIONS = (".lgt", ".logtalk")
    LINE_COMMENTS = ("%",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'")

    _OPEN = re.compile(
        r":-\s*(object|protocol|category)\(\s*([a-z]\w*)(.*?)\)\.",
        re.IGNORECASE | re.DOTALL)
    _CLOSE = re.compile(r":-\s*end_(object|protocol|category)\.", re.IGNORECASE)
    _PRED_DIRECTIVE = re.compile(
        r":-\s*(?:public|protected|private)\(\s*(.+?)\s*\)\.",
        re.IGNORECASE | re.DOTALL)
    _USE = re.compile(
        r":-\s*(?:use_module|uses)\(\s*(?:library\(\s*)?([a-z]\w*)",
        re.IGNORECASE)
    _RELATION = re.compile(
        r"\b(extends|implements|imports|instantiates|specializes)\(\s*([^)]*)\)",
        re.IGNORECASE)
    # a clause head:  name(args) :-   OR fact  name(args).   at column 0
    _CLAUSE = re.compile(r"^([a-z]\w*)\((.*?)\)\s*(?::-|\.)", re.MULTILINE | re.DOTALL)
    _FACT0 = re.compile(r"^([a-z]\w*)\s*(?::-|\.)", re.MULTILINE)

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._OPEN.finditer(text):
            self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)

        # imports (file-level and entity-level use_module)
        for m in self._USE.finditer(text):
            self._add_import(file_id, m.group(1), m.group(1))

        # entity spans
        opens = [(m.start(), m.end(), m.group(1).lower(), m.group(2), m.group(3))
                 for m in self._OPEN.finditer(text)]
        closes = [m.start() for m in self._CLOSE.finditer(text)]

        for idx, (ostart, oend, kind, name, rel) in enumerate(opens):
            # body ends at the first end_* after this open
            body_end = next((c for c in closes if c > oend), len(text))
            body = text[oend:body_end]
            cid = self._class_registry.get(name)

            parents = []
            for rm in self._RELATION.finditer(rel or ""):
                for tok in re.findall(r"[a-z]\w*", rm.group(2)):
                    if tok in self._class_registry:
                        parents.append(self._class_registry[tok])

            methods, seen = [], set()
            # declared predicates
            for pm in self._PRED_DIRECTIVE.finditer(body):
                for spec in self._split_top_level(pm.group(1)):
                    nm = re.match(r"([a-z]\w*)\s*/\s*\d+", spec.strip())
                    if nm and nm.group(1) not in seen:
                        seen.add(nm.group(1))
                        methods.append(self._add_function(
                            file_id, nm.group(1), [], [], class_id=cid,
                            description=f"logtalk {kind} predicate"))
            # defined clauses (predicate heads)
            for cm in self._CLAUSE.finditer(body):
                nm = cm.group(1)
                if nm in seen:
                    continue
                seen.add(nm)
                arity = len(self._split_top_level(cm.group(2))) if cm.group(2).strip() else 0
                arg_ids = [self._add_arg(f"arg{i+1}") for i in range(arity)]
                methods.append(self._add_function(
                    file_id, nm, arg_ids, [], class_id=cid,
                    description=f"logtalk {kind} clause"))
            self._add_class(file_id, name, description=f"logtalk {kind}",
                            parent_ids=parents, method_ids=methods)

        # clauses outside any entity -> free predicates (dedup by name)
        entity_ranges = [(opens[i][0],
                          next((c for c in closes if c > opens[i][1]), len(text)))
                         for i in range(len(opens))]

        def inside(pos):
            return any(a <= pos < b for a, b in entity_ranges)

        free_seen = set()
        for cm in self._CLAUSE.finditer(text):
            if inside(cm.start()):
                continue
            nm = cm.group(1)
            if nm in free_seen:
                continue
            free_seen.add(nm)
            arity = len(self._split_top_level(cm.group(2))) if cm.group(2).strip() else 0
            arg_ids = [self._add_arg(f"arg{i+1}") for i in range(arity)]
            self._add_function(file_id, nm, arg_ids, [], description="logtalk predicate")
