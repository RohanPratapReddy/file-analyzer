# Eiffel (.e / .eiffel) analyzer.
#
# Real parser for Eiffel (case-insensitive keywords; '--' line comments; strings
# "..."):
#   class ACCOUNT                                        -> class
#   inherit  DEPOSIT  redefine make end                  -> parent
#   create  make                                          -> (creation marker)
#   feature {NONE}                                        -> feature clause
#       balance: INTEGER                                  -> attribute
#       deposit (sum: INTEGER)                            -> routine (method)
#           do ... end
#       make                                              -> routine
#           do ... end
import re

from .regex_base import RegexCodeAnalyzer


class EiffelAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "eiffel"
    EXTENSIONS = (".e", ".eiffel")
    LINE_COMMENTS = ("--",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _CLASS = re.compile(
        r"^\s*(?:deferred\s+|expanded\s+|frozen\s+)*class\s+([A-Z][A-Z0-9_]*)",
        re.MULTILINE,
    )
    _INHERIT = re.compile(r"^\s*inherit\b", re.IGNORECASE)
    _FEATURE = re.compile(r"^\s*feature\b", re.IGNORECASE)
    # a feature (routine or attribute) declared at feature-body indentation:
    #   name (args): TYPE       -> routine with return
    #   name (args)             -> routine
    #   name: TYPE              -> attribute (or once/constant)
    #   name, name2: TYPE       -> attributes
    _FEAT_DECL = re.compile(
        r"^\s{1,}([a-z]\w*(?:\s*,\s*[a-z]\w*)*)\s*"
        r"(?:\(([^)]*)\))?"
        r"(?:\s*:\s*([A-Za-z][\w \[\],]*?))?\s*$"
    )
    _KEYWORDS = {
        "do",
        "end",
        "then",
        "else",
        "elseif",
        "if",
        "from",
        "until",
        "loop",
        "inspect",
        "when",
        "require",
        "ensure",
        "local",
        "check",
        "rescue",
        "retry",
        "invariant",
        "variant",
        "across",
        "as",
        "and",
        "or",
        "not",
        "implies",
        "xor",
        "create",
        "result",
        "current",
        "deferred",
        "once",
        "external",
        "alias",
        "attribute",
        "obsolete",
        "note",
        "class",
        "inherit",
        "feature",
        "convert",
        "redefine",
        "rename",
        "export",
        "undefine",
        "select",
        "old",
        "true",
        "false",
        "void",
        "precursor",
        "agent",
        "debug",
    }

    # keywords that open a block requiring a matching `end`
    _BLOCK_OPEN = re.compile(
        r"\b(do|deferred|once|external|attribute|if|from|inspect|check|debug)\b",
        re.IGNORECASE,
    )
    _END_TOK = re.compile(r"\bend\b", re.IGNORECASE)

    @staticmethod
    def _skip_routine_body(lines, start, n):
        """Advance past a routine body, returning the index just after its
        terminating ``end`` by tracking block-keyword depth. If no body is
        found (declaration only), returns ``start`` unchanged."""
        depth = 0
        j = start
        started = False
        while j < n:
            low = lines[j]
            opens = len(EiffelAnalyzer._BLOCK_OPEN.findall(low))
            ends = len(EiffelAnalyzer._END_TOK.findall(low))
            if opens:
                started = True
            depth += opens - ends
            if started and depth <= 0:
                return j + 1
            j += 1
        return start

    def _register_types(self, file_id, text, path):
        text = self._strip_comments(text)
        for m in self._CLASS.finditer(text):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        text = self._strip_comments(text)
        lines = text.splitlines()

        cm = self._CLASS.search(text)
        if not cm:
            return
        cname = cm.group(1)
        cid = self._class_registry.get(cname)

        parents, methods, attrs = [], [], []
        in_feature = False
        in_inherit = False
        i, n = 0, len(lines)
        while i < n:
            line = lines[i]

            if self._INHERIT.match(line):
                in_inherit = True
                in_feature = False
                # parent may be on same line or following lines
                pm = re.search(r"inherit\s+([A-Z][A-Z0-9_]*)", line, re.IGNORECASE)
                if pm and pm.group(1) in self._class_registry:
                    parents.append(self._class_registry[pm.group(1)])
                i += 1
                continue

            if self._FEATURE.match(line):
                in_feature = True
                in_inherit = False
                i += 1
                continue

            if in_inherit:
                pm = re.match(r"^\s+([A-Z][A-Z0-9_]*)\s*$", line)
                if pm and pm.group(1) in self._class_registry:
                    parents.append(self._class_registry[pm.group(1)])
                i += 1
                continue

            if in_feature:
                fm = self._FEAT_DECL.match(line)
                if fm:
                    names = [x.strip() for x in fm.group(1).split(",")]
                    if any(nm.lower() in self._KEYWORDS for nm in names):
                        i += 1
                        continue
                    args_raw, ret = fm.group(2), fm.group(3)
                    # Classify: scan forward over the declaration's own body only,
                    # stopping at the next feature declaration / clause boundary so
                    # the lookahead never bleeds into a following routine's body.
                    is_routine = args_raw is not None
                    is_attr_body = False
                    j = i + 1
                    while j < n:
                        lj = lines[j].strip()
                        if not lj:
                            j += 1
                            continue
                        low = lj.lower()
                        if re.match(
                            r"(do|deferred|once|external|obsolete|" r"require|local)\b",
                            low,
                        ):
                            is_routine = True
                            break
                        if re.match(r"attribute\b", low):
                            is_attr_body = True  # attribute with a body clause
                            break
                        # next feature declaration or a clause terminator ends
                        # this declaration without a routine body -> attribute.
                        if self._FEAT_DECL.match(lines[j]) or re.match(
                            r"\s*(feature|end|invariant|note)\b",
                            lines[j],
                            re.IGNORECASE,
                        ):
                            break
                        j += 1
                    if is_routine and not is_attr_body:
                        arg_ids = []
                        for grp in self._split_top_level(args_raw or "", sep=";"):
                            am = re.match(r"([a-z][\w, ]*?)\s*:\s*(.+)", grp.strip())
                            if am:
                                atype = am.group(2).strip()
                                for an in am.group(1).split(","):
                                    arg_ids.append(self._add_arg(an.strip(), atype))
                        out_ids = [self._add_output(ret.strip())] if ret else []
                        for nm in names:
                            methods.append(
                                self._add_function(
                                    file_id,
                                    nm,
                                    arg_ids,
                                    out_ids,
                                    class_id=cid,
                                    description="eiffel routine",
                                )
                            )
                        # skip the routine body so locals aren't read as features
                        i = self._skip_routine_body(lines, i + 1, n)
                        continue
                    else:
                        for nm in names:
                            attrs.append(
                                self._add_arg(nm, ret.strip() if ret else None)
                            )
                i += 1
                continue

            i += 1

        self._add_class(
            file_id,
            cname,
            description="eiffel class",
            parent_ids=parents,
            method_ids=methods,
            attr_ids=attrs,
        )
