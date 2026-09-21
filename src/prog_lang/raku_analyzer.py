# Raku / Perl 6 (.raku / .p6) analyzer.
#
# Real parser for Raku ('#' line comments, '#`( )' embedded, '=begin pod'..'=end pod'
# blocks; strings "..." and '...'):
#   use Foo::Bar;                                        -> import
#   class Point is Base does Role { ... }                 -> class (+ parent/role)
#   role R { ... }  grammar G { ... }  module M { ... }   -> class
#   has Int $.x;                                           -> attribute
#   method dist($p) { ... }                                -> method
#   sub area($r) { ... }                                   -> function
#   my $count = 0;   our @items;                            -> variable
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer

_TYPEKW = ("class", "role", "grammar", "module", "monitor")


class RakuAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "raku"
    EXTENSIONS = (".raku", ".p6", ".pm6", ".rakumod")
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    _USE = re.compile(r"^\s*(?:use|need|import)\s+([\w:]+)", re.MULTILINE)
    _TYPE = re.compile(
        r"^\s*(?:my\s+|our\s+)?(" + "|".join(_TYPEKW) + r")\s+"
        r"([\w:]+)\s*((?:is\s+[\w:]+\s*|does\s+[\w:]+\s*)*)",
        re.MULTILINE)
    _METHOD = re.compile(
        r"^\s*(?:multi\s+|proto\s+|only\s+)?(?:method|submethod)\s+"
        r"([\w:!-]+|\S)\s*", re.MULTILINE)
    _SUB = re.compile(
        r"^\s*(?:multi\s+|proto\s+|only\s+|our\s+|my\s+)?sub\s+"
        r"([\w:!-]+|\S)\s*", re.MULTILINE)
    _HAS = re.compile(r"^\s*has\s+(?:[\w:]+\s+)?[\$@%&][.!]?([\w-]+)", re.MULTILINE)
    _VAR = re.compile(
        r"^\s*(?:my|our|state|constant)\s+(?:[\w:]+\s+)?"
        r"([\$@%&][\w-]+)", re.MULTILINE)

    def _clean(self, text):
        # remove =begin pod ... =end pod (and =begin X..=end X) POD blocks
        text = re.sub(r"^=begin\b.*?^=end\b.*?$", lambda m: "\n" * m.group(0).count("\n"),
                      text, flags=re.MULTILINE | re.DOTALL)
        # remove =head/=para one-line pod directives
        text = re.sub(r"^=\w+.*$", "", text, flags=re.MULTILINE)
        # embedded #`( ... ) comments (single-level paren)
        text = re.sub(r"#`\([^)]*\)", "", text)
        return self._strip_comments(text)

    def _type_body(self, text, decl_end):
        """Return (start, end) of the { } body following a type declaration, or None."""
        lb = text.find("{", decl_end)
        # ensure no ';' before the brace (would be a stub decl)
        semi = text.find(";", decl_end)
        if lb == -1 or (semi != -1 and semi < lb):
            return None
        rb = self._find_matching(text, lb, "{", "}")
        return (lb, rb)

    def _register_types(self, file_id, text, path):
        text = self._clean(text)
        for m in self._TYPE.finditer(text):
            self._register_class(m.group(2))

    def _extract_entities(self, file_id, text, path):
        text = self._clean(text)

        for m in self._USE.finditer(text):
            mod = m.group(1)
            if mod.lower() in ("v6", "lib", "strict", "fatal", "worries"):
                continue
            self._add_import(file_id, mod.split("::")[-1], mod)

        # map each type to its body span so members attach correctly
        type_spans = []      # (start, end, name)
        for m in self._TYPE.finditer(text):
            name = m.group(2)
            span = self._type_body(text, m.end())
            if span:
                type_spans.append((span[0], span[1], name))

        def owner_at(pos):
            best = None
            for a, b, nm in type_spans:
                if a < pos < b:
                    if best is None or a > best[0]:
                        best = (a, b, nm)
            return best[2] if best else None

        members = {}   # class name -> (methods, attrs)

        def bag(name):
            return members.setdefault(name, ([], []))

        # methods
        for m in self._METHOD.finditer(text):
            name = m.group(1)
            if not re.match(r"^[\w-]+$", name):
                continue
            owner = owner_at(m.start())
            cid = self._class_registry.get(owner) if owner else None
            fid = self._add_function(file_id, name, [], [], class_id=cid,
                                     description="raku method")
            if owner:
                bag(owner)[0].append(fid)

        # subs
        for m in self._SUB.finditer(text):
            name = m.group(1)
            if not re.match(r"^[\w-]+$", name):
                continue
            owner = owner_at(m.start())
            cid = self._class_registry.get(owner) if owner else None
            fid = self._add_function(file_id, name, [], [], class_id=cid,
                                     description="raku sub")
            if owner:
                bag(owner)[0].append(fid)

        # attributes
        for m in self._HAS.finditer(text):
            owner = owner_at(m.start())
            if owner:
                bag(owner)[1].append(self._add_arg(m.group(1)))

        # variables (top-level only)
        for m in self._VAR.finditer(text):
            if owner_at(m.start()) is None:
                self._add_variable(file_id, m.group(1), None)

        # emit classes with parents/roles
        for m in self._TYPE.finditer(text):
            name = m.group(2)
            parents = []
            for pm in re.finditer(r"(?:is|does)\s+([\w:]+)", m.group(3) or ""):
                pn = pm.group(1).split("::")[-1]
                if pn in self._class_registry:
                    parents.append(self._class_registry[pn])
            meth, attr = members.get(name, ([], []))
            self._add_class(file_id, name, description=f"raku {m.group(1)}",
                            parent_ids=parents, method_ids=meth, attr_ids=attr)
