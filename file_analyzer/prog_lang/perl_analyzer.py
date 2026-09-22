# Perl module (.pm) analyzer.
#
# Real parser for Perl (`#` line comments, POD =cut blocks skipped):
#   use strict; use POSIX qw(floor);             -> import
#   require Foo::Bar;                              -> import
#   package My::Module;                            -> package (class row)
#   sub area { my ($self, $r) = @_; ... }          -> function
#   our $VERSION = '1.0';   my @list = (...);       -> variable
# Perl OO is package-based; `use parent`/`use base`/`our @ISA` set inheritance.
import re

from .regex_base import RegexCodeAnalyzer


class PerlAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "perl"
    EXTENSIONS = (".pm",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()

    _USE = re.compile(r"^\s*(?:use|require)\s+([\w:]+)", re.MULTILINE)
    _PARENT = re.compile(
        r"^\s*use\s+(?:parent|base)\s+" r"(?:qw[/(]?\s*)?([\w:\s'\",-]+)", re.MULTILINE
    )
    _PACKAGE = re.compile(r"^\s*package\s+([\w:]+)", re.MULTILINE)
    _SUB = re.compile(r"^\s*sub\s+(\w+)\s*(?:\([^)]*\))?\s*\{", re.MULTILINE)
    _VAR = re.compile(r"^\s*(?:our|my|local)\s+([\$@%]\w+)\s*=", re.MULTILINE)

    def _strip_pod(self, text):
        # POD documentation: =pod .. =cut and other =command blocks.
        out, skip = [], False
        for line in text.splitlines():
            if re.match(r"^=\w+", line):
                skip = not line.startswith("=cut")
                out.append("")
                continue
            if skip and line.startswith("=cut"):
                skip = False
                out.append("")
                continue
            out.append("" if skip else line)
        return "\n".join(out)

    def _register_types(self, file_id, text, path):
        t = self._strip_comments(self._strip_pod(text))
        for m in self._PACKAGE.finditer(t):
            self._register_class(m.group(1).split("::")[-1])

    def _extract_entities(self, file_id, text, path):
        t = self._strip_comments(self._strip_pod(text))

        pragmas = {
            "strict",
            "warnings",
            "utf8",
            "vars",
            "lib",
            "constant",
            "parent",
            "base",
        }
        for m in self._USE.finditer(t):
            mod = m.group(1)
            if mod in pragmas:
                continue
            self._add_import(file_id, mod.split("::")[-1], mod)

        packages = [
            (m.start(), m.group(1).split("::")[-1]) for m in self._PACKAGE.finditer(t)
        ]

        def enclosing(pos):
            owner = None
            for start, name in packages:
                if start <= pos:
                    owner = name
                else:
                    break
            return owner

        for m in self._PARENT.finditer(t):
            parents = []
            for p in re.split(r"[\s,'\"]+", m.group(1).strip()):
                p = p.strip()
                if p and p not in ("-norequire",):
                    pid = self._register_class(p.split("::")[-1])
                    if pid is not None:
                        parents.append(pid)
            owner = enclosing(m.start())
            if owner:
                self._add_class(
                    file_id, owner, parent_ids=parents, description="perl package"
                )

        seen_pkg = set()
        for _, name in packages:
            if name not in seen_pkg:
                seen_pkg.add(name)
                self._add_class(file_id, name, description="perl package")

        for m in self._SUB.finditer(t):
            owner = enclosing(m.start())
            cid = self._class_registry.get(owner) if owner else None
            self._add_function(
                file_id, m.group(1), class_id=cid, description="perl sub"
            )

        for m in self._VAR.finditer(t):
            self._add_variable(file_id, m.group(1))
