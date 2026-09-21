# Robot Framework (.robot) analyzer.
#
# Real parser for Robot Framework test suites (section-based tabular syntax; '#'
# line comments; no strings-as-literals -- text is free-form):
#   *** Settings ***
#   Library           SeleniumLibrary                -> import
#   Resource          keywords/common.robot           -> import
#   Variables         data/vars.py                     -> import
#   *** Variables ***
#   ${URL}            http://example.com                -> variable
#   @{ITEMS}          a    b    c                        -> variable
#   *** Test Cases ***
#   Login Works                                          -> function (test case)
#       Open Browser    ${URL}
#   *** Keywords ***
#   Do Login                                             -> function (keyword)
#       [Arguments]    ${user}    ${pass}                 -> args
#       Log    ${user}
import re

from .regex_base import RegexCodeAnalyzer

# A header line starts with one or more stars (Robot accepts `*Test Cases*` as
# well as `*** Test Cases ***`); trailing cells after the closing stars are
# ignored, so we do NOT anchor to end-of-line. The known-section whitelist
# (checked by the caller) guards against matching stray data rows.
_SECTION = re.compile(r"^\s*\*+\s*([A-Za-z][A-Za-z ]*?)\s*\*+")
_KNOWN_SECTIONS = {"setting", "variable", "test case", "task", "keyword", "comment"}


class RobotFrameworkAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "robotframework"
    EXTENSIONS = (".robot", ".resource")
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ()

    def _register_types(self, file_id, text, path):
        pass

    @staticmethod
    def _norm(name):
        return name.strip().lower().rstrip("s")

    @staticmethod
    def _cells(line):
        # Robot separates cells by 2+ spaces or a tab
        return [c for c in re.split(r"\t|\s{2,}", line.strip()) if c != ""]

    def _extract_entities(self, file_id, text, path):
        section = None
        # (name, body_lines) blocks for test-case / keyword sections
        blocks = []  # list of (kind, name, [lines])
        cur = None
        for raw in text.splitlines():
            # drop trailing comments (a '#' starting a cell)
            line = (
                re.sub(r"(?:^|\s)#.*$", "", raw)
                if raw.lstrip().startswith("#")
                else re.sub(r"\s{2,}#.*$", "", raw)
            )
            sm = _SECTION.match(line)
            if sm and self._norm(sm.group(1)) in _KNOWN_SECTIONS:
                section = self._norm(sm.group(1))
                cur = None
                continue
            if not line.strip():
                continue
            if section == "setting":
                cells = self._cells(line)
                if not cells:
                    continue
                key = cells[0].lower()
                if key in ("library", "resource", "variables") and len(cells) > 1:
                    src = cells[1]
                    alias = None
                    # Library  Foo  WITH NAME  Bar   /   AS  Bar
                    if "with name" in line.lower():
                        alias = cells[-1]
                    leaf = re.split(r"[\\/]", src)[-1]
                    leaf = re.sub(r"\.(py|robot|resource|yaml|yml)$", "", leaf)
                    self._add_import(file_id, alias or leaf, src, alias)
            elif section == "variable":
                cells = self._cells(line)
                if cells and re.match(r"^[\$@&]\{.+\}=?$", cells[0]):
                    vname = re.sub(r"^[\$@&]\{(.+?)\}=?$", r"\1", cells[0])
                    val = cells[1] if len(cells) > 1 else None
                    self._add_variable(file_id, vname, val)
            elif section in ("test case", "task", "keyword"):
                if self._indent_of(line) == 0:
                    # new test case / keyword header (name is first cell)
                    name = self._cells(line)
                    if name:
                        cur = (section, name[0], [])
                        blocks.append(cur)
                elif cur is not None:
                    cur[2].append(line)

        for kind, name, body in blocks:
            arg_ids = []
            for bl in body:
                cells = self._cells(bl)
                if cells and cells[0].lower() == "[arguments]":
                    for a in cells[1:]:
                        am = re.match(r"^[\$@&]\{(.+?)\}(?:=(.*))?$", a)
                        if am:
                            arg_ids.append(
                                self._add_arg(
                                    am.group(1),
                                    None,
                                    (
                                        am.group(2)
                                        if am.lastindex and am.group(2)
                                        else None
                                    ),
                                )
                            )
            desc = (
                "robot test case" if kind in ("test case", "task") else "robot keyword"
            )
            self._add_function(file_id, name, arg_ids, [], description=desc)
