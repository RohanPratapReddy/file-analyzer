# Generic test-definition file (.test).
#
# A `.test` file holds test definitions; the concrete notation varies by
# toolchain, so this analyzer recognises the common cross-language test-authoring
# forms without assuming one framework:
#
#     test "adds two numbers" {            (Zig / Rust-style block)  -> function
#     describe("Calculator", () => {       (Mocha / Jasmine)        -> function
#     it("returns the sum", () => {                                  -> function
#     scenario "user logs in"                                        -> function
#     Feature: Checkout                    (Gherkin)                 -> class
#     Scenario: empty cart                 (Gherkin)                 -> function
#     Scenario Outline: many carts                                   -> function
#     def test_addition(self):             (pytest / unittest)       -> function
#     func TestAddition(t *testing.T) {    (Go)                      -> function
#     @Test  public void addsTwo() {       (JUnit)                   -> function
#     setup / teardown / before / after                             -> function (fixture)
#
# `//`, `#` and `--` start line comments; `"` / `'` / `` ` `` delimit strings.
import re
from .regex_base import RegexCodeAnalyzer

_ID = r"[A-Za-z_]\w*"


class TestDefAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "test_def"
    EXTENSIONS = (".test",)
    LINE_COMMENTS = ("//", "#", "--")
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"', "'", "`")

    # test "name" {   /   test 'name'
    _TEST_BLOCK = re.compile(r"(?m)^[ \t]*test\s+[\"']([^\"']+)[\"']")
    # describe/context/it/specify/suite/scenario("name"  or  scenario "name"
    _BDD_CALL = re.compile(r"(?m)\b(?:describe|context|it|specify|suite|"
                           r"scenario|test)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]")
    _BDD_BARE = re.compile(r"(?m)^[ \t]*(?:scenario|specify)\s+[\"']([^\"']+)[\"']")
    # Gherkin
    _FEATURE = re.compile(r"(?m)^[ \t]*Feature\s*:\s*(.+?)\s*$")
    _SCENARIO = re.compile(r"(?m)^[ \t]*Scenario(?:\s+Outline)?\s*:\s*(.+?)\s*$")
    # pytest / unittest / Go / fixtures
    _PYTEST = re.compile(r"(?m)^[ \t]*def\s+(test" + r"\w*)\s*\(")
    _GOTEST = re.compile(r"(?m)^[ \t]*func\s+(Test\w+|Benchmark\w+|Example\w+)"
                         r"\s*\(")
    _FIXTURE = re.compile(r"(?m)^[ \t]*(setup|teardown|before(?:Each|All)?|"
                          r"after(?:Each|All)?|beforeEach|afterEach)\b")
    # JUnit: @Test on its own / preceding line, then `... name(`
    _JUNIT_ANNOT = re.compile(r"(?m)^[ \t]*@(?:Test|ParameterizedTest|"
                              r"RepeatedTest)\b")
    _JAVA_METHOD = re.compile(r"[ \t]*(?:public|private|protected|static|\s)*"
                              r"(?:void|[A-Za-z_][\w<>\[\]]*)\s+(" + _ID +
                              r")\s*\(")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn, seen_c = set(), set()

        def add_fn(name, desc):
            name = (name or "").strip()
            if name and name not in seen_fn:
                seen_fn.add(name)
                self._add_function(file_id, name, [], [], description=desc)

        def add_cls(name):
            name = (name or "").strip()
            if name and name not in seen_c:
                seen_c.add(name)
                self._add_class(file_id, name, description="test feature")

        for m in self._FEATURE.finditer(clean):
            add_cls(m.group(1))
        for m in self._SCENARIO.finditer(clean):
            add_fn(m.group(1), "gherkin scenario")
        for rx, desc in ((self._TEST_BLOCK, "test case"),
                         (self._BDD_CALL, "test case"),
                         (self._BDD_BARE, "test case"),
                         (self._PYTEST, "test function"),
                         (self._GOTEST, "test function")):
            for m in rx.finditer(clean):
                add_fn(m.group(1), desc)

        # JUnit @Test annotations: name comes from the following method line
        lines = clean.splitlines()
        for i, ln in enumerate(lines):
            if self._JUNIT_ANNOT.match(ln):
                for nxt in lines[i + 1:]:
                    if not nxt.strip():
                        continue
                    mm = self._JAVA_METHOD.match(nxt)
                    if mm:
                        add_fn(mm.group(1), "JUnit test")
                    break

        for m in self._FIXTURE.finditer(clean):
            add_fn(m.group(1), "test fixture")
