# ACPI Source Language (.asl / .dsl).
#
# ASL is the C-like language ACPI firmware tables (DSDT/SSDT) are written in and
# compiled by iasl.  Its named constructs:
#
#     DefinitionBlock ("dsdt.aml", "DSDT", 2, "OEM", "TABLE", 0x1) {
#         External (\_SB.PCI0, DeviceObj)
#         Scope (\_SB) {
#             Device (PCI0) {
#                 Name (_HID, EisaId ("PNP0A08"))
#                 OperationRegion (PMIO, SystemIO, 0x400, 0x80)
#                 Method (_STA, 0, NotSerialized) { Return (0x0F) }
#             }
#         }
#     }
#
#   DefinitionBlock / Scope / Device / Processor / PowerResource / ThermalZone /
#   Field / OperationRegion (named container objects)   -> class
#   Method (NAME, argc, ...)                             -> function (Arg0..ArgN)
#   Name (NAME, value)                                   -> variable
#   External (NAME, type)  /  Include ("file")  /  #include -> import
#
# ASL uses C comments (`//`, `/* */`); the default strip handles them.  ACPI
# names are 4-char roots that may be scoped/rooted (`\_SB.PCI0`, `^DEV`, `_HID`).
import re

from .regex_base import RegexCodeAnalyzer

_NM = r"[\\^A-Za-z_][A-Za-z0-9_.\\^]*"


class AslAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "asl"
    EXTENSIONS = (".asl",)  # iasl `.dsl` output is a sibling, appended at test time
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = (("/*", "*/"),)
    STRING_DELIMS = ('"',)

    _CONTAINER = re.compile(
        r"(?m)\b(DefinitionBlock|Scope|Device|Processor|PowerResource|"
        r"ThermalZone|Field|IndexField|BankField|OperationRegion|Package)\s*\("
    )
    _METHOD = re.compile(r"(?m)\bMethod\s*\(\s*(" + _NM + r")\s*(?:,\s*(\d+))?")
    _NAME = re.compile(r"(?m)\bName\s*\(\s*(" + _NM + r")\s*,")
    _EXTERNAL = re.compile(r"(?m)\bExternal\s*\(\s*(" + _NM + r")")
    _INCLUDE = re.compile(r'(?m)^\s*(?:#\s*include|Include\s*\()\s*[<"]?([^>")\s]+)')

    def _simple(self, qname: str) -> str:
        return qname.strip("\\^").split(".")[-1] or qname

    def _first_arg(self, text: str, open_paren: int) -> str:
        end = self._find_matching(text, open_paren, "(", ")")
        inner = text[open_paren + 1 : end - 1]
        parts = self._split_top_level(inner)
        return parts[0].strip() if parts else ""

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._CONTAINER.finditer(clean):
            if m.group(1) == "Package":
                continue
            arg = self._first_arg(clean, m.end() - 1)
            arg = arg.strip('"')
            if arg and re.match(_NM, arg):
                self._register_class(self._simple(arg))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._INCLUDE.finditer(clean):
            src = m.group(1)
            self._add_import(file_id, src.split("/")[-1].split(".")[0] or src, src)
        for m in self._EXTERNAL.finditer(clean):
            nm = self._simple(m.group(1))
            self._add_import(file_id, nm, m.group(1))

        seen_cls = set()
        for m in self._CONTAINER.finditer(clean):
            kind = m.group(1)
            if kind == "Package":
                continue
            arg = self._first_arg(clean, m.end() - 1).strip('"')
            if kind == "DefinitionBlock":
                # first operand is the output-file string; use the table sig 2nd arg
                end = self._find_matching(clean, m.end() - 1, "(", ")")
                parts = self._split_top_level(clean[m.end() : end - 1])
                nm = parts[1].strip().strip('"') if len(parts) > 1 else "DSDT"
                self._add_class(
                    file_id,
                    nm or "DefinitionBlock",
                    description="ACPI definition block",
                )
                continue
            if not arg or not re.match(_NM, arg):
                continue
            nm = self._simple(arg)
            key = (nm, kind)
            if key in seen_cls:
                continue
            seen_cls.add(key)
            self._add_class(file_id, nm, description="ACPI " + kind)

        seen_fn = set()
        for m in self._METHOD.finditer(clean):
            nm = self._simple(m.group(1))
            if nm in seen_fn:
                continue
            seen_fn.add(nm)
            argc = int(m.group(2)) if m.group(2) else 0
            arg_ids = [self._add_arg(f"Arg{i}") for i in range(argc)]
            self._add_function(file_id, nm, arg_ids, [], description="ACPI method")

        seen_var = set()
        for m in self._NAME.finditer(clean):
            nm = self._simple(m.group(1))
            if nm in seen_var:
                continue
            seen_var.add(nm)
            self._add_variable(file_id, nm, "ACPI named object", scope="acpi")
