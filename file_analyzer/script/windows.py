# Windows command-language scripts for the `script` plane.
#
#   .ps1 .psm1   PowerShell scripts / script-modules
#   .bat .cmd    Windows / OS-2 batch files
#
# Both are real hand-written parsers built on `ShellScriptBase` (so a sourced
# file -> import, a subroutine -> function, a variable -> variable, identical
# table shape to every other `code` file).
import re

from ..shell.shell_base import ShellScriptBase


class PowerShellAnalyzer(ShellScriptBase):
    """PowerShell (`.ps1` script, `.psm1` module).

    function Get-Thing { param([int]$n) ... }   -> function (+params)
    filter Select-Even { ... }                  -> function
    class Widget : Base { [int]$Size }          -> class (+parent)
    enum Color { Red; Green }                   -> class row
    Import-Module Pester                         -> import
    using module ./lib.psm1                      -> import
    . "$PSScriptRoot/helpers.ps1"                -> import (dot-source)
    $script:Count = 0                            -> variable
    """

    LANG_KEY = "powershell"
    EXTENSIONS = (".ps1", ".psm1")
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = (("<#", "#>"),)
    STRING_DELIMS = ('"', "'")

    _FUNC = re.compile(
        r"(?im)^[ \t]*(?:function|filter|workflow|configuration)[ \t]+"
        r"(?:global:|local:|script:|private:)?([A-Za-z_][\w-]*)"
    )
    _CLASS = re.compile(
        r"(?im)^[ \t]*class[ \t]+([A-Za-z_]\w*)"
        r"(?:[ \t]*:[ \t]*([A-Za-z_][\w.,\s]*?))?[ \t]*\{"
    )
    _ENUM = re.compile(r"(?im)^[ \t]*enum[ \t]+([A-Za-z_]\w*)")
    _IMPORT_MODULE = re.compile(
        r"(?im)^[ \t]*Import-Module[ \t]+" r"(?:-Name[ \t]+)?['\"]?([\w.\-/\\]+)"
    )
    _USING = re.compile(
        r"(?im)^[ \t]*using[ \t]+(?:module|namespace|assembly)[ \t]+"
        r"['\"]?([\w.\-/\\]+)"
    )
    _DOTSOURCE = re.compile(r"(?m)^[ \t]*\.[ \t]+(['\"]?)([^\n'\";]+?)\1[ \t]*$")
    _PARAM_BLOCK = re.compile(r"(?is)\bparam[ \t]*\(")
    _PARAM_VAR = re.compile(
        r"(?:\[[^\]]+\][ \t]*)*\$(?:global:|local:|script:|private:)?" r"([A-Za-z_]\w*)"
    )
    # Top-level assignment: $Var = ...  /  $script:Var = ...
    _ASSIGN = re.compile(
        r"(?m)^[ \t]*\$(?:global:|script:|env:)?([A-Za-z_]\w*)[ \t]*=(?!=)"
    )

    def _register_types(self, file_id, text, path):
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        clean = self._strip_comments(text)
        for m in self._CLASS.finditer(clean):
            self._register_class(m.group(1))
        for m in self._ENUM.finditer(clean):
            self._register_class(m.group(1))

    def _find_block(self, text, open_idx):
        """Return the substring of a `( ... )` block starting at `open_idx`."""
        depth, i, n = 0, open_idx, len(text)
        while i < n:
            c = text[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return text[open_idx + 1 : i]
            i += 1
        return text[open_idx + 1 :]

    def _extract_entities(self, file_id, text, path):
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        self._record_shebang(file_id, text)
        clean = self._strip_comments(text)

        # Imports: Import-Module, using module/namespace, dot-sourced scripts.
        seen_imp = set()
        for m in self._IMPORT_MODULE.finditer(clean):
            mod = m.group(1)
            if mod not in seen_imp:
                seen_imp.add(mod)
                self._add_sourced(file_id, mod, keyword="import-module")
        for m in self._USING.finditer(clean):
            mod = m.group(1)
            if mod not in seen_imp:
                seen_imp.add(mod)
                self._add_sourced(file_id, mod, keyword="using")
        for m in self._DOTSOURCE.finditer(clean):
            tgt = m.group(2).strip()
            # a bare `.` method call is not a dot-source; require a path-ish token
            if not tgt or tgt in seen_imp or not re.search(r"[\\/.]", tgt):
                continue
            if tgt.lower().rsplit(".", 1)[-1] not in ("ps1", "psm1"):
                continue
            seen_imp.add(tgt)
            self._add_sourced(file_id, tgt, keyword="dot-source")

        # Classes / enums (+ parents).
        for m in self._CLASS.finditer(clean):
            name, bases = m.group(1), m.group(2)
            parents = []
            if bases:
                for b in bases.split(","):
                    pid = self._register_class(b.strip())
                    if pid is not None:
                        parents.append(pid)
            self._add_class(
                file_id, name, parent_ids=parents, description="powershell class"
            )
        for m in self._ENUM.finditer(clean):
            self._add_class(file_id, m.group(1), description="powershell enum")

        # Functions (+ param() positional/named parameters).
        seen_fn = set()
        for m in self._FUNC.finditer(clean):
            name = m.group(1)
            if name in seen_fn:
                continue
            seen_fn.add(name)
            params = []
            pm = self._PARAM_BLOCK.search(clean, m.end())
            # only treat a param() that is close to the function head as its own
            if pm and pm.start() - m.end() < 200:
                block = self._find_block(clean, pm.end() - 1)
                params = self._uniq(self._PARAM_VAR.findall(block))
            self._add_shell_function(
                file_id, name, params=params, description="powershell function"
            )

        # Module-level variables.
        seen_var = set()
        for m in self._ASSIGN.finditer(clean):
            name = m.group(1)
            if name in seen_var or name.lower() in ("_", "true", "false", "null"):
                continue
            seen_var.add(name)
            self._add_variable(file_id, name, scope="module")

        self._record_module_meta(
            file_id,
            dialect="powershell",
            is_module=path.suffix.lower() == ".psm1",
            functions=len(seen_fn),
            variables=len(seen_var),
        )


class BatchScriptAnalyzer(ShellScriptBase):
    """Windows / OS-2 batch (`.bat`, `.cmd`).

    :build                                        -> function (label/subroutine)
    call :build arg1                              -> (call target)
    set NAME=value    set /a N=1    set /p X=?    -> variable
    call other.bat                                -> import
    %VAR%  !VAR!                                  -> (variable references)
    """

    LANG_KEY = "batch"
    EXTENSIONS = (".bat", ".cmd")
    LINE_COMMENTS = ("::",)  # `rem` handled explicitly below
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _LABEL = re.compile(r"(?im)^[ \t]*:([A-Za-z_][\w.$-]*)[ \t]*$")
    _SET = re.compile(
        r"(?im)^[ \t]*set[ \t]+(?:/a[ \t]+|/p[ \t]+)?" r"\"?([A-Za-z_][\w.#$-]*)="
    )
    _CALL_FILE = re.compile(
        r"(?im)^[ \t]*call[ \t]+(?!:)\"?([\w.\-\\/%~]+\.(?:bat|cmd))"
    )
    _CALL_LABEL = re.compile(r"(?im)^[ \t]*call[ \t]+:([A-Za-z_][\w.$-]*)")
    _GOTO = re.compile(r"(?im)^[ \t]*goto[ \t]+:?([A-Za-z_][\w.$-]*)")

    def _strip_rem(self, text: str) -> str:
        # `rem comment` lines (whole-line remark) -> blanked, newlines kept.
        return re.sub(r"(?im)^[ \t]*rem\b.*$", "", text)

    def _register_types(self, file_id, text, path):
        return

    def _extract_entities(self, file_id, text, path):
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        clean = self._strip_comments(self._strip_rem(text))

        # Labels are the callable subroutines of a batch file.
        seen_fn = set()
        for m in self._LABEL.finditer(clean):
            name = m.group(1)
            if name.lower() in ("eof",) or name in seen_fn:
                continue
            seen_fn.add(name)
            self._add_shell_function(file_id, name, description="batch label")

        # Variables (set / set /a / set /p).
        seen_var = set()
        for m in self._SET.finditer(clean):
            name = m.group(1)
            if name in seen_var:
                continue
            seen_var.add(name)
            self._add_variable(file_id, name, scope="module")

        # Called external batch files -> imports.
        seen_imp = set()
        for m in self._CALL_FILE.finditer(clean):
            tgt = m.group(1)
            if tgt not in seen_imp:
                seen_imp.add(tgt)
                self._add_sourced(file_id, tgt, keyword="call")

        calls = len(self._CALL_LABEL.findall(clean))
        self._record_module_meta(
            file_id,
            dialect="batch",
            labels=len(seen_fn),
            variables=len(seen_var),
            subroutine_calls=calls,
            gotos=len(self._GOTO.findall(clean)),
        )
