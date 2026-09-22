# Whitespace (.ws).
#
# Whitespace is an imperative stack/heap language whose ONLY significant
# characters are Space (0x20), Tab (0x09) and Line-Feed (0x0A); every other
# byte is a comment.  Instructions are grouped by an IMP (Instruction
# Modification Parameter) prefix:
#
#     [Space]        Stack manipulation
#     [Tab][Space]   Arithmetic
#     [Tab][Tab]     Heap access
#     [LF]           Flow control
#     [Tab][LF]      I/O
#
# The only *named* construct is a flow-control label.  Under the [LF] IMP:
#     [Space][Space] <label>  Mark a location   (a label definition)
#     [Space][Tab]   <label>  Call a subroutine
#     [Space][LF]    <label>  Jump unconditionally
#     [Tab][Space]   <label>  Jump if zero
#     [Tab][Tab]     <label>  Jump if negative
#     [Tab][LF]               Return
#     [LF][LF]                End program
# A <label> is a run of Space/Tab terminated by LF (Space=0, Tab=1, read as a
# binary number).  Numbers (Space=0/Tab=1 bits, sign first, LF-terminated) are
# the parameters of the other IMPs.
#
# This analyzer is a REAL Whitespace tokenizer: it filters the source to the
# three significant characters and walks the full instruction stream, consuming
# each instruction's parameters so a LF inside a number/label is never mistaken
# for a flow-control IMP.  Every "Mark" instruction is emitted as a function
# named `label_<n>`; subroutine calls are emitted as imports to `label_<n>`.
from .regex_base import RegexCodeAnalyzer


class WhitespaceAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "whitespace"
    EXTENSIONS = (".ws",)
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ()

    def _extract_entities(self, file_id, text, path):
        # Reduce to the three significant tokens: S=space, T=tab, L=linefeed.
        stream = []
        for ch in text:
            if ch == " ":
                stream.append("S")
            elif ch == "\t":
                stream.append("T")
            elif ch == "\n":
                stream.append("L")
        n = len(stream)
        i = 0

        def read_param():
            # a number or label: bits until the terminating L. Returns (value,)
            nonlocal i
            bits = []
            while i < n and stream[i] != "L":
                bits.append("0" if stream[i] == "S" else "1")
                i += 1
            if i < n:
                i += 1  # consume the terminating L
            return "".join(bits)

        def label_value(bits):
            # labels are compared as bit-strings; canonicalise to an int name.
            return int(bits, 2) if bits else 0

        defined = set()
        called = set()

        def take(k):
            nonlocal i
            got = "".join(stream[i : i + k])
            i += k
            return got

        while i < n:
            c = stream[i]
            if c == "S":  # Stack manipulation IMP
                i += 1
                if i >= n:
                    break
                if stream[i] == "S":  # push number
                    i += 1
                    read_param()
                elif stream[i] == "T":  # copy / slide (98) -> number param
                    i += 1
                    if i < n and stream[i] in ("S", "L"):
                        i += 1
                        read_param()
                    else:
                        break
                else:  # L: dup / swap / discard (2-char)
                    i += 1
                    if i < n:
                        i += 1
            elif c == "T":
                i += 1
                if i >= n:
                    break
                if stream[i] == "S":  # Arithmetic IMP: 2 more chars
                    i += 1
                    take(2)
                elif stream[i] == "T":  # Heap access IMP: 1 more char
                    i += 1
                    take(1)
                else:  # T L -> I/O IMP: 2 more chars
                    i += 1
                    take(2)
            elif c == "L":  # Flow control IMP
                i += 1
                op = take(2)
                if op == "SS":  # Mark a label
                    lbl = label_value(read_param())
                    defined.add(lbl)
                elif op in ("ST", "SL", "TS", "TT"):  # call / jumps
                    lbl = label_value(read_param())
                    if op == "ST":
                        called.add(lbl)
                # TL (return) / LL (end) take no parameter
            else:
                i += 1

        for lbl in sorted(defined):
            self._add_function(
                file_id,
                f"label_{lbl}",
                [],
                [],
                description="whitespace flow-control label",
            )
        for lbl in sorted(called - defined):
            # a call to a label not defined in this file (external / forward)
            self._add_import(file_id, f"label_{lbl}", f"label_{lbl}")
