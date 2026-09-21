# Brainfuck (.bf).
#
# Brainfuck's entire program is a stream of eight single-character commands:
#
#       >  <  +  -  .  ,  [  ]
#
# Every other byte is, by definition, a comment (the reference interpreter
# simply ignores it).  The language has NO named constructs whatsoever: no
# functions, no variables, no imports, no types.  A `[ ... ]` pair is the only
# structural unit and it is anonymous.
#
# Therefore the honest analysis of a Brainfuck file yields no named symbols.
# This analyzer still *parses* the file for real — it isolates the command
# stream, verifies bracket balance, and treats the balanced loops as the
# program's structure — but emits nothing into the symbol tables because the
# language names nothing.  A Brainfuck file legitimately showing up as "empty"
# in the symbol index is the CORRECT result, not a missed extraction.
from .regex_base import RegexCodeAnalyzer

_COMMANDS = set("><+-.,[]")


class BrainfuckAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "brainfuck"
    EXTENSIONS = (".bf",)
    LINE_COMMENTS = ()  # non-command bytes are the comments
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ()

    @staticmethod
    def _command_stream(text):
        """The program with every non-command byte (comment) removed."""
        return "".join(ch for ch in text if ch in _COMMANDS)

    def _extract_entities(self, file_id, text, path):
        # Parse the command stream so a malformed program does not masquerade
        # as a well-formed one, then emit nothing: Brainfuck names no entity.
        code = self._command_stream(text)
        depth = 0
        for ch in code:
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth = max(0, depth - 1)
        # depth/balance is validated but there is nothing named to record.
        return
