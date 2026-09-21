# Befunge (.befunge).
#
# Befunge is a two-dimensional stack language: the instruction pointer moves
# across a grid ("Funge-Space") of single-character opcodes and can turn,
# wrap, and even self-modify.  Befunge-93 / Befunge-98 programs are a plain
# text rectangle where each cell is one instruction:
#
#       >987v>.v
#       v456<  :
#       >321 ^ _@
#
# The opcode alphabet is  0-9 a-f  (push digits/hex, 98)  and the operators
#       + - * / % ! ` > < ^ v ? _ | " : \ $ . , # g p & ~ @ ` { } ( ) etc.
#
# Like Brainfuck, Befunge has NO named symbols: no functions, variables,
# imports or types.  `"..."` toggles string mode (each char is pushed) and is
# NOT a declaration.  Befunge-98's `(`/`)` fingerprint-load takes its name off
# the stack at run time, so it is not statically recoverable either.
#
# The honest analysis therefore yields no named symbols; this analyzer parses
# the grid (it measures the playfield and tracks string-mode toggles so a
# quoted region is not mistaken for anything) and emits nothing.  An "empty"
# Befunge file is the CORRECT outcome.
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class BefungeAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "befunge"
    EXTENSIONS = (".befunge",)
    LINE_COMMENTS = ()          # there is no line-comment syntax
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ()          # `"` is run-time string mode, handled below

    def _extract_entities(self, file_id, text, path):
        # Walk the playfield honouring `"` string-mode toggles, purely to parse
        # the program faithfully.  Nothing in Befunge is named, so nothing is
        # recorded into the symbol tables.
        for line in text.splitlines():
            in_string = False
            for ch in line:
                if ch == '"':
                    in_string = not in_string
                # opcodes and pushed characters carry no declaration
        return
