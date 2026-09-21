"""
Binary analysis subpackage.

Two complementary analyzers:

* :class:`MachineCodeAnalyzer` (option 1) -- the post-planes stage that owns the
  ``binary`` routing class; deep struct-level parsers for executable / object /
  bytecode / firmware formats (ELF, PE/COFF, Mach-O, Java ``.class``, Python
  ``.pyc``, WebAssembly, Android DEX, ``ar``, LLVM bitcode, UF2, OLE) emitting the
  five ``binary_*`` relational tables.
* :class:`BinaryForensicsAnalyzer` (option 2) -- a standalone, format-agnostic
  forensic engine (size / sha256 / magic / detected-format / entropy / byte
  distribution / string extraction) plus the full ``binaries.json`` taxonomy;
  composed by ``MachineCodeAnalyzer`` and usable on its own.
* :class:`BinaryFormatParser` (option 3) -- deep magic-driven structural parsers
  for the *non-executable* binary universe (media / image / 3D-model / disk-image
  / firmware / scientific / serialization / font / ROM / packet-capture and
  ~1100 registered extensions). Consulted by ``MachineCodeAnalyzer`` when the
  executable dispatcher does not claim a file; identifies the concrete format
  from real content signatures and decodes documented header fields, degrading to
  an honest forensic disposition (never a fabricated field) for proprietary or
  undocumented payloads.
"""

from .binary_forensics import BinaryForensicsAnalyzer
from .format_parsers import BinaryFormatParser
from .machine_code import MachineCodeAnalyzer

__all__ = ["MachineCodeAnalyzer", "BinaryForensicsAnalyzer", "BinaryFormatParser"]
