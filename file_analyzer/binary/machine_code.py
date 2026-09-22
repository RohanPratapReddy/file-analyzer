"""
Deep executable / object / bytecode analysis.

``MachineCodeAnalyzer`` is the post-planes stage that owns the ``binary`` routing
class: every file whose true suffix names a machine-code / object / bytecode /
firmware container (ELF, PE/COFF, Mach-O, Java ``.class``, Python ``.pyc``,
WebAssembly, Android DEX, ``ar`` static libraries, LLVM bitcode, UF2, OLE/MSI) is
routed here and parsed with pure-stdlib ``struct`` readers -- no third-party
dependencies, no external tools.

For each binary it produces five relational tables:

    * ``binary_index``       -- one row per file: format, arch, bitness, endianness,
                                entry point, stripped/dynamic/PIC flags, section /
                                symbol / import / export counts, sha256, size,
                                entropy, how the format was detected, and notes.
    * ``binary_sections``    -- one row per section / segment (name, type, virtual
                                address, file offset, size, flags, per-section
                                entropy where cheaply available).
    * ``binary_symbols``     -- one row per symbol (name, kind, binding, address,
                                size, section, import/export flags, library).
    * ``binary_imports``     -- one row per imported library / symbol dependency.
    * ``binary_properties``  -- flexible ``(group, name, value)`` bag for
                                format-specific facts that do not fit a fixed column
                                (OS/ABI, machine string, PE characteristics, Mach-O
                                load commands, WASM section sizes, class-file version,
                                pyc magic / interpreter version, ...).

The generic, format-independent layer (size, sha256, magic, entropy, detected
format, taxonomy category) is delegated to :class:`BinaryForensicsAnalyzer`, which
this class composes -- so every ``binary_index`` row also carries honest forensic
metrics even when the deep parser only partially understands a format.

Everything here is metadata only. Section/segment *contents* are never stored; at
most a bounded byte window is read to measure per-section entropy. Robustness rule:
any single malformed file is caught, recorded with a ``notes``/``error`` marker,
and never sinks the batch.
"""

import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .binary_forensics import BinaryForensicsAnalyzer
from .format_parsers import BinaryFormatParser

# Bounded reads so a hostile / truncated header cannot cause a huge allocation.
_MAX_SECTIONS = 20_000
_MAX_SYMBOLS = 200_000
_MAX_IMPORTS = 100_000
_SECTION_ENTROPY_CAP = 1 << 20  # 1 MiB window per section for entropy


class MachineCodeAnalyzer:
    """Deep parser for executable / object / bytecode formats (owns ``binary`` routing)."""

    # Extensions this analyzer claims exclusively via the router. These are
    # machine-code / object / bytecode / firmware containers that are NOT already
    # owned by code/schema/archive/data. (Verified against the live router: none of
    # these collide with DataAnalyzer's semantic formats or ArchiveAnalyzer.)
    # NOTE: kept deliberately free of collisions with the higher-priority classes.
    # ``.mod`` / ``.ll`` are already owned by ``code`` (they win via priority), and
    # ``.msp`` is owned by ``DataAnalyzer`` -- none are listed here so routing is
    # unchanged for them and no format regresses.
    ROUTED_EXTS = frozenset(
        {
            # ELF & generic executables / objects
            ".elf",
            ".o",
            ".ko",
            ".so",
            ".prx",
            ".axf",
            ".bin",
            # PE / COFF (Windows)
            ".exe",
            ".dll",
            ".sys",
            ".efi",
            ".ocx",
            ".cpl",
            ".scr",
            ".drv",
            ".mui",
            ".winmd",
            # Mach-O (Apple) -- .dylib; bare Mach-O executables usually carry no suffix
            # and .bundle is archive-owned, so they are handled by content-sniff, not here
            ".dylib",
            ".macho",
            # Java / JVM bytecode
            ".class",
            # Python bytecode
            ".pyc",
            ".pyo",
            # WebAssembly
            ".wasm",
            # Android runtime
            ".dex",
            ".odex",
            ".oat",
            ".vdex",
            ".art",
            # OCaml / LLVM / misc bytecode & firmware
            ".bc",
            ".llbc",
            ".cma",
            ".cmo",
            ".cmx",
            ".cmxs",
            ".uf2",
            ".hex",
            ".srec",
            ".s19",
            ".s28",
            ".s37",
            # Installer / OLE compound (technical structure only)
            ".msi",
            ".msm",
        }
    )

    def __init__(
        self, engine: Any = None, files_rows: Optional[List[Dict[str, Any]]] = None
    ):
        """
        Args:
            engine: the owning AnalysisEngine (optional; only read for attrs). Kept
                for signature-parity with the other post-planes stages.
            files_rows: list of ``{file_id, file_location, analyzer_class}`` rows.
                Only rows with ``analyzer_class == "binary"`` (or a routed suffix)
                are parsed.
        """
        self.engine = engine
        self.files_rows = files_rows or []
        self.forensics = BinaryForensicsAnalyzer()
        # Deep structural parser for the non-executable binary universe (media /
        # image / model / disk-image / firmware / scientific / serialization /
        # font / ROM / capture). Consulted when the executable dispatcher below
        # does not claim the file, before falling back to a bare forensic note.
        self.format_parser = BinaryFormatParser()
        self._bid = 0
        self._sec_id = 0
        self._sym_id = 0
        self._imp_id = 0
        self._prop_id = 0

    # ------------------------------------------------------------------
    def process(self) -> Dict[str, List[Dict[str, Any]]]:
        """Parse every routed binary file and return the five binary_* tables."""
        index: List[Dict[str, Any]] = []
        sections: List[Dict[str, Any]] = []
        symbols: List[Dict[str, Any]] = []
        imports: List[Dict[str, Any]] = []
        properties: List[Dict[str, Any]] = []

        for row in self.files_rows:
            cls = row.get("analyzer_class")
            loc = row.get("file_location")
            if not loc:
                continue
            if cls not in (None, "binary") and cls != "binary":
                # Only handle rows explicitly routed to us.
                if cls != "binary":
                    continue
            self._bid += 1
            bid = self._bid
            try:
                self._analyze_one(
                    bid, row, index, sections, symbols, imports, properties
                )
            except (
                Exception
            ) as err:  # noqa: BLE001 - one bad file must not sink the batch
                index.append(
                    self._min_index_row(bid, row, error=f"{type(err).__name__}: {err}")
                )

        return {
            "binary_index": index,
            "binary_sections": sections,
            "binary_symbols": symbols,
            "binary_imports": imports,
            "binary_properties": properties,
        }

    # ------------------------------------------------------------------
    def _analyze_one(
        self, bid, row, index, sections, symbols, imports, properties
    ) -> None:
        path = Path(row["file_location"])
        prof = self.forensics.profile(path)

        # Base index row from forensics; the deep parser fills structural columns.
        idx = {
            "binary_id": bid,
            "file_id": row.get("file_id"),
            "file_name": path.name,
            "binary_format": prof.get("detected_format"),
            "format_family": prof.get("format_family"),
            "category": prof.get("category"),
            "subcategory": prof.get("subcategory"),
            "architecture": None,
            "bitness": None,
            "endianness": None,
            "entry_point": None,
            "is_stripped": None,
            "is_dynamic": None,
            "is_pic": None,
            "section_count": 0,
            "symbol_count": 0,
            "import_count": 0,
            "export_count": 0,
            "sha256": prof.get("sha256"),
            "size": prof.get("size"),
            "entropy": prof.get("entropy"),
            "detected_via": "magic" if prof.get("detected_format") else "extension",
            "notes": None,
            "error": prof.get("error"),
        }

        try:
            with open(path, "rb") as fh:
                head = fh.read(64)
        except OSError as err:
            idx["error"] = f"read failed: {type(err).__name__}: {err}"
            index.append(idx)
            return

        parser = self._dispatch(head, path.suffix.lower())
        if parser is not None:
            try:
                parser(bid, path, idx, sections, symbols, imports, properties)
            except Exception as err:  # noqa: BLE001
                idx["notes"] = f"deep-parse partial: {type(err).__name__}: {err}"
        else:
            # Not an executable/object/bytecode container: consult the deep
            # structural parser for the rest of the binary universe. It does real
            # magic-first identification and header decoding; for genuinely
            # proprietary/undocumented payloads it returns an honest forensic
            # disposition (no fabricated fields), which layers on top of the
            # format-agnostic forensic profile already computed above.
            self._apply_format_parser(bid, path, idx, sections, properties)

        idx["section_count"] = sum(1 for s in sections if s["binary_id"] == bid)
        idx["symbol_count"] = sum(1 for s in symbols if s["binary_id"] == bid)
        idx["import_count"] = sum(1 for s in imports if s["binary_id"] == bid)
        idx["export_count"] = sum(
            1 for s in symbols if s["binary_id"] == bid and s.get("is_export")
        )
        index.append(idx)

    def _dispatch(self, head: bytes, ext: str):
        if head[:4] == b"\x7fELF":
            return self._parse_elf
        if head[:2] == b"MZ":
            return self._parse_pe
        if head[:4] in (
            b"\xfe\xed\xfa\xce",
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xcf\xfa\xed\xfe",
        ):
            return self._parse_macho
        if head[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") and ext in (
            ".class",
        ):
            return self._parse_class
        if head[:4] == b"\xca\xfe\xba\xbe" and ext == ".class":
            return self._parse_class
        if head[:4] == b"\xca\xfe\xba\xbe":
            # Ambiguous: Java class vs Mach-O universal. Extension disambiguates;
            # default to class only for .class, else fat Mach-O.
            return self._parse_class if ext == ".class" else self._parse_macho_fat
        if head[:4] == b"\x00asm":
            return self._parse_wasm
        if head[:4] in (b"dex\n", b"dey\n"):
            return self._parse_dex
        if head[:8] == b"!<arch>\n":
            return self._parse_ar
        if head[:4] in (b"BC\xc0\xde", b"\xde\xc0\x17\x0b"):
            return self._parse_llvm_bitcode
        if head[:4] == b"UF2\n" or ext == ".uf2":
            return self._parse_uf2
        if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            return self._parse_ole
        if ext in (".pyc", ".pyo"):
            return self._parse_pyc
        if ext in (".hex", ".srec", ".s19", ".s28", ".s37"):
            return self._parse_hexrec
        return None

    # ------------------------------------------------------------------
    def _apply_format_parser(self, bid, path, idx, sections, properties) -> None:
        """Fold BinaryFormatParser output into the index/section/property tables.

        Refines ``binary_format`` / ``format_family`` from the concrete magic-
        driven identification, records ``detected_via``, and appends the parser's
        real structural sections and header properties with proper table ids. Only
        overrides the forensic-derived label when the deep parser actually
        identified something -- it never blanks a value the forensics found.
        """
        res = self.format_parser.analyze(path)
        if res.get("format"):
            idx["binary_format"] = res["format"]
        if res.get("family"):
            idx["format_family"] = res["family"]
        if res.get("detected_via"):
            idx["detected_via"] = res["detected_via"]
        if res.get("notes"):
            idx["notes"] = res["notes"]
        elif not idx.get("notes"):
            idx["notes"] = "structural parse; forensic profile only"

        for sec in res.get("sections", []):
            self._sec_id += 1
            sections.append(
                {
                    "section_id": self._sec_id,
                    "binary_id": bid,
                    "ordinal": None,
                    "name": sec.get("name"),
                    "sec_type": sec.get("sec_type"),
                    "virtual_address": None,
                    "file_offset": sec.get("file_offset"),
                    "size": sec.get("size"),
                    "flags": None,
                    "entropy": None,
                }
            )
        for group, name, value in res.get("properties", []):
            self._prop(properties, bid, group, name, value)

    # ==================================================================
    # ELF
    # ==================================================================
    _ELF_MACHINE = {
        0: "None",
        2: "SPARC",
        3: "x86",
        8: "MIPS",
        20: "PowerPC",
        21: "PowerPC64",
        40: "ARM",
        42: "SuperH",
        43: "SPARCv9",
        50: "IA-64",
        62: "x86-64",
        183: "AArch64",
        243: "RISC-V",
        258: "LoongArch",
    }
    _ELF_OSABI = {
        0: "System V",
        1: "HP-UX",
        2: "NetBSD",
        3: "Linux",
        6: "Solaris",
        9: "FreeBSD",
        12: "OpenBSD",
        255: "Standalone",
    }
    _ELF_TYPE = {
        0: "NONE",
        1: "REL (object)",
        2: "EXEC",
        3: "DYN (shared/PIE)",
        4: "CORE",
    }
    _ELF_SHT = {
        0: "NULL",
        1: "PROGBITS",
        2: "SYMTAB",
        3: "STRTAB",
        4: "RELA",
        5: "HASH",
        6: "DYNAMIC",
        7: "NOTE",
        8: "NOBITS",
        9: "REL",
        11: "DYNSYM",
        14: "INIT_ARRAY",
        15: "FINI_ARRAY",
    }

    def _parse_elf(self, bid, path, idx, sections, symbols, imports, properties):
        data = path.read_bytes()
        if len(data) < 64:
            raise ValueError("ELF header truncated")
        ei_class = data[4]  # 1=32, 2=64
        ei_data = data[5]  # 1=LE, 2=BE
        ei_osabi = data[7]
        bits = 64 if ei_class == 2 else 32
        endian = "<" if ei_data == 1 else ">"
        idx["bitness"] = bits
        idx["endianness"] = "little" if ei_data == 1 else "big"
        idx["binary_format"] = "ELF"
        idx["format_family"] = "executable"

        if bits == 64:
            (
                e_type,
                e_machine,
                e_version,
                e_entry,
                e_phoff,
                e_shoff,
                e_flags,
                e_ehsize,
                e_phentsize,
                e_phnum,
                e_shentsize,
                e_shnum,
                e_shstrndx,
            ) = struct.unpack(endian + "HHIQQQIHHHHHH", data[16:64])
        else:
            (
                e_type,
                e_machine,
                e_version,
                e_entry,
                e_phoff,
                e_shoff,
                e_flags,
                e_ehsize,
                e_phentsize,
                e_phnum,
                e_shentsize,
                e_shnum,
                e_shstrndx,
            ) = struct.unpack(endian + "HHIIIIIHHHHHH", data[16:52])

        idx["architecture"] = self._ELF_MACHINE.get(e_machine, f"machine-{e_machine}")
        idx["entry_point"] = e_entry
        idx["is_pic"] = e_type == 3
        self._prop(
            properties, bid, "elf", "type", self._ELF_TYPE.get(e_type, str(e_type))
        )
        self._prop(
            properties,
            bid,
            "elf",
            "osabi",
            self._ELF_OSABI.get(ei_osabi, str(ei_osabi)),
        )
        self._prop(properties, bid, "elf", "flags", hex(e_flags))
        self._prop(properties, bid, "elf", "program_headers", str(e_phnum))

        # Section headers.
        is_dynamic = False
        stripped = True
        if e_shoff and e_shnum and e_shnum < _MAX_SECTIONS:
            # Section-header string table.
            shstr_off = None
            sh_entries = []
            for i in range(e_shnum):
                base = e_shoff + i * e_shentsize
                raw = data[base : base + e_shentsize]
                if len(raw) < e_shentsize:
                    break
                if bits == 64:
                    (
                        sh_name,
                        sh_type,
                        sh_flags,
                        sh_addr,
                        sh_offset,
                        sh_size,
                        sh_link,
                        sh_info,
                        sh_addralign,
                        sh_entsize,
                    ) = struct.unpack(endian + "IIQQQQIIQQ", raw[:64])
                else:
                    (
                        sh_name,
                        sh_type,
                        sh_flags,
                        sh_addr,
                        sh_offset,
                        sh_size,
                        sh_link,
                        sh_info,
                        sh_addralign,
                        sh_entsize,
                    ) = struct.unpack(endian + "IIIIIIIIII", raw[:40])
                sh_entries.append(
                    (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size)
                )
            if e_shstrndx < len(sh_entries):
                shstr_off = sh_entries[e_shstrndx][4]
                shstr_size = sh_entries[e_shstrndx][5]
                shstrtab = data[shstr_off : shstr_off + shstr_size]
            else:
                shstrtab = b""

            for ordv, (
                sh_name,
                sh_type,
                sh_flags,
                sh_addr,
                sh_offset,
                sh_size,
            ) in enumerate(sh_entries):
                name = self._cstr(shstrtab, sh_name) if shstrtab else ""
                if name in (".symtab",):
                    stripped = False
                if name == ".dynamic":
                    is_dynamic = True
                self._sec_id += 1
                sections.append(
                    {
                        "section_id": self._sec_id,
                        "binary_id": bid,
                        "ordinal": ordv,
                        "name": name,
                        "sec_type": self._ELF_SHT.get(sh_type, f"0x{sh_type:x}"),
                        "virtual_address": sh_addr,
                        "file_offset": sh_offset,
                        "size": sh_size,
                        "flags": self._elf_shflags(sh_flags),
                        "entropy": self._section_entropy(
                            data, sh_offset, sh_size, sh_type
                        ),
                    }
                )

            # Symbols (.dynsym / .symtab) + needed libraries (.dynamic DT_NEEDED).
            self._elf_symbols(bid, data, endian, bits, sh_entries, shstrtab, symbols)
            self._elf_needed(bid, data, endian, bits, sh_entries, imports)

        idx["is_dynamic"] = is_dynamic
        idx["is_stripped"] = stripped

    def _elf_shflags(self, f):
        out = []
        if f & 0x1:
            out.append("WRITE")
        if f & 0x2:
            out.append("ALLOC")
        if f & 0x4:
            out.append("EXEC")
        if f & 0x20:
            out.append("STRINGS")
        return ",".join(out)

    _ELF_STT = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE", 6: "TLS"}
    _ELF_STB = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}

    def _elf_symbols(self, bid, data, endian, bits, sh_entries, shstrtab, symbols):
        for sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size in sh_entries:
            if sh_type not in (2, 11):  # SYMTAB, DYNSYM
                continue
            # Find its linked string table via the section whose name matches convention.
            secname = self._cstr(shstrtab, sh_name) if shstrtab else ""
            strtab_name = ".strtab" if sh_type == 2 else ".dynstr"
            strtab = b""
            for n2, t2, fl2, a2, o2, s2 in sh_entries:
                if self._cstr(shstrtab, n2) == strtab_name:
                    strtab = data[o2 : o2 + s2]
                    break
            entsize = 24 if bits == 64 else 16
            count = sh_size // entsize if entsize else 0
            for i in range(min(count, _MAX_SYMBOLS)):
                base = sh_offset + i * entsize
                raw = data[base : base + entsize]
                if len(raw) < entsize:
                    break
                if bits == 64:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = (
                        struct.unpack(endian + "IBBHQQ", raw)
                    )
                else:
                    st_name, st_value, st_size, st_info, st_other, st_shndx = (
                        struct.unpack(endian + "IIIBBH", raw)
                    )
                name = self._cstr(strtab, st_name) if strtab else ""
                if not name:
                    continue
                stt = st_info & 0xF
                stb = st_info >> 4
                is_import = st_shndx == 0  # SHN_UNDEF -> imported
                is_export = stb in (1, 2) and st_shndx != 0
                self._sym_id += 1
                symbols.append(
                    {
                        "symbol_id": self._sym_id,
                        "binary_id": bid,
                        "name": name,
                        "sym_kind": self._ELF_STT.get(stt, str(stt)),
                        "binding": self._ELF_STB.get(stb, str(stb)),
                        "address": st_value,
                        "size": st_size,
                        "section": str(st_shndx),
                        "is_import": is_import,
                        "is_export": is_export,
                        "library": None,
                    }
                )

    def _elf_needed(self, bid, data, endian, bits, sh_entries, imports):
        # DT_NEEDED = 1; entries live in .dynamic, strings in .dynstr.
        dynamic = None
        dynstr = b""
        for sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size in sh_entries:
            if sh_type == 6:  # DYNAMIC
                dynamic = (sh_offset, sh_size)
            if sh_type == 3 and dynstr == b"":
                pass
        # locate .dynstr by type STRTAB linked to dynsym is hard without names;
        # use the last STRTAB that is ALLOC (dynstr is allocated, .strtab is not).
        for sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size in sh_entries:
            if sh_type == 3 and (sh_flags & 0x2):  # STRTAB + ALLOC => .dynstr
                dynstr = data[sh_offset : sh_offset + sh_size]
                break
        if not dynamic or not dynstr:
            return
        off, size = dynamic
        entsize = 16 if bits == 64 else 8
        count = size // entsize if entsize else 0
        for i in range(min(count, _MAX_IMPORTS)):
            base = off + i * entsize
            raw = data[base : base + entsize]
            if len(raw) < entsize:
                break
            if bits == 64:
                d_tag, d_val = struct.unpack(endian + "qQ", raw)
            else:
                d_tag, d_val = struct.unpack(endian + "iI", raw)
            if d_tag == 0:  # DT_NULL terminates
                break
            if d_tag == 1:  # DT_NEEDED
                lib = self._cstr(dynstr, d_val)
                if lib:
                    self._imp_id += 1
                    imports.append(
                        {
                            "import_id": self._imp_id,
                            "binary_id": bid,
                            "library": lib,
                            "symbol": None,
                            "kind": "needed-library",
                        }
                    )

    # ==================================================================
    # PE / COFF
    # ==================================================================
    _PE_MACHINE = {
        0x14C: "x86",
        0x8664: "x86-64",
        0x1C0: "ARM",
        0xAA64: "ARM64",
        0x1C4: "ARMv7 (Thumb)",
        0x200: "IA-64",
        0x5032: "RISC-V32",
        0x5064: "RISC-V64",
        0xEBC: "EFI byte code",
    }

    def _parse_pe(self, bid, path, idx, sections, symbols, imports, properties):
        data = path.read_bytes()
        if len(data) < 0x40:
            raise ValueError("MZ header truncated")
        e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
        if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            idx["binary_format"] = "MZ (DOS, no PE header)"
            idx["format_family"] = "executable"
            return
        idx["binary_format"] = "PE"
        idx["format_family"] = "executable"
        coff = e_lfanew + 4
        (
            machine,
            num_sections,
            timestamp,
            sym_ptr,
            num_syms,
            opt_size,
            characteristics,
        ) = struct.unpack("<HHIIIHH", data[coff : coff + 20])
        idx["architecture"] = self._PE_MACHINE.get(machine, f"machine-0x{machine:x}")
        idx["is_dynamic"] = bool(characteristics & 0x2000)  # IMAGE_FILE_DLL
        idx["is_stripped"] = bool(characteristics & 0x0200)  # DEBUG_STRIPPED
        self._prop(properties, bid, "pe", "characteristics", hex(characteristics))
        self._prop(properties, bid, "pe", "timestamp", str(timestamp))
        if characteristics & 0x2000:
            idx["binary_format"] = "PE (DLL)"

        opt = coff + 20
        magic = (
            struct.unpack("<H", data[opt : opt + 2])[0] if opt + 2 <= len(data) else 0
        )
        pe32plus = magic == 0x20B
        idx["bitness"] = 64 if pe32plus else 32
        idx["endianness"] = "little"
        if opt + 20 <= len(data):
            entry = struct.unpack("<I", data[opt + 16 : opt + 20])[0]
            idx["entry_point"] = entry
        # ImageBase & subsystem for context.
        try:
            if pe32plus:
                image_base = struct.unpack("<Q", data[opt + 24 : opt + 32])[0]
            else:
                image_base = struct.unpack("<I", data[opt + 28 : opt + 32])[0]
            self._prop(properties, bid, "pe", "image_base", hex(image_base))
        except struct.error:
            pass

        # Section table follows the optional header.
        sec_off = opt + opt_size
        for i in range(min(num_sections, _MAX_SECTIONS)):
            base = sec_off + i * 40
            raw = data[base : base + 40]
            if len(raw) < 40:
                break
            name = raw[:8].rstrip(b"\x00").decode("latin-1", "replace")
            vsize, vaddr, rawsize, rawptr, relptr, lnptr, nrel, nln, chars = (
                struct.unpack("<IIIIIIHHI", raw[8:40])
            )
            self._sec_id += 1
            sections.append(
                {
                    "section_id": self._sec_id,
                    "binary_id": bid,
                    "ordinal": i,
                    "name": name,
                    "sec_type": (
                        "code"
                        if chars & 0x20
                        else ("data" if chars & 0xC0 else "other")
                    ),
                    "virtual_address": vaddr,
                    "file_offset": rawptr,
                    "size": rawsize,
                    "flags": self._pe_secflags(chars),
                    "entropy": self._section_entropy(data, rawptr, rawsize, 1),
                }
            )
        # Import & export directories (best-effort).
        self._pe_imports(bid, data, opt, pe32plus, sec_off, num_sections, imports)
        self._pe_exports(bid, data, opt, pe32plus, sec_off, num_sections, symbols)

    def _pe_secflags(self, c):
        out = []
        if c & 0x20:
            out.append("CODE")
        if c & 0x40:
            out.append("IDATA")
        if c & 0x80:
            out.append("UDATA")
        if c & 0x20000000:
            out.append("EXEC")
        if c & 0x40000000:
            out.append("READ")
        if c & 0x80000000:
            out.append("WRITE")
        return ",".join(out)

    def _pe_imports(self, bid, data, opt, pe32plus, sec_off, num_sections, imports):
        # DataDirectory[1] = import table (RVA, size). Located after the fixed
        # optional-header fields + NumberOfRvaAndSizes.
        try:
            dd_base = opt + (0x70 if pe32plus else 0x60)
            imp_rva = struct.unpack("<I", data[dd_base + 8 : dd_base + 12])[0]
            if not imp_rva:
                return
            # Build section map for RVA->offset.
            secs = []
            for i in range(num_sections):
                base = sec_off + i * 40
                raw = data[base : base + 40]
                if len(raw) < 40:
                    break
                vaddr, rawsize, rawptr = struct.unpack("<III", raw[12:24])
                secs.append((vaddr, rawsize, rawptr))

            def rva2off(rva):
                for vaddr, rawsize, rawptr in secs:
                    if vaddr <= rva < vaddr + max(rawsize, 1):
                        return rawptr + (rva - vaddr)
                return None

            off = rva2off(imp_rva)
            if off is None:
                return
            for n in range(_MAX_IMPORTS):
                ent = data[off + n * 20 : off + n * 20 + 20]
                if len(ent) < 20 or ent == b"\x00" * 20:
                    break
                name_rva = struct.unpack("<I", ent[12:16])[0]
                if not name_rva:
                    break
                noff = rva2off(name_rva)
                if noff is None:
                    break
                lib = self._cstr(data, noff)
                if lib:
                    self._imp_id += 1
                    imports.append(
                        {
                            "import_id": self._imp_id,
                            "binary_id": bid,
                            "library": lib,
                            "symbol": None,
                            "kind": "import-dll",
                        }
                    )
        except (struct.error, IndexError):
            return

    def _pe_section_map(self, data, sec_off, num_sections):
        secs = []
        for i in range(num_sections):
            base = sec_off + i * 40
            raw = data[base : base + 40]
            if len(raw) < 40:
                break
            vaddr, rawsize, rawptr = struct.unpack("<III", raw[12:24])
            secs.append((vaddr, rawsize, rawptr))

        def rva2off(rva):
            for vaddr, rawsize, rawptr in secs:
                if vaddr <= rva < vaddr + max(rawsize, 1):
                    return rawptr + (rva - vaddr)
            return None

        return rva2off

    def _pe_exports(self, bid, data, opt, pe32plus, sec_off, num_sections, symbols):
        # DataDirectory[0] = export table (RVA, size).
        try:
            dd_base = opt + (0x70 if pe32plus else 0x60)
            exp_rva = struct.unpack("<I", data[dd_base : dd_base + 4])[0]
            if not exp_rva:
                return
            rva2off = self._pe_section_map(data, sec_off, num_sections)
            off = rva2off(exp_rva)
            if off is None:
                return
            # IMAGE_EXPORT_DIRECTORY: NumberOfNames @0x18, AddressOfNames @0x20.
            num_names = struct.unpack("<I", data[off + 0x18 : off + 0x1C])[0]
            names_rva = struct.unpack("<I", data[off + 0x20 : off + 0x24])[0]
            names_off = rva2off(names_rva)
            if names_off is None:
                return
            for i in range(min(num_names, _MAX_SYMBOLS)):
                name_ptr = struct.unpack(
                    "<I", data[names_off + i * 4 : names_off + i * 4 + 4]
                )[0]
                noff = rva2off(name_ptr)
                if noff is None:
                    continue
                name = self._cstr(data, noff)
                if not name:
                    continue
                self._sym_id += 1
                symbols.append(
                    {
                        "symbol_id": self._sym_id,
                        "binary_id": bid,
                        "name": name,
                        "sym_kind": "export",
                        "binding": None,
                        "address": None,
                        "size": None,
                        "section": None,
                        "is_import": False,
                        "is_export": True,
                        "library": None,
                    }
                )
        except (struct.error, IndexError):
            return

    # ==================================================================
    # Mach-O
    # ==================================================================
    _MACHO_CPU = {
        7: "x86",
        0x01000007: "x86-64",
        12: "ARM",
        0x0100000C: "ARM64",
        18: "PowerPC",
        0x01000012: "PowerPC64",
    }
    _MACHO_FILETYPE = {
        1: "OBJECT",
        2: "EXECUTE",
        6: "DYLIB",
        7: "DYLINKER",
        8: "BUNDLE",
        9: "DYLIB_STUB",
        0xA: "DSYM",
    }

    def _parse_macho(self, bid, path, idx, sections, symbols, imports, properties):
        data = path.read_bytes()
        magic = data[:4]
        big = magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf")
        is64 = magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
        endian = ">" if big else "<"
        idx["binary_format"] = "Mach-O"
        idx["format_family"] = "executable"
        idx["bitness"] = 64 if is64 else 32
        idx["endianness"] = "big" if big else "little"

        cputype, cpusub, filetype, ncmds, sizeofcmds, flags = struct.unpack(
            endian + "iiIIII", data[4:28]
        )
        idx["architecture"] = self._MACHO_CPU.get(
            cputype & 0xFFFFFFFF, f"cpu-{cputype}"
        )
        idx["is_pic"] = bool(flags & 0x200000)  # MH_PIE
        idx["is_dynamic"] = filetype in (6, 8)
        self._prop(
            properties,
            bid,
            "macho",
            "filetype",
            self._MACHO_FILETYPE.get(filetype, str(filetype)),
        )
        self._prop(properties, bid, "macho", "flags", hex(flags))
        self._prop(properties, bid, "macho", "load_commands", str(ncmds))

        off = 32 if is64 else 28
        ordv = 0
        stripped = True
        for _ in range(min(ncmds, _MAX_SECTIONS)):
            if off + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack(endian + "II", data[off : off + 8])
            if cmdsize == 0:
                break
            # LC_SEGMENT(_64) = 0x1 / 0x19
            if cmd in (0x1, 0x19):
                is_seg64 = cmd == 0x19
                seg = data[off : off + cmdsize]
                segname = seg[8:24].rstrip(b"\x00").decode("latin-1", "replace")
                if is_seg64:
                    vmaddr, vmsize, fileoff, filesize = struct.unpack(
                        endian + "QQQQ", seg[24:56]
                    )
                    nsects = struct.unpack(endian + "I", seg[64:68])[0]
                else:
                    vmaddr, vmsize, fileoff, filesize = struct.unpack(
                        endian + "IIII", seg[24:40]
                    )
                    nsects = struct.unpack(endian + "I", seg[48:52])[0]
                self._sec_id += 1
                ordv += 1
                sections.append(
                    {
                        "section_id": self._sec_id,
                        "binary_id": bid,
                        "ordinal": ordv,
                        "name": segname,
                        "sec_type": "segment",
                        "virtual_address": vmaddr,
                        "file_offset": fileoff,
                        "size": filesize,
                        "flags": "",
                        "entropy": self._section_entropy(data, fileoff, filesize, 1),
                    }
                )
            elif cmd in (0xC, 0x8000001C, 0xD, 0xF, 0x18, 0x1F):  # LC_LOAD_DYLIB family
                dy = data[off : off + cmdsize]
                name_off = struct.unpack(endian + "I", dy[8:12])[0]
                lib = self._cstr(dy, name_off)
                if lib:
                    self._imp_id += 1
                    imports.append(
                        {
                            "import_id": self._imp_id,
                            "binary_id": bid,
                            "library": lib,
                            "symbol": None,
                            "kind": "load-dylib",
                        }
                    )
            elif cmd == 0x2:  # LC_SYMTAB present -> not fully stripped
                stripped = False
                self._macho_symtab(bid, data, endian, is64, off, symbols)
            off += cmdsize
        idx["is_stripped"] = stripped

    def _macho_symtab(self, bid, data, endian, is64, cmd_off, symbols):
        seg = data[cmd_off : cmd_off + 24]
        symoff, nsyms, stroff, strsize = struct.unpack(endian + "IIII", seg[8:24])
        strtab = data[stroff : stroff + strsize]
        entsize = 16 if is64 else 12
        for i in range(min(nsyms, _MAX_SYMBOLS)):
            base = symoff + i * entsize
            raw = data[base : base + entsize]
            if len(raw) < entsize:
                break
            if is64:
                n_strx, n_type, n_sect, n_desc, n_value = struct.unpack(
                    endian + "IBBHQ", raw
                )
            else:
                n_strx, n_type, n_sect, n_desc, n_value = struct.unpack(
                    endian + "IBBHI", raw
                )
            name = self._cstr(strtab, n_strx)
            if not name:
                continue
            is_ext = bool(n_type & 0x1)  # N_EXT
            is_undef = (n_type & 0xE) == 0  # N_UNDF
            self._sym_id += 1
            symbols.append(
                {
                    "symbol_id": self._sym_id,
                    "binary_id": bid,
                    "name": name,
                    "sym_kind": "ext" if is_ext else "local",
                    "binding": None,
                    "address": n_value,
                    "size": None,
                    "section": str(n_sect),
                    "is_import": bool(is_undef and is_ext),
                    "is_export": bool(is_ext and not is_undef),
                    "library": None,
                }
            )

    def _parse_macho_fat(self, bid, path, idx, sections, symbols, imports, properties):
        # Universal (fat) binary: record slices as properties; parse the first slice.
        data = path.read_bytes()
        nfat = struct.unpack(">I", data[4:8])[0]
        idx["binary_format"] = "Mach-O universal (fat)"
        idx["format_family"] = "executable"
        self._prop(properties, bid, "macho", "fat_slices", str(nfat))
        for i in range(min(nfat, 64)):
            base = 8 + i * 20
            raw = data[base : base + 20]
            if len(raw) < 20:
                break
            cputype, cpusub, offset, size, align = struct.unpack(">iiIII", raw)
            self._prop(
                properties,
                bid,
                "macho",
                f"slice{i}_arch",
                self._MACHO_CPU.get(cputype & 0xFFFFFFFF, f"cpu-{cputype}"),
            )

    # ==================================================================
    # Java .class
    # ==================================================================
    _JAVA_VERSION = {
        45: "1.1",
        46: "1.2",
        47: "1.3",
        48: "1.4",
        49: "5",
        50: "6",
        51: "7",
        52: "8",
        53: "9",
        54: "10",
        55: "11",
        56: "12",
        57: "13",
        58: "14",
        59: "15",
        60: "16",
        61: "17",
        62: "18",
        63: "19",
        64: "20",
        65: "21",
        66: "22",
        67: "23",
        68: "24",
    }

    def _parse_class(self, bid, path, idx, sections, symbols, imports, properties):
        data = path.read_bytes()
        if data[:4] != b"\xca\xfe\xba\xbe" or len(data) < 10:
            raise ValueError("not a Java class file")
        minor, major = struct.unpack(">HH", data[4:8])
        idx["binary_format"] = "Java class"
        idx["format_family"] = "bytecode"
        idx["architecture"] = "JVM"
        idx["bitness"] = None
        self._prop(properties, bid, "java", "major_version", str(major))
        self._prop(
            properties, bid, "java", "jdk", self._JAVA_VERSION.get(major, "unknown")
        )
        # Constant pool: count referenced classes as imports (best-effort walk).
        cp_count = struct.unpack(">H", data[8:10])[0]
        off = 10
        utf8: Dict[int, str] = {}
        class_refs: List[int] = []
        i = 1
        try:
            while i < cp_count and off < len(data):
                tag = data[off]
                off += 1
                if tag == 1:  # Utf8
                    ln = struct.unpack(">H", data[off : off + 2])[0]
                    off += 2
                    utf8[i] = data[off : off + ln].decode("utf-8", "replace")
                    off += ln
                elif tag in (
                    7,
                    8,
                    16,
                    19,
                    20,
                ):  # Class/String/MethodType/Module/Package (u2 index)
                    if tag == 7:
                        class_refs.append(struct.unpack(">H", data[off : off + 2])[0])
                    off += 2
                elif tag in (15,):  # MethodHandle (u1+u2)
                    off += 3
                elif tag in (
                    3,
                    4,
                    9,
                    10,
                    11,
                    12,
                    17,
                    18,
                ):  # int/float/refs/nameandtype/dynamic (u4)
                    off += 4
                elif tag in (5, 6):  # long/double take two slots
                    off += 8
                    i += 1
                else:
                    break
                i += 1
        except (struct.error, IndexError):
            pass
        seen = set()
        for ref in class_refs[:_MAX_IMPORTS]:
            cname = utf8.get(ref)
            if cname and cname not in seen:
                seen.add(cname)
                self._imp_id += 1
                imports.append(
                    {
                        "import_id": self._imp_id,
                        "binary_id": bid,
                        "library": cname.replace("/", "."),
                        "symbol": None,
                        "kind": "class-ref",
                    }
                )

    # ==================================================================
    # Python .pyc
    # ==================================================================
    # Final-release CPython pyc base magics (the u16 before "\r\n"). Kept as exact
    # release markers; anything unlisted falls back to matching the running
    # interpreter, then to the highest known release <= the file's magic.
    _PYC_MAGIC = {
        3394: "3.7",
        3413: "3.8",
        3425: "3.9",
        3439: "3.10",
        3495: "3.11",
        3531: "3.12",
        3571: "3.13",
        3621: "3.14",
    }

    def _pyc_version(self, magic: int) -> str:
        if magic in self._PYC_MAGIC:
            return self._PYC_MAGIC[magic]
        # Fall back to the interpreter that produced this run, if it matches.
        try:
            import importlib.util
            import sys as _sys

            if struct.unpack("<H", importlib.util.MAGIC_NUMBER[:2])[0] == magic:
                return f"{_sys.version_info.major}.{_sys.version_info.minor}"
        except Exception:  # noqa: BLE001
            pass
        known = [m for m in self._PYC_MAGIC if m <= magic]
        if known:
            return f"~{self._PYC_MAGIC[max(known)]}+"
        return "unknown"

    def _parse_pyc(self, bid, path, idx, sections, symbols, imports, properties):
        data = path.read_bytes()
        if len(data) < 16:
            raise ValueError("pyc truncated")
        magic = struct.unpack("<H", data[:2])[0]
        idx["binary_format"] = "Python bytecode (.pyc)"
        idx["format_family"] = "bytecode"
        idx["architecture"] = "CPython"
        self._prop(properties, bid, "pyc", "magic_number", str(magic))
        self._prop(properties, bid, "pyc", "python_version", self._pyc_version(magic))
        bit_field = struct.unpack("<I", data[4:8])[0]
        self._prop(properties, bid, "pyc", "hash_based", str(bool(bit_field & 0x1)))

    # ==================================================================
    # WebAssembly
    # ==================================================================
    _WASM_SECTIONS = {
        0: "custom",
        1: "type",
        2: "import",
        3: "function",
        4: "table",
        5: "memory",
        6: "global",
        7: "export",
        8: "start",
        9: "element",
        10: "code",
        11: "data",
        12: "datacount",
    }

    def _parse_wasm(self, bid, path, idx, sections, symbols, imports, properties):
        data = path.read_bytes()
        if data[:4] != b"\x00asm":
            raise ValueError("not wasm")
        version = struct.unpack("<I", data[4:8])[0]
        idx["binary_format"] = "WebAssembly"
        idx["format_family"] = "bytecode"
        idx["architecture"] = "WASM"
        self._prop(properties, bid, "wasm", "version", str(version))
        off = 8
        ordv = 0
        while off < len(data):
            sec_id = data[off]
            off += 1
            size, off = self._uleb(data, off)
            body_start = off
            self._sec_id += 1
            ordv += 1
            sections.append(
                {
                    "section_id": self._sec_id,
                    "binary_id": bid,
                    "ordinal": ordv,
                    "name": self._WASM_SECTIONS.get(sec_id, f"section-{sec_id}"),
                    "sec_type": "wasm-section",
                    "virtual_address": None,
                    "file_offset": body_start,
                    "size": size,
                    "flags": "",
                    "entropy": self._section_entropy(data, body_start, size, 1),
                }
            )
            if sec_id == 2:  # import section
                self._wasm_imports(bid, data, body_start, size, imports)
            off = body_start + size
            if size == 0 and sec_id == 0:
                break

    def _wasm_imports(self, bid, data, start, size, imports):
        off = start
        try:
            count, off = self._uleb(data, off)
            for _ in range(min(count, _MAX_IMPORTS)):
                mlen, off = self._uleb(data, off)
                module = data[off : off + mlen].decode("utf-8", "replace")
                off += mlen
                nlen, off = self._uleb(data, off)
                field = data[off : off + nlen].decode("utf-8", "replace")
                off += nlen
                kind = data[off]
                off += 1
                # skip the type descriptor (approximate: one uleb for most kinds)
                _, off = self._uleb(data, off)
                self._imp_id += 1
                imports.append(
                    {
                        "import_id": self._imp_id,
                        "binary_id": bid,
                        "library": module,
                        "symbol": field,
                        "kind": {0: "func", 1: "table", 2: "memory", 3: "global"}.get(
                            kind, "import"
                        ),
                    }
                )
        except (struct.error, IndexError):
            return

    # ==================================================================
    # Android DEX
    # ==================================================================
    def _parse_dex(self, bid, path, idx, sections, symbols, imports, properties):
        data = path.read_bytes()
        idx["binary_format"] = "Android DEX"
        idx["format_family"] = "bytecode"
        idx["architecture"] = "Dalvik"
        ver = data[4:7].decode("latin-1", "replace")
        self._prop(properties, bid, "dex", "version", ver)
        if len(data) >= 0x70:
            string_ids_size, string_ids_off = struct.unpack("<II", data[0x38:0x40])
            type_ids_size, type_ids_off = struct.unpack("<II", data[0x40:0x48])
            method_ids_size, method_ids_off = struct.unpack("<II", data[0x58:0x60])
            self._prop(properties, bid, "dex", "string_count", str(string_ids_size))
            self._prop(properties, bid, "dex", "type_count", str(type_ids_size))
            self._prop(properties, bid, "dex", "method_count", str(method_ids_size))

    # ==================================================================
    # ar static library
    # ==================================================================
    def _parse_ar(self, bid, path, idx, sections, symbols, imports, properties):
        data = path.read_bytes()
        idx["binary_format"] = "ar static library"
        idx["format_family"] = "static-library"
        off = 8
        ordv = 0
        while off + 60 <= len(data):
            header = data[off : off + 60]
            name = header[:16].rstrip().decode("latin-1", "replace")
            try:
                size = int(header[48:58].strip() or b"0")
            except ValueError:
                break
            if header[58:60] != b"`\n":
                break
            ordv += 1
            self._sec_id += 1
            sections.append(
                {
                    "section_id": self._sec_id,
                    "binary_id": bid,
                    "ordinal": ordv,
                    "name": name,
                    "sec_type": "ar-member",
                    "virtual_address": None,
                    "file_offset": off + 60,
                    "size": size,
                    "flags": "",
                    "entropy": None,
                }
            )
            off += 60 + size + (size & 1)
        self._prop(properties, bid, "ar", "member_count", str(ordv))

    # ==================================================================
    # LLVM bitcode / UF2 / OLE / hex records (light structural summaries)
    # ==================================================================
    def _parse_llvm_bitcode(
        self, bid, path, idx, sections, symbols, imports, properties
    ):
        idx["binary_format"] = "LLVM bitcode"
        idx["format_family"] = "bytecode"
        idx["architecture"] = "LLVM IR"
        head = path.read_bytes()[:4]
        self._prop(properties, bid, "llvm", "wrapper", str(head == b"\xde\xc0\x17\x0b"))

    def _parse_uf2(self, bid, path, idx, sections, symbols, imports, properties):
        data = path.read_bytes()
        idx["binary_format"] = "UF2 firmware"
        idx["format_family"] = "firmware"
        nblocks = len(data) // 512
        self._prop(properties, bid, "uf2", "block_count", str(nblocks))
        if len(data) >= 32:
            flags, target_addr, payload_size, block_no, num_blocks, family = (
                struct.unpack("<IIIIII", data[8:32])
            )
            self._prop(properties, bid, "uf2", "target_address", hex(target_addr))
            self._prop(properties, bid, "uf2", "num_blocks", str(num_blocks))
            self._prop(properties, bid, "uf2", "family_id", hex(family))

    def _parse_ole(self, bid, path, idx, sections, symbols, imports, properties):
        data = path.read_bytes()
        idx["binary_format"] = "OLE compound file (MSI/OLE)"
        idx["format_family"] = "container"
        if len(data) >= 32:
            sector_shift = struct.unpack("<H", data[30:32])[0]
            self._prop(properties, bid, "ole", "sector_size", str(1 << sector_shift))
        # Note technical structure only; never enumerate document streams' contents.
        self._prop(
            properties, bid, "ole", "note", "structure only; no stream payload read"
        )

    def _parse_hexrec(self, bid, path, idx, sections, symbols, imports, properties):
        # Intel HEX / Motorola S-record: ASCII firmware image. Count records only.
        idx["binary_format"] = "Intel HEX / S-record"
        idx["format_family"] = "firmware"
        idx["endianness"] = "big"
        try:
            lines = path.read_text(encoding="latin-1").splitlines()
        except OSError:
            return
        rec = sum(1 for ln in lines if ln[:1] in (":", "S"))
        self._prop(properties, bid, "hexrec", "record_count", str(rec))

    # ==================================================================
    # Helpers
    # ==================================================================
    def _prop(self, properties, bid, group, name, value):
        self._prop_id += 1
        properties.append(
            {
                "property_id": self._prop_id,
                "binary_id": bid,
                "prop_group": group,
                "prop_name": name,
                "prop_value": str(value),
            }
        )

    @staticmethod
    def _cstr(buf: bytes, off: int) -> str:
        if off is None or off < 0 or off >= len(buf):
            return ""
        end = buf.find(b"\x00", off)
        if end < 0:
            end = len(buf)
        return buf[off:end].decode("utf-8", "replace")

    @staticmethod
    def _uleb(data: bytes, off: int) -> Tuple[int, int]:
        result = 0
        shift = 0
        while off < len(data):
            b = data[off]
            off += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        return result, off

    @staticmethod
    def _section_entropy(data: bytes, offset, size, sec_type) -> Optional[float]:
        # NOBITS / zero-size / out-of-range: no measurable payload.
        if not offset or not size or sec_type == 8:
            return None
        if offset < 0 or offset >= len(data):
            return None
        window = data[offset : offset + min(size, _SECTION_ENTROPY_CAP)]
        if not window:
            return None
        counts = [0] * 256
        for b in window:
            counts[b] += 1
        import math

        n = len(window)
        ent = 0.0
        for c in counts:
            if c:
                px = c / n
                ent -= px * math.log2(px)
        return round(ent, 4)

    def _min_index_row(self, bid, row, error=None):
        return {
            "binary_id": bid,
            "file_id": row.get("file_id"),
            "file_name": Path(row.get("file_location", "")).name,
            "binary_format": None,
            "format_family": None,
            "category": None,
            "subcategory": None,
            "architecture": None,
            "bitness": None,
            "endianness": None,
            "entry_point": None,
            "is_stripped": None,
            "is_dynamic": None,
            "is_pic": None,
            "section_count": 0,
            "symbol_count": 0,
            "import_count": 0,
            "export_count": 0,
            "sha256": None,
            "size": None,
            "entropy": None,
            "detected_via": None,
            "notes": None,
            "error": error,
        }
