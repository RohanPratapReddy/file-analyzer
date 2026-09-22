# Compiled / encoded script artifacts.  These are NOT human-readable source:
# they are compiled bytecode (AppleScript .scpt/.scptd), binary action/macro
# containers (Photoshop .atn, generic .macro, WordPerfect .wpm, Excel 4 .xlm) or
# deliberately obfuscated text (Microsoft Script Encoder .jse/.vbe).
#
# There is no honest way to reconstruct functions/variables from an opaque
# binary, so this analyzer does NOT fabricate symbol rows.  It performs a real
# byte-level inspection (magic bytes, size, entropy, encoding markers, embedded
# printable strings) and records the findings as module-level introspection
# metadata ONLY.  This keeps the promise of "real implementation, no stubs":
# what can be known from the bytes is reported; what cannot is not invented.
import hashlib
import math
import re
from collections import Counter

from .shell_base import ShellScriptBase


class CompiledScriptAnalyzer(ShellScriptBase):
    """Byte-level metadata reader for compiled / encoded script artifacts."""

    LANG_KEY = "compiled-script"
    EXTENSIONS = (".scpt", ".scptd", ".atn", ".jse", ".vbe", ".macro", ".wpm", ".xlm")
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ()

    # Known signatures, matched at the start of the payload.
    _MAGIC = (
        (b"FasdUAS", "applescript-compiled"),  # compiled AppleScript
        (b"bplist00", "binary-plist"),  # scpt sometimes wraps a bplist
        (b"8BPS", "photoshop"),  # Photoshop resource
        (b"\x00\x00\x00", "binary-container"),
        (b"PK\x03\x04", "zip-bundle"),  # .scptd bundles / zipped macros
        (b"\xd0\xcf\x11\xe0", "ole2-compound"),  # OLE2 (legacy Office macro)
        (b"<?xml", "xml-macro"),  # some .xlm are XML
    )
    # Microsoft Script Encoder marker (present in .jse / .vbe and encoded blocks).
    _ENC_MARKER = b"#@~^"
    _PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")

    def _extract_entities(self, file_id, text, path):
        # Ignore the (lossy) decoded `text`; work from the raw bytes.
        try:
            raw = path.read_bytes()
        except (OSError, IsADirectoryError):
            # .scptd is a bundle directory; record that honestly.
            self._record_module_meta(
                file_id,
                artifact="bundle-directory",
                format=path.suffix.lower().lstrip("."),
                readable=False,
            )
            return

        size = len(raw)
        head = raw[:16]
        magic_hex = head[:8].hex()

        fmt = None
        for sig, label in self._MAGIC:
            if raw.startswith(sig):
                fmt = label
                break

        is_encoded = self._ENC_MARKER in raw[:4096]
        # Count embedded printable ASCII runs -- a cheap "how much is text" gauge.
        strings = self._PRINTABLE.findall(raw)
        printable_bytes = sum(len(s) for s in strings)
        text_ratio = round(printable_bytes / size, 3) if size else 0.0

        self._record_module_meta(
            file_id,
            artifact="compiled-or-encoded-script",
            format=path.suffix.lower().lstrip("."),
            detected_format=fmt,
            byte_size=size,
            sha256=hashlib.sha256(raw).hexdigest(),
            magic_bytes=magic_hex,
            entropy=self._entropy(raw),
            is_script_encoder_payload=is_encoded,
            printable_string_count=len(strings),
            printable_ratio=text_ratio,
            symbols_extracted=False,  # honest: opaque payload, none invented
        )

    @staticmethod
    def _entropy(data: bytes) -> float:
        """Shannon entropy (bits/byte, 0..8) -- a real measure of how compressed
        or encrypted the payload is."""
        if not data:
            return 0.0
        counts = Counter(data)
        n = len(data)
        return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 3)
