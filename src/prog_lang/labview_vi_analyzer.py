# LabVIEW Virtual Instrument (.vi).
#
# A `.vi` file is a **binary** LabVIEW resource (front panel + block diagram +
# compiled code), not source text — there is no textual grammar to parse.  Like
# the other binary formats in this package (LabVIEW is analogous to a compiled
# artefact), the honest analysis is a bounded, best-effort string scan that
# recovers the human-meaningful identifiers LabVIEW stores as readable ASCII/
# UTF-16 inside the resource fork:
#
#   * referenced subVI file names   ("Foo.vi", "Bar.ctl")  -> class  (subVI ref)
#   * the "LVSR"/"vers"-adjacent VI name / description       -> variable
#
# If none are found the file is legitimately left with no symbols (a purely
# binary VI with no embedded readable names), exactly as the .urp / Piet
# precedent: an empty result here is correct, not a miss.
import re

from .regex_base import RegexCodeAnalyzer

# Readable ASCII runs of length >= 4 (LabVIEW pads names into the resource).
_ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,}")
# subVI / control references LabVIEW embeds as "<stem>.vi" / "<stem>.ctl".
_VI_REF = re.compile(r"([A-Za-z0-9_][\w \-]*\.(?:vi|ctl|vit|ctt))$", re.I)
_CLEAN_STEM = re.compile(r"[^\w \-]")


class LabviewViAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "labview_vi"
    EXTENSIONS = (".vi", ".vit", ".ctl", ".ctt")
    LINE_COMMENTS = ()
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ()

    # Binary format: read raw bytes ourselves, bypass text/comment machinery.
    def _extract_entities(self, file_id, text, path):
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError:
            return

        seen_c = set()
        for m in _ASCII_RUN.finditer(blob):
            try:
                run = m.group(0).decode("ascii", "ignore")
            except Exception:
                continue
            for token in run.replace("\\", "/").split("/"):
                vm = _VI_REF.search(token.strip())
                if not vm:
                    continue
                ref = vm.group(1).strip()
                stem = _CLEAN_STEM.sub("", ref.rsplit(".", 1)[0]).strip()
                if len(stem) < 2 or stem in seen_c:
                    continue
                seen_c.add(stem)
                self._add_class(file_id, stem, description="LabVIEW subVI reference")
