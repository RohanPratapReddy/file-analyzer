# HTCondor DAGMan workflow (.dag).
#
# A DAGMan input file declares a directed-acyclic graph of HTCondor jobs:
#
#     JOB  A  a.sub
#     JOB  B  b.sub  DIR  runB
#     SUBDAG EXTERNAL  D  inner.dag
#     PARENT A CHILD B C
#     SCRIPT PRE  A  prep.sh  $JOB
#     SCRIPT POST B  clean.sh
#     VARS A  dataset="set1"  seed="42"
#     RETRY A 3
#     INCLUDE common.inc
#
#   JOB name submit_file            -> function (a node) + submit_file -> import
#   FINAL / PROVISIONER name file   -> function (a node) + file        -> import
#   SUBDAG EXTERNAL name file       -> function (a node) + file        -> import
#   SPLICE name dagfile             -> function (a spliced-in graph)   + file -> import
#   SCRIPT PRE|POST name script     -> the script file                -> import
#   VARS name key="val" ...         -> variables (key = val)
#   INCLUDE file                    -> import
#
# `#` starts a comment; PARENT/CHILD edges carry no new symbol and are skipped.
import re

from .regex_base import RegexCodeAnalyzer

_NM = r"[A-Za-z0-9_.\-+]+"


class DagmanAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "dagman"
    EXTENSIONS = (".dag",)
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    # JOB / FINAL / PROVISIONER all take `<keyword> name submit_file`.
    _JOB = re.compile(r"(?mi)^\s*(?:JOB|FINAL|PROVISIONER)\s+(" + _NM + r")\s+(\S+)")
    _SUBDAG = re.compile(r"(?mi)^\s*SUBDAG\s+EXTERNAL\s+(" + _NM + r")\s+(\S+)")
    # SPLICE name dagfile  (splices another DAG's nodes in-line)
    _SPLICE = re.compile(r"(?mi)^\s*SPLICE\s+(" + _NM + r")\s+(\S+)")
    _SCRIPT = re.compile(
        r"(?mi)^\s*SCRIPT\s+(?:DEFER\s+\d+\s+\d+\s+)?"
        r"(?:PRE|POST|HOLD)\s+(" + _NM + r")\s+(\S+)"
    )
    _VARS = re.compile(r"(?mi)^\s*VARS\s+(" + _NM + r")\s+(.+)$")
    _VARKV = re.compile(r"(" + _NM + r')\s*=\s*"([^"]*)"')
    _INCLUDE = re.compile(r"(?mi)^\s*INCLUDE\s+(\S+)")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        seen_fn = set()
        for m in self._JOB.finditer(clean):
            nm, sub = m.group(1), m.group(2)
            if nm not in seen_fn:
                seen_fn.add(nm)
                self._add_function(file_id, nm, [], [], description="DAG job node")
            self._add_import(file_id, sub.split("/")[-1], sub)
        for m in self._SUBDAG.finditer(clean):
            nm, sub = m.group(1), m.group(2)
            if nm not in seen_fn:
                seen_fn.add(nm)
                self._add_function(file_id, nm, [], [], description="DAG sub-dag node")
            self._add_import(file_id, sub.split("/")[-1], sub)
        for m in self._SPLICE.finditer(clean):
            nm, sub = m.group(1), m.group(2)
            if nm not in seen_fn:
                seen_fn.add(nm)
                self._add_function(file_id, nm, [], [], description="DAG spliced graph")
            self._add_import(file_id, sub.split("/")[-1], sub)

        for m in self._SCRIPT.finditer(clean):
            scr = m.group(2)
            self._add_import(file_id, scr.split("/")[-1], scr)
        for m in self._INCLUDE.finditer(clean):
            inc = m.group(1)
            self._add_import(file_id, inc.split("/")[-1], inc)

        for m in self._VARS.finditer(clean):
            node = m.group(1)
            for kv in self._VARKV.finditer(m.group(2)):
                self._add_variable(
                    file_id, f"{node}.{kv.group(1)}", kv.group(2), scope="node"
                )
