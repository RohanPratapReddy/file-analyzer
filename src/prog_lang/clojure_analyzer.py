# Clojure (.clj), ClojureScript (.cljs), reader-conditional (.cljc) analyzer.
#
# Real parser for Clojure s-expressions (`;` line comments, no block comments):
#   (ns my.app (:require [clojure.set :as set]))  -> namespace + imports
#   (require '[clojure.string :as str])            -> import
#   (import java.util.Date)                         -> import
#   (def pi 3.14)                                   -> variable
#   (defn area [r] (* pi r r))                       -> function
#   (defn- helper [x] ...)                           -> function (private)
#   (defrecord Point [x y])                          -> record (class row, fields)
#   (defprotocol Shape (area [this]))                -> protocol (class row)
import re
from pathlib import Path
from .regex_base import RegexCodeAnalyzer


class ClojureAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "clojure"
    EXTENSIONS = (".clj", ".cljc", ".cljs")
    LINE_COMMENTS = (";",)
    BLOCK_COMMENTS = ()

    _NS = re.compile(r"\(ns\s+([\w.\-]+)")
    _REQUIRE = re.compile(r"\[\s*([\w.\-]+)(?:\s+:as\s+([\w.\-]+))?")
    _IMPORT = re.compile(r"\(import\s+(?:'?\(?)([\w.$\s]+)\)?")
    _DEF = re.compile(r"\(def\s+([\w.\-!?*+<>=/]+)")
    _DEFN = re.compile(r"\(defn-?\s+([\w.\-!?*+<>=/]+)\s*(?:\"[^\"]*\")?\s*\[([^\]]*)\]")
    _RECORD = re.compile(r"\(def(?:record|type)\s+([\w.\-]+)\s*\[([^\]]*)\]")
    _PROTOCOL = re.compile(r"\(defprotocol\s+([\w.\-]+)")

    def _register_types(self, file_id, text, path):
        t = self._strip_comments(text)
        for m in self._RECORD.finditer(t):
            self._register_class(m.group(1))
        for m in self._PROTOCOL.finditer(t):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        t = self._strip_comments(text)

        for m in self._NS.finditer(t):
            self._add_class(file_id, m.group(1), description="clojure namespace")

        # :require / require vectors anywhere in the file.
        seen_imp = set()
        for rm in re.finditer(r"\(:?require\b(.*?)\)", t, re.DOTALL):
            for m in self._REQUIRE.finditer(rm.group(1)):
                mod = m.group(1)
                if mod not in seen_imp:
                    seen_imp.add(mod)
                    self._add_import(file_id, mod.split(".")[-1], mod,
                                     alias=m.group(2))
        for m in self._IMPORT.finditer(t):
            for cls in m.group(1).split():
                cls = cls.strip()
                if cls and cls not in seen_imp:
                    seen_imp.add(cls)
                    self._add_import(file_id, cls.split(".")[-1], cls)

        for m in self._RECORD.finditer(t):
            attr_ids = [self._add_arg(f) for f in m.group(2).split() if f]
            self._add_class(file_id, m.group(1), description="clojure record",
                            attr_ids=attr_ids)
        for m in self._PROTOCOL.finditer(t):
            self._add_class(file_id, m.group(1), description="clojure protocol")

        fn_names = set()
        for m in self._DEFN.finditer(t):
            name = m.group(1)
            fn_names.add(name)
            arg_ids = [self._add_arg(a) for a in m.group(2).split()
                       if a and a not in ("&",)]
            self._add_function(file_id, name, arg_ids,
                               description="clojure function")
        for m in self._DEF.finditer(t):
            name = m.group(1)
            if name not in fn_names:
                self._add_variable(file_id, name)
