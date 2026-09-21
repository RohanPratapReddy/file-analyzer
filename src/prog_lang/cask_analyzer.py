# Homebrew Cask (.cask / cask `.rb`).
#
# A Cask is a Ruby DSL describing a macOS application to install:
#
#     cask "google-chrome" do
#       version "120.0"
#       sha256 "abc123..."
#       url "https://dl.example.com/chrome-#{version}.dmg"
#       name "Google Chrome"
#       desc "Web browser"
#       homepage "https://www.google.com/chrome/"
#       depends_on macos: ">= :big_sur"
#       app "Google Chrome.app"
#       postflight do
#         system_command "/usr/bin/..."
#       end
#       zap trash: "~/Library/Caches/Google/Chrome"
#     end
#
#   cask "name" do                     -> class (the cask)
#   version/sha256/url/name/desc/      -> variables (stanza -> value)
#     homepage/app/pkg/binary/... "v"
#   depends_on cask:/formula: "x"      -> import (a dependency)
#   preflight/postflight/uninstall/    -> function (lifecycle block)
#     zap  do ... end
#
# Ruby `#` line comments; single- and double-quoted strings.
import re

from .regex_base import RegexCodeAnalyzer

_STANZAS = (
    "version",
    "sha256",
    "url",
    "name",
    "desc",
    "homepage",
    "app",
    "pkg",
    "binary",
    "manpage",
    "colorpicker",
    "dictionary",
    "font",
    "input_method",
    "internet_plugin",
    "prefpane",
    "qlplugin",
    "screen_saver",
    "service",
    "suite",
    "artifact",
    "installer",
    "container",
    "appcast",
    "auto_updates",
    "arch",
    "os",
    "livecheck",
    "language",
)
_BLOCKS = (
    "preflight",
    "postflight",
    "uninstall_preflight",
    "uninstall_postflight",
    "uninstall",
    "zap",
    "caveats",
)


class CaskAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "cask"
    EXTENSIONS = (".cask",)  # Homebrew casks ship as `.rb`; appended at test time
    LINE_COMMENTS = ("#",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"', "'")

    _CASK = re.compile(r'(?m)^\s*cask\s+["\']([^"\']+)["\']\s+do')
    _STANZA = re.compile(r"(?m)^\s*(" + "|".join(_STANZAS) + r')\s+["\']([^"\']*)["\']')
    _VERSION_BARE = re.compile(r"(?m)^\s*version\s+(:\w+)")
    _DEPENDS = re.compile(
        r"(?m)^\s*depends_on\s+(cask|formula|macos|arch):" r'\s*["\']?([^"\'\n,]+)'
    )
    _BLOCK = re.compile(r"(?m)^\s*(" + "|".join(_BLOCKS) + r")\s+do\b")
    # zap/uninstall also take a directive-hash form: `zap trash: "..."`
    _CLEANUP = re.compile(
        r"(?m)^\s*(zap|uninstall|uninstall_preflight|"
        r"uninstall_postflight)\s+[a-z_]+:"
    )

    def _register_types(self, file_id, text, path):
        clean = self._strip_comments(text)
        for m in self._CASK.finditer(clean):
            self._register_class(m.group(1))

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        for m in self._CASK.finditer(clean):
            self._add_class(file_id, m.group(1), description="Homebrew cask")

        for m in self._DEPENDS.finditer(clean):
            kind, dep = m.group(1), m.group(2).strip()
            if kind in ("cask", "formula"):
                self._add_import(file_id, dep.split("/")[-1], dep)

        seen_v = set()
        for m in self._STANZA.finditer(clean):
            nm = m.group(1)
            if nm in seen_v:
                continue
            seen_v.add(nm)
            self._add_variable(file_id, nm, m.group(2)[:100], scope="stanza")
        for m in self._VERSION_BARE.finditer(clean):
            if "version" not in seen_v:
                seen_v.add("version")
                self._add_variable(file_id, "version", m.group(1), scope="stanza")

        seen_fn = set()
        for m in self._BLOCK.finditer(clean):
            nm = m.group(1)
            if nm in seen_fn:
                continue
            seen_fn.add(nm)
            self._add_function(file_id, nm, [], [], description="cask lifecycle block")
        for m in self._CLEANUP.finditer(clean):
            nm = m.group(1)
            if nm in seen_fn:
                continue
            seen_fn.add(nm)
            self._add_function(
                file_id, nm, [], [], description="cask cleanup directive"
            )
