# Cedar (.cedar) analyzer -- AWS's authorization-policy language.
#
# A Cedar file is a sequence of ``;``-terminated policies, optionally annotated:
#
#     @id("view-photos")                         -> (annotation, names the policy)
#     permit (principal, action, resource)       -> function (policy)
#       when { resource.owner == principal }
#       unless { resource.private };
#     forbid (principal, action, resource);      -> function (policy)
#
# Unannotated policies are named ``permit_N`` / ``forbid_N`` by order.  Entity
# and action paths referenced in the scope are surfaced as variables.  Comments
# are '//'; strings use '"'.
import re

from .regex_base import RegexCodeAnalyzer


class CedarAnalyzer(RegexCodeAnalyzer):
    LANG_KEY = "cedar"
    EXTENSIONS = (".cedar",)
    LINE_COMMENTS = ("//",)
    BLOCK_COMMENTS = ()
    STRING_DELIMS = ('"',)

    _EFFECT = re.compile(r"\b(permit|forbid)\s*\(")
    _ANNOT = re.compile(r'@([A-Za-z_]\w*)\s*\(\s*"([^"]*)"\s*\)')
    _ENTITY = re.compile(r"\b([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\s*::\s*\"")

    def _extract_entities(self, file_id, text, path):
        clean = self._strip_comments(text)

        counters = {"permit": 0, "forbid": 0}
        for chunk in self._split_top_level(clean, sep=";"):
            eff = self._EFFECT.search(chunk)
            if not eff:
                continue
            effect = eff.group(1)
            counters[effect] += 1
            am = self._ANNOT.search(chunk[: eff.start()])
            # prefer an @id annotation; else the first annotation value; else ordinal
            name = None
            ids = [
                (m.group(1), m.group(2))
                for m in self._ANNOT.finditer(chunk[: eff.start()])
            ]
            for key, val in ids:
                if key == "id":
                    name = val
                    break
            if name is None and ids:
                name = ids[0][1]
            if name is None:
                name = f"{effect}_{counters[effect]}"
            self._add_function(
                file_id, name, [], [], description=f"cedar {effect} policy"
            )
            # entity-type literals referenced in the policy scope
            seen = set()
            for em in self._ENTITY.finditer(chunk):
                et = em.group(1)
                if et not in seen:
                    seen.add(et)
                    self._add_variable(file_id, et, scope="entity")
