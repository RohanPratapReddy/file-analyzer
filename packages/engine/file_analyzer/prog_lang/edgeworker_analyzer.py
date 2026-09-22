# Akamai EdgeWorkers (.edgeworker).
#
# An EdgeWorker is an ECMAScript module that runs at the CDN edge: it `import`s
# from the `http-request`/`http-response`/`create-response`/`log` EdgeWorker
# namespaces and `export`s the event-handler functions `onClientRequest`,
# `onOriginRequest`, `onOriginResponse`, `onClientResponse` and `responseProvider`,
# alongside ordinary functions/classes/consts.  The syntax is JavaScript, so the
# honest analyzer is the tree-sitter JS engine keyed to the `.edgeworker`
# extension; the inherited extraction captures every import / handler function /
# class / variable a real EdgeWorker contains.
from .javascript_analyzer import JavaScriptAnalyzer


class EdgeWorkerAnalyzer(JavaScriptAnalyzer):
    def __init__(self, **kwargs):
        # grammar stays the JavaScript tree-sitter parser; only the recorded
        # language name and on-disk extension change.
        super().__init__(lang_key="javascript", extensions=[".edgeworker"], **kwargs)
        self.language_name = "edgeworker"
        self.introspection_source = (
            "Akamai EdgeWorker ES-module (import http-request/http-response/log, "
            "export onClientRequest/onOriginRequest/onOriginResponse/"
            "onClientResponse/responseProvider handlers)"
        )
