# PennyLane (.pennylane) analyzer.
#
# PennyLane programs are ordinary Python using Xanadu's PennyLane framework; the
# file grammar is Python (AST-parsed by the shared base).  Domain constructs:
#
#     import pennylane as qml                           -> import
#     dev = qml.device("default.qubit", wires=2)        -> variable (+ dsl tag)
#     @qml.qnode(dev)                                    -> function (QNode)
#     def circuit(theta):
#         qml.RX(theta, wires=0)
#         qml.CNOT(wires=[0, 1])
#         return qml.expval(qml.PauliZ(0))
#     class MyTemplate(Operation): ...                   -> class (custom op)
#
# The @qml.qnode / @qnode decorator marks a quantum node (the framework's core
# entry point); qml.device(...) marks a device.  Both are tagged.
import ast

from .python_embedded_base import PythonEmbeddedAnalyzer


class PennyLaneAnalyzer(PythonEmbeddedAnalyzer):
    LANG_KEY = "pennylane"
    EXTENSIONS = (".pennylane",)
    DSL_DECORATORS = (
        "qml.qnode",
        "qnode",
        "pennylane.qnode",
        "qml.qjit",
        "qjit",
        "qml.transform",
        "transform",
    )
    DSL_BASECLASSES = (
        "Operation",
        "qml.Operation",
        "Observable",
        "qml.Observable",
        "Channel",
        "Operator",
        "qml.operation.Operation",
    )

    def _dsl_enrich(self, file_id, tree, code_text):
        super()._dsl_enrich(file_id, tree, code_text)  # qnode decorators + ops
        seen = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            head = self._decorator_root(node)
            if head in ("qml.device", "pennylane.device") and head not in seen:
                seen.add(head)
                self._dsl_tag(file_id, "device", "device:" + head)
