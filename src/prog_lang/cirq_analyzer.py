# Cirq (.cirq) analyzer.
#
# Cirq programs are ordinary Python using Google's Cirq framework, so the file
# grammar is Python (parsed via AST by the shared base).  Domain constructs:
#
#     import cirq                                       -> import
#     q0, q1 = cirq.LineQubit.range(2)                  -> variable
#     class MyGate(cirq.Gate):                          -> class (custom gate)
#         def _num_qubits_(self): return 1              -> method
#     def make_bell(q0, q1):                            -> function
#         return cirq.Circuit([cirq.H(q0), cirq.CNOT(q0, q1)])
#     circuit = cirq.Circuit(...)                       -> variable (+ dsl tag)
#     simulator = cirq.Simulator()                      -> variable (+ dsl tag)
#
# Custom gates/operations subclass cirq.Gate/Operation/Device; circuit- and
# simulator-construction sites are tagged as domain entry points.
import ast
from .python_embedded_base import PythonEmbeddedAnalyzer


class CirqAnalyzer(PythonEmbeddedAnalyzer):
    LANG_KEY = "cirq"
    EXTENSIONS = (".cirq",)
    DSL_BASECLASSES = ("Gate", "cirq.Gate", "TwoQubitGate", "SingleQubitGate",
                       "Operation", "cirq.Operation", "Device", "cirq.Device",
                       "EigenGate", "cirq.EigenGate", "ArithmeticGate",
                       "Qid", "cirq.Qid")
    # constructor heads that mark a Cirq circuit / execution entry point
    _CTORS = {"Circuit", "Simulator", "DensityMatrixSimulator", "Moment",
              "LineQubit", "GridQubit", "NamedQubit", "PauliString"}

    def _dsl_enrich(self, file_id, tree, code_text):
        super()._dsl_enrich(file_id, tree, code_text)   # gate/op subclasses
        seen = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            head = self._decorator_root(node)            # dotted callee name
            leaf = head.split(".")[-1]
            if leaf not in self._CTORS:
                continue
            # accept cirq.Circuit(...) (attribute rooted in cirq) or a bare
            # Circuit(...) call from `from cirq import Circuit`
            if head in seen:
                continue
            if head.startswith("cirq.") or head == leaf:
                seen.add(head)
                self._dsl_tag(file_id, leaf, "circuit-build:" + head)
