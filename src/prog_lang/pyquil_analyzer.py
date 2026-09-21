# pyQuil (.pyquil) analyzer.
#
# pyQuil programs are ordinary Python using Rigetti's pyQuil framework; the file
# grammar is Python (AST-parsed by the shared base).  Domain constructs:
#
#     from pyquil import Program, get_qc                -> import
#     from pyquil.gates import H, CNOT, MEASURE         -> import
#     p = Program()                                     -> variable (+ dsl tag)
#     p += H(0)                                          -> (augmented op)
#     qc = get_qc("2q-qvm")                              -> variable (+ dsl tag)
#     def bell():                                        -> function
#         p = Program(H(0), CNOT(0, 1))
#         return p
#     class MyRoutine(AbstractCompiler): ...             -> class
#
# Program(...) construction and get_qc(...)/QuantumComputer connections are the
# domain entry points; they are tagged in addition to the full Python pass.
import ast

from .python_embedded_base import PythonEmbeddedAnalyzer


class PyQuilAnalyzer(PythonEmbeddedAnalyzer):
    LANG_KEY = "pyquil"
    EXTENSIONS = (".pyquil",)
    DSL_BASECLASSES = (
        "AbstractCompiler",
        "pyquil.AbstractCompiler",
        "AbstractGate",
        "Gate",
        "QuantumComputer",
    )
    _CTORS = {
        "Program",
        "get_qc",
        "QuantumComputer",
        "QubitPlaceholder",
        "Pragma",
        "DefGate",
        "DefPermutationGate",
    }

    def _dsl_enrich(self, file_id, tree, code_text):
        super()._dsl_enrich(file_id, tree, code_text)
        seen = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            head = self._decorator_root(node)
            leaf = head.split(".")[-1]
            if leaf in self._CTORS and head not in seen:
                seen.add(head)
                self._dsl_tag(file_id, leaf, "program-build:" + head)
