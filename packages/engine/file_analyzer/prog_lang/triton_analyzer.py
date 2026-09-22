# Triton (.triton) analyzer.
#
# OpenAI Triton kernels are ordinary Python using the `triton` framework; the
# file grammar is Python (AST-parsed by the shared base).  Domain constructs:
#
#     import triton
#     import triton.language as tl                       -> import
#     @triton.jit                                        -> function (GPU kernel)
#     def add_kernel(x_ptr, y_ptr, out_ptr, n, BLOCK: tl.constexpr):
#         pid = tl.program_id(0)
#         ...
#     @triton.autotune(configs=[...], key=["n"])         -> function (tuned kernel)
#     @triton.jit
#     def matmul_kernel(...): ...
#     def add(x, y):                                      -> function (host wrapper)
#         add_kernel[grid](x, y, out, n, BLOCK=1024)
#
# @triton.jit / @triton.autotune / @triton.heuristics decorated functions are
# GPU kernels (the domain entry point); they are tagged in addition to the
# full Python pass.
from .python_embedded_base import PythonEmbeddedAnalyzer


class TritonAnalyzer(PythonEmbeddedAnalyzer):
    LANG_KEY = "triton"
    EXTENSIONS = (".triton",)
    DSL_DECORATORS = (
        "triton.jit",
        "jit",
        "triton.autotune",
        "autotune",
        "triton.heuristics",
        "heuristics",
        "triton.language.jit",
    )
