# Auto-extracted from code_analyzer.py (verbatim class body).
from pathlib import Path
from typing import Any, Dict, List, Union

from .abap_analyzer import AbapAnalyzer
from .actionscript_analyzer import ActionScriptAnalyzer
from .ada_analyzer import AdaAnalyzer
from .afl_analyzer import AFLAnalyzer
from .agda_analyzer import AgdaAnalyzer
from .al_analyzer import ALAnalyzer
from .alembic_analyzer import AlembicAnalyzer
from .algol_analyzer import AlgolAnalyzer
from .ampl_analyzer import AMPLAnalyzer
from .apache_beam_analyzer import ApacheBeamAnalyzer

# ---- Batch 10 ----
from .apl_analyzer import AplAnalyzer
from .asl_analyzer import AslAnalyzer
from .aspnet_ashx_analyzer import AspNetAshxAnalyzer
from .aspnet_asmx_analyzer import AspNetAsmxAnalyzer
from .astro_analyzer import AstroAnalyzer
from .ballerina_analyzer import BallerinaAnalyzer
from .base_code_analyzer import BaseCodeAnalyzer
from .befunge_analyzer import BefungeAnalyzer
from .bicep_analyzer import BicepAnalyzer
from .blackbird_analyzer import BlackbirdAnalyzer
from .bloqade_analyzer import BloqadeAnalyzer
from .bluespec_analyzer import BluespecAnalyzer
from .bms_analyzer import BmsAnalyzer
from .boo_analyzer import BooAnalyzer
from .brainfuck_analyzer import BrainfuckAnalyzer
from .c_analyzer import CAnalyzer, CppAnalyzer
from .cairo_analyzer import CairoAnalyzer
from .carbon_analyzer import CarbonAnalyzer
from .cask_analyzer import CaskAnalyzer
from .cdk_analyzer import CdkAnalyzer
from .cedar_analyzer import CedarAnalyzer
from .ceylon_analyzer import CeylonAnalyzer
from .chapel_analyzer import ChapelAnalyzer
from .chisel_analyzer import ChiselAnalyzer

# ---- Batch 18 (Python-embedded quantum & orchestration DSLs) ----
from .cirq_analyzer import CirqAnalyzer
from .clarity_analyzer import ClarityAnalyzer
from .clojure_analyzer import ClojureAnalyzer
from .cobol_analyzer import CobolAnalyzer
from .coffeescript_analyzer import CoffeeScriptAnalyzer
from .coldfusion_analyzer import ColdFusionAnalyzer

# ---- Batch 15 ----
from .cppmodule_analyzer import CppModuleAnalyzer
from .crystal_analyzer import CrystalAnalyzer
from .csharp_analyzer import CSharpAnalyzer
from .curry_analyzer import CurryAnalyzer
from .cython_analyzer import CythonAnalyzer
from .d_analyzer import DAnalyzer
from .dagman_analyzer import DagmanAnalyzer
from .dagster_analyzer import DagsterAnalyzer
from .dart_analyzer import DartAnalyzer
from .devicetree_analyzer import DeviceTreeAnalyzer
from .drools_analyzer import DroolsAnalyzer
from .dynamics_nav_analyzer import DynamicsNAVAnalyzer
from .easytrieve_analyzer import EasytrieveAnalyzer
from .edgeworker_analyzer import EdgeWorkerAnalyzer
from .eiffel_analyzer import EiffelAnalyzer
from .elixir_analyzer import ElixirAnalyzer
from .elm_analyzer import ElmAnalyzer
from .emacslisp_analyzer import EmacsLispAnalyzer
from .erlang_analyzer import ErlangAnalyzer
from .esignal_efs_analyzer import ESignalEFSAnalyzer
from .factor_analyzer import FactorAnalyzer
from .fennel_analyzer import FennelAnalyzer
from .flix_analyzer import FlixAnalyzer
from .focus_analyzer import FocusAnalyzer
from .forth_analyzer import ForthAnalyzer
from .fortran_analyzer import FortranAnalyzer
from .fourgl_analyzer import FourGLAnalyzer
from .frege_analyzer import FregeAnalyzer
from .fsharp_analyzer import FSharpAnalyzer
from .gams_analyzer import GAMSAnalyzer
from .gauge_spec_analyzer import GaugeSpecAnalyzer
from .gaussian_input_analyzer import GaussianInputAnalyzer
from .gdscript_analyzer import GDScriptAnalyzer
from .gleam_analyzer import GleamAnalyzer
from .gmsh_geo_analyzer import GmshGeoAnalyzer
from .gnu_assembly_analyzer import GnuAssemblyAnalyzer
from .go_analyzer import GoAnalyzer
from .gren_analyzer import GrenAnalyzer
from .groovy_analyzer import GroovyAnalyzer
from .harbour_analyzer import HarbourAnalyzer
from .haskell_analyzer import HaskellAnalyzer
from .haxe_analyzer import HaxeAnalyzer
from .hip_analyzer import HipAnalyzer
from .hy_analyzer import HyAnalyzer
from .icon_analyzer import IconAnalyzer
from .ideal_analyzer import IdealAnalyzer
from .idris_analyzer import IdrisAnalyzer
from .ink_analyzer import InkAnalyzer
from .intercal_analyzer import IntercalAnalyzer
from .io_analyzer import IoAnalyzer

# ---- Batch 8 ----
from .isabelle_analyzer import IsabelleAnalyzer
from .j_analyzer import JAnalyzer

# ---- Batch 14 ----
from .jai_analyzer import JaiAnalyzer
from .janet_analyzer import JanetAnalyzer
from .java_analyzer import JavaAnalyzer
from .javascript_analyzer import JavaScriptAnalyzer, TypeScriptAnalyzer
from .jbi_analyzer import JbiAnalyzer
from .jsbundle_analyzer import JSBundleAnalyzer
from .julia_analyzer import JuliaAnalyzer
from .k6_analyzer import K6Analyzer
from .k_analyzer import KAnalyzer
from .koka_analyzer import KokaAnalyzer
from .kotlin_analyzer import KotlinAnalyzer
from .krl_analyzer import KRLAnalyzer
from .labview_vi_analyzer import LabviewViAnalyzer
from .lark_analyzer import LarkAnalyzer
from .lean_analyzer import LeanAnalyzer

# ---- Batch 7 ----
from .lex_analyzer import LexAnalyzer
from .ligo_analyzer import LigoAnalyzer
from .lilypond_analyzer import LilyPondAnalyzer
from .lisp_analyzer import LispAnalyzer
from .livescript_analyzer import LiveScriptAnalyzer
from .llvmir_analyzer import LLVMIRAnalyzer
from .locust_analyzer import LocustAnalyzer
from .logtalk_analyzer import LogtalkAnalyzer
from .lolcode_analyzer import LOLCODEAnalyzer
from .lookml_analyzer import LookMLAnalyzer
from .lua_analyzer import LuaAnalyzer
from .luigi_analyzer import LuigiAnalyzer
from .macro_asm_analyzer import MacroAsmAnalyzer
from .magik_analyzer import MagikAnalyzer
from .marko_analyzer import MarkoAnalyzer
from .matlab_analyzer import MatlabAnalyzer
from .mercury_analyzer import MercuryAnalyzer
from .mermaid_analyzer import MermaidAnalyzer
from .metafont_analyzer import MetafontAnalyzer
from .michelson_analyzer import MichelsonAnalyzer
from .mizar_analyzer import MizarAnalyzer
from .ml4_analyzer import Ml4Analyzer
from .mlir_analyzer import MLIRAnalyzer
from .modula2_analyzer import Modula2Analyzer
from .modula3_analyzer import Modula3Analyzer
from .mojo_analyzer import MojoAnalyzer
from .moonscript_analyzer import MoonScriptAnalyzer
from .motoko_analyzer import MotokoAnalyzer
from .move_analyzer import MoveAnalyzer
from .mql_analyzer import MQLAnalyzer

# ---- Batch 9 ----
from .nasm_analyzer import NasmAnalyzer
from .natural_analyzer import NaturalAnalyzer
from .nemerle_analyzer import NemerleAnalyzer
from .netlogo_analyzer import NetLogoAnalyzer
from .nim_analyzer import NimAnalyzer
from .nix_analyzer import NixAnalyzer
from .oberon_analyzer import OberonAnalyzer
from .ocaml_analyzer import OCamlAnalyzer
from .ocamllex_analyzer import OCamllexAnalyzer
from .ocamlyacc_analyzer import OCamlyaccAnalyzer
from .odin_analyzer import OdinAnalyzer
from .ook_analyzer import OokAnalyzer
from .opendss_analyzer import OpenDSSAnalyzer
from .openqasm_analyzer import OpenQASMAnalyzer
from .openscad_analyzer import OpenSCADAnalyzer
from .pascal_analyzer import PascalAnalyzer
from .peg_analyzer import PegAnalyzer
from .pennylane_analyzer import PennyLaneAnalyzer
from .perl_analyzer import PerlAnalyzer
from .php_analyzer import PhpAnalyzer
from .piet_analyzer import PietAnalyzer
from .pinescript_analyzer import PineScriptAnalyzer

# Residual source_code plane (Batch 25): 20 new hand-written language analyzers
# clearing the last `source_code` extensions, plus pure aliases onto existing
# analyzers wired directly in EXT_MAP below.
from .plantuml_analyzer import PlantUMLAnalyzer
from .pli_analyzer import PLIAnalyzer
from .pony_analyzer import PonyAnalyzer
from .prefect_analyzer import PrefectAnalyzer
from .processing_analyzer import ProcessingAnalyzer

# ---- Batch 16 ----
from .progress_analyzer import ProgressAnalyzer
from .prolog_analyzer import PrologAnalyzer
from .puppet_analyzer import PuppetAnalyzer
from .purescript_analyzer import PureScriptAnalyzer
from .pyquil_analyzer import PyQuilAnalyzer
from .python_analyzer import PythonCodeAnalyzer
from .q_analyzer import QAnalyzer

# ---- Batch 17 ----
from .qir_analyzer import QIRAnalyzer

# ---- Batch 12 ----
from .qml_analyzer import QMLAnalyzer
from .qmod_analyzer import QmodAnalyzer
from .qsharp_analyzer import QSharpAnalyzer
from .quest_analyzer import QuestAnalyzer
from .quil_analyzer import QuilAnalyzer
from .r_analyzer import RAnalyzer
from .racket_analyzer import RacketAnalyzer
from .raku_analyzer import RakuAnalyzer
from .ramis_analyzer import RamisAnalyzer
from .rapid_analyzer import RAPIDAnalyzer
from .rc_analyzer import RcAnalyzer
from .reasonml_analyzer import ReasonMLAnalyzer
from .rebol_analyzer import RebolAnalyzer
from .red_analyzer import RedAnalyzer
from .rego_analyzer import RegoAnalyzer
from .ren_analyzer import RenPyAnalyzer
from .rescript_analyzer import ReScriptAnalyzer
from .riot_analyzer import RiotAnalyzer
from .robotframework_analyzer import RobotFrameworkAnalyzer
from .roc_analyzer import RocAnalyzer
from .rpg_analyzer import RPGAnalyzer
from .ruby_analyzer import RubyAnalyzer
from .rust_analyzer import RustAnalyzer
from .scala_analyzer import ScalaAnalyzer
from .scheme_analyzer import SchemeAnalyzer
from .scilab_analyzer import ScilabAnalyzer
from .scilla_analyzer import ScillaAnalyzer
from .sentinel_analyzer import SentinelAnalyzer
from .simula_analyzer import SimulaAnalyzer
from .slang_analyzer import SLangAnalyzer
from .smali_analyzer import SmaliAnalyzer
from .sml_analyzer import SMLAnalyzer
from .smtlib_analyzer import SMTLibAnalyzer
from .snobol_analyzer import SnobolAnalyzer
from .solidity_analyzer import SolidityAnalyzer

# ---- Batch 13 ----
from .spice_analyzer import SpiceAnalyzer
from .spice_lib_analyzer import SpiceLibAnalyzer
from .squirrel_analyzer import SquirrelAnalyzer
from .stim_analyzer import StimAnalyzer
from .stl_analyzer import STLAnalyzer
from .structuredtext_analyzer import StructuredTextAnalyzer
from .svelte_analyzer import SvelteAnalyzer
from .swift_analyzer import SwiftAnalyzer
from .swiftinterface_analyzer import SwiftInterfaceAnalyzer
from .sycl_analyzer import SyclAnalyzer
from .tal_analyzer import TALAnalyzer
from .teal_analyzer import TealAnalyzer
from .test_def_analyzer import TestDefAnalyzer
from .tradestation_tsl_analyzer import TradeStationTSLAnalyzer
from .tree_sitter_grammar_analyzer import TreeSitterGrammarAnalyzer
from .triton_analyzer import TritonAnalyzer
from .twee_analyzer import TweeAnalyzer
from .unison_analyzer import UnisonAnalyzer
from .upc_analyzer import UPCAnalyzer
from .urscript_analyzer import URScriptAnalyzer
from .vala_analyzer import ValaAnalyzer
from .vb_analyzer import VBAnalyzer
from .vb_usercontrol_analyzer import VBUserControlAnalyzer
from .vcl_analyzer import VCLAnalyzer
from .verilog_analyzer import VerilogAnalyzer
from .verilog_header_analyzer import VerilogHeaderAnalyzer
from .vhdl_analyzer import VhdlAnalyzer
from .vue_analyzer import VueAnalyzer
from .vyper_analyzer import VyperAnalyzer
from .wat_analyzer import WatAnalyzer
from .whitespace_analyzer import WhitespaceAnalyzer
from .wolfram_analyzer import WolframAnalyzer
from .wren_analyzer import WrenAnalyzer
from .yacc_analyzer import YaccAnalyzer
from .yara_analyzer import YaraAnalyzer
from .zig_analyzer import ZigAnalyzer
from .zimpl_analyzer import ZIMPLAnalyzer


class PolyglotCodeAnalyzer:
    """
    Unified entry point. Automatically routes all files to their corresponding
    reflection and AST analyzer engines, aggregating output tables into a unified
    relational dataset.
    """

    EXT_MAP = {
        ".py": PythonCodeAnalyzer,
        ".js": JavaScriptAnalyzer,
        ".jsx": JavaScriptAnalyzer,
        ".mjs": JavaScriptAnalyzer,
        ".ts": TypeScriptAnalyzer,
        ".tsx": TypeScriptAnalyzer,
        ".go": GoAnalyzer,
        ".java": JavaAnalyzer,
        ".cs": CSharpAnalyzer,
        ".rs": RustAnalyzer,
        ".cpp": CppAnalyzer,
        ".hpp": CppAnalyzer,
        ".cc": CppAnalyzer,
        ".cxx": CppAnalyzer,
        ".c": CAnalyzer,
        ".h": CAnalyzer,
        ".r": RAnalyzer,
        ".R": RAnalyzer,
        ".rb": RubyAnalyzer,
        ".rake": RubyAnalyzer,
        ".php": PhpAnalyzer,
        ".swift": SwiftAnalyzer,
        ".kt": KotlinAnalyzer,
        ".kts": KotlinAnalyzer,
        ".scala": ScalaAnalyzer,
        ".sc": ScalaAnalyzer,
        ".ex": ElixirAnalyzer,
        ".exs": ElixirAnalyzer,
        # ---- Batch 1: hand-written (regex/heuristic) analyzers ----
        ".vala": ValaAnalyzer,
        ".vapi": ValaAnalyzer,
        ".cr": CrystalAnalyzer,
        ".hx": HaxeAnalyzer,
        ".d": DAnalyzer,
        ".di": DAnalyzer,
        ".odin": OdinAnalyzer,
        ".pony": PonyAnalyzer,
        ".wren": WrenAnalyzer,
        ".gd": GDScriptAnalyzer,
        ".coffee": CoffeeScriptAnalyzer,
        ".litcoffee": CoffeeScriptAnalyzer,
        ".mojo": MojoAnalyzer,
        ".\U0001f525": MojoAnalyzer,
        # ---- Batch 2: hand-written (regex/heuristic) analyzers ----
        ".ada": AdaAnalyzer,
        ".adb": AdaAnalyzer,
        ".ads": AdaAnalyzer,
        ".as": ActionScriptAnalyzer,
        ".al": ALAnalyzer,
        ".bal": BallerinaAnalyzer,
        ".ballerina": BallerinaAnalyzer,
        ".boo": BooAnalyzer,
        ".cairo": CairoAnalyzer,
        ".ceylon": CeylonAnalyzer,
        ".chpl": ChapelAnalyzer,
        ".vy": VyperAnalyzer,
        # ---- Batch 3: hand-written (regex/heuristic) analyzers ----
        ".cbl": CobolAnalyzer,
        ".cob": CobolAnalyzer,
        ".cpy": CobolAnalyzer,
        ".f03": FortranAnalyzer,
        ".f08": FortranAnalyzer,
        ".hpf": FortranAnalyzer,
        ".cuf": FortranAnalyzer,
        ".pas": PascalAnalyzer,
        ".dpr": PascalAnalyzer,
        ".dpk": PascalAnalyzer,
        ".lisp": LispAnalyzer,
        ".lsp": LispAnalyzer,
        ".scm": SchemeAnalyzer,
        ".ss": SchemeAnalyzer,
        ".rkt": RacketAnalyzer,
        ".sml": SMLAnalyzer,
        ".sig": SMLAnalyzer,
        ".fun": SMLAnalyzer,
        ".elm": ElmAnalyzer,
        ".vb": VBAnalyzer,
        ".bas": VBAnalyzer,
        ".frm": VBAnalyzer,
        # ---- Batch 4: hand-written (regex/heuristic) analyzers ----
        ".abap": AbapAnalyzer,
        ".raku": RakuAnalyzer,
        ".p6": RakuAnalyzer,
        ".pm6": RakuAnalyzer,
        ".rakumod": RakuAnalyzer,
        ".purs": PureScriptAnalyzer,
        ".gleam": GleamAnalyzer,
        ".re": ReasonMLAnalyzer,
        ".rei": ReasonMLAnalyzer,
        ".idr": IdrisAnalyzer,
        ".lidr": IdrisAnalyzer,
        ".lean": LeanAnalyzer,
        ".lgt": LogtalkAnalyzer,
        ".logtalk": LogtalkAnalyzer,
        ".e": EiffelAnalyzer,
        ".eiffel": EiffelAnalyzer,
        # ---- Batch 5: hand-written (regex/heuristic) analyzers ----
        ".fnl": FennelAnalyzer,
        ".hy": HyAnalyzer,
        ".janet": JanetAnalyzer,
        ".el": EmacsLispAnalyzer,
        ".factor": FactorAnalyzer,
        ".forth": ForthAnalyzer,
        ".fth": ForthAnalyzer,
        ".prolog": PrologAnalyzer,
        ".mercury": MercuryAnalyzer,
        ".curry": CurryAnalyzer,
        # ---- Batch 6: hand-written (regex/heuristic) analyzers ----
        ".move": MoveAnalyzer,
        ".clar": ClarityAnalyzer,
        ".agda": AgdaAnalyzer,
        ".fsharp": FSharpAnalyzer,
        ".rego": RegoAnalyzer,
        ".robot": RobotFrameworkAnalyzer,
        ".resource": RobotFrameworkAnalyzer,
        ".wat": WatAnalyzer,
        ".wast": WatAnalyzer,
        ".moon": MoonScriptAnalyzer,
        ".nut": SquirrelAnalyzer,
        # ---- Batch 7: grammar-generator & quantum analyzers ----
        ".l": LexAnalyzer,
        ".y": YaccAnalyzer,
        ".mll": OCamllexAnalyzer,
        ".mly": OCamlyaccAnalyzer,
        ".peg": PegAnalyzer,
        ".lark": LarkAnalyzer,
        ".qs": QSharpAnalyzer,
        ".qsharp": QSharpAnalyzer,
        ".qasm": OpenQASMAnalyzer,
        ".openqasm": OpenQASMAnalyzer,
        ".quil": QuilAnalyzer,
        # ---- Batch 8: formal-methods / smart-contract / HDL / IR ----
        ".thy": IsabelleAnalyzer,
        ".teal": TealAnalyzer,
        ".michelson": MichelsonAnalyzer,
        ".tz": MichelsonAnalyzer,
        ".ligo": LigoAnalyzer,
        ".scilla": ScillaAnalyzer,
        ".bsv": BluespecAnalyzer,
        ".mlir": MLIRAnalyzer,
        ".ll": LLVMIRAnalyzer,
        ".smt2": SMTLibAnalyzer,
        # ---- Batch 9: assembly / IaC / HDL-header / DSL analyzers ----
        ".nasm": NasmAnalyzer,
        ".mo": MotokoAnalyzer,
        ".bicep": BicepAnalyzer,
        ".vh": VerilogHeaderAnalyzer,
        ".svh": VerilogHeaderAnalyzer,
        ".dts": DeviceTreeAnalyzer,
        ".dtsi": DeviceTreeAnalyzer,
        ".pine": PineScriptAnalyzer,
        ".mq4": MQLAnalyzer,
        ".mq5": MQLAnalyzer,
        ".st": StructuredTextAnalyzer,
        ".scl": StructuredTextAnalyzer,
        ".q": QAnalyzer,
        # ---- Batch 10: array / prototype / bytecode / formal / legacy-OO ----
        ".apl": AplAnalyzer,
        ".j": JAnalyzer,
        ".k": KAnalyzer,
        ".io": IoAnalyzer,
        ".smali": SmaliAnalyzer,
        ".mizar": MizarAnalyzer,
        ".miz": MizarAnalyzer,
        ".simula": SimulaAnalyzer,
        ".sim": SimulaAnalyzer,
        ".reb": RebolAnalyzer,
        ".rebol": RebolAnalyzer,
        ".red": RedAnalyzer,
        ".mod": Modula2Analyzer,
        ".def": Modula2Analyzer,
        ".m3": Modula3Analyzer,
        ".i3": Modula3Analyzer,
        ".oberon": OberonAnalyzer,
        ".pli": PLIAnalyzer,
        ".rpg": RPGAnalyzer,
        ".rpgle": RPGAnalyzer,
        ".yar": YaraAnalyzer,
        ".yara": YaraAnalyzer,
        ".pp": PuppetAnalyzer,
        ".scad": OpenSCADAnalyzer,
        ".icn": IconAnalyzer,
        # ---- Batch 12: UI/DSL/functional/modeling ----
        ".qml": QMLAnalyzer,
        ".pde": ProcessingAnalyzer,
        ".frege": FregeAnalyzer,
        ".fr": FregeAnalyzer,
        ".roc": RocAnalyzer,
        ".u": UnisonAnalyzer,
        ".unison": UnisonAnalyzer,
        ".vcl": VCLAnalyzer,
        ".varnish": VCLAnalyzer,
        ".drl": DroolsAnalyzer,
        ".ampl": AMPLAnalyzer,
        ".gms": GAMSAnalyzer,
        # ---- Batch 13: netlist/diagram/functional/policy/config ----
        ".cir": SpiceAnalyzer,
        ".sp": SpiceAnalyzer,
        ".spi": SpiceAnalyzer,
        ".subckt": SpiceAnalyzer,
        ".mermaid": MermaidAnalyzer,
        ".plantuml": PlantUMLAnalyzer,
        ".flix": FlixAnalyzer,
        ".gren": GrenAnalyzer,
        ".carbon": CarbonAnalyzer,
        ".lkml": LookMLAnalyzer,
        ".cedar": CedarAnalyzer,
        ".kk": KokaAnalyzer,
        # ---- Batch 14: systems/.NET/GIS/notation/narrative/numeric/symbolic ----
        ".jai": JaiAnalyzer,
        ".n": NemerleAnalyzer,
        ".nemerle": NemerleAnalyzer,
        ".magik": MagikAnalyzer,
        ".ly": LilyPondAnalyzer,
        ".ily": LilyPondAnalyzer,
        ".ink": InkAnalyzer,
        ".twee": TweeAnalyzer,
        ".tw": TweeAnalyzer,
        ".sci": ScilabAnalyzer,
        ".sce": ScilabAnalyzer,
        ".wl": WolframAnalyzer,
        ".wls": WolframAnalyzer,
        ".lol": LOLCODEAnalyzer,
        ".lolcode": LOLCODEAnalyzer,
        # ---- Batch 15: C++ modules/templating/CFML/policy/4GL/robotics/xBase ----
        ".cppm": CppModuleAnalyzer,
        ".ixx": CppModuleAnalyzer,
        ".ipp": CppModuleAnalyzer,
        ".tpp": CppModuleAnalyzer,
        ".inl": CppModuleAnalyzer,
        ".marko": MarkoAnalyzer,
        ".riot": RiotAnalyzer,
        ".cfc": ColdFusionAnalyzer,
        ".sentinel": SentinelAnalyzer,
        ".4gl": FourGLAnalyzer,
        ".krl": KRLAnalyzer,
        ".rapid": RAPIDAnalyzer,
        ".prg": HarbourAnalyzer,
        # ---- Batch 16: 4GL/PLC/robotics/quantum/report/historical ----
        ".progress": ProgressAnalyzer,
        ".w": ProgressAnalyzer,
        ".nat": NaturalAnalyzer,
        ".nsp": NaturalAnalyzer,
        ".nsn": NaturalAnalyzer,
        ".tal": TALAnalyzer,
        ".awl": STLAnalyzer,
        ".afl": AFLAnalyzer,
        ".qmod": QmodAnalyzer,
        ".algol": AlgolAnalyzer,
        ".alg": AlgolAnalyzer,
        ".a68": AlgolAnalyzer,
        ".snobol": SnobolAnalyzer,
        ".sno": SnobolAnalyzer,
        ".script": URScriptAnalyzer,
        # ---- Batch 17: quantum-IR/HDL/GPU-C++/PGAS/Cython/DSL/report/math ----
        ".qir": QIRAnalyzer,
        ".chisel": ChiselAnalyzer,
        ".sycl": SyclAnalyzer,
        ".hip": HipAnalyzer,
        ".upc": UPCAnalyzer,
        ".pxi": CythonAnalyzer,
        ".cy": CythonAnalyzer,
        ".ren": RenPyAnalyzer,
        ".easytrieve": EasytrieveAnalyzer,
        ".zpl": ZIMPLAnalyzer,
        # ---- Batch 18: Python-embedded quantum & orchestration DSLs ----
        ".cirq": CirqAnalyzer,
        ".pyquil": PyQuilAnalyzer,
        ".pennylane": PennyLaneAnalyzer,
        ".triton": TritonAnalyzer,
        ".dagster": DagsterAnalyzer,
        ".luigi": LuigiAnalyzer,
        ".prefect": PrefectAnalyzer,
        ".locustfile": LocustAnalyzer,
        ".k6": K6Analyzer,
        ".jsbundle": JSBundleAnalyzer,
        ".edgeworker": EdgeWorkerAnalyzer,
        ".swiftinterface": SwiftInterfaceAnalyzer,
        ".ls": LiveScriptAnalyzer,
        ".bms": BmsAnalyzer,
        ".asl": AslAnalyzer,
        ".rc": RcAnalyzer,
        ".mf": MetafontAnalyzer,
        ".nl": NetLogoAnalyzer,
        ".dag": DagmanAnalyzer,
        ".cask": CaskAnalyzer,
        ".ml4": Ml4Analyzer,
        ".jbi": JbiAnalyzer,
        ".bf": BrainfuckAnalyzer,
        ".befunge": BefungeAnalyzer,
        ".ook": OokAnalyzer,
        ".ws": WhitespaceAnalyzer,
        ".intercal": IntercalAnalyzer,
        ".piet": PietAnalyzer,
        ".geo": GmshGeoAnalyzer,
        ".dss": OpenDSSAnalyzer,
        ".stim": StimAnalyzer,
        ".lib": SpiceLibAnalyzer,
        ".gjf": GaussianInputAnalyzer,
        ".com": GaussianInputAnalyzer,
        ".nav": DynamicsNAVAnalyzer,
        ".sl": SLangAnalyzer,
        ".blackbird": BlackbirdAnalyzer,
        ".tsl": TradeStationTSLAnalyzer,
        ".focus": FocusAnalyzer,
        ".ramis": RamisAnalyzer,
        ".res": ReScriptAnalyzer,
        ".els": ESignalEFSAnalyzer,
        ".mac": MacroAsmAnalyzer,
        ".ideal": IdealAnalyzer,
        ".asmx": AspNetAsmxAnalyzer,
        ".ashx": AspNetAshxAnalyzer,
        ".ctl": VBUserControlAnalyzer,
        ".quest": QuestAnalyzer,
        ".blq": BloqadeAnalyzer,
        ".spec": GaugeSpecAnalyzer,
        ".test": TestDefAnalyzer,
        ".vi": LabviewViAnalyzer,
        ".alembic": AlembicAnalyzer,
        ".cdk": CdkAnalyzer,
        ".beam": ApacheBeamAnalyzer,
        ".tree-sitter": TreeSitterGrammarAnalyzer,
        # ----------------------------------------------------------------
        # Batch 25 -- residual `source_code` extensions.
        # Pure aliases onto existing analyzers (same syntax family):
        ".c++": CppAnalyzer,
        ".hh": CppAnalyzer,
        ".hxx": CppAnalyzer,
        ".ino": CppAnalyzer,
        ".cu": CppAnalyzer,
        ".cuh": CppAnalyzer,
        ".cjs": JavaScriptAnalyzer,
        ".cts": TypeScriptAnalyzer,
        ".cl": LispAnalyzer,
        ".pyx": CythonAnalyzer,
        ".pxd": CythonAnalyzer,
        ".pyi": PythonCodeAnalyzer,
        ".pyw": PythonCodeAnalyzer,
        ".nbconvert": PythonCodeAnalyzer,
        ".mmd": MermaidAnalyzer,
        ".puml": PlantUMLAnalyzer,
        ".f": FortranAnalyzer,
        ".f77": FortranAnalyzer,
        ".f90": FortranAnalyzer,
        ".f95": FortranAnalyzer,
        ".for": FortranAnalyzer,
        ".fs": FSharpAnalyzer,
        ".fsi": FSharpAnalyzer,
        # New dedicated per-language analyzers:
        ".hs": HaskellAnalyzer,
        ".lhs": HaskellAnalyzer,
        ".lua": LuaAnalyzer,
        ".jl": JuliaAnalyzer,
        ".erl": ErlangAnalyzer,
        ".hrl": ErlangAnalyzer,
        ".ml": OCamlAnalyzer,
        ".mli": OCamlAnalyzer,
        ".clj": ClojureAnalyzer,
        ".cljc": ClojureAnalyzer,
        ".cljs": ClojureAnalyzer,
        ".dart": DartAnalyzer,
        ".nim": NimAnalyzer,
        ".zig": ZigAnalyzer,
        ".sol": SolidityAnalyzer,
        ".v": VerilogAnalyzer,
        ".sv": VerilogAnalyzer,
        ".vhdl": VhdlAnalyzer,
        ".vue": VueAnalyzer,
        ".svelte": SvelteAnalyzer,
        ".nix": NixAnalyzer,
        ".groovy": GroovyAnalyzer,
        ".pm": PerlAnalyzer,
        ".m": MatlabAnalyzer,
        ".s": GnuAssemblyAnalyzer,
        ".astro": AstroAnalyzer,
    }

    def __init__(
        self,
        file_paths: List[Union[str, Path]],
        dump_file_path: str = "polyglot_analysis.json",
        dump_file_type: str = "json",
    ):
        self.file_paths = [Path(p).resolve() for p in file_paths]
        self.dump_file_path = dump_file_path
        self.dump_file_type = dump_file_type

    def analyze(self) -> Dict[str, List[Dict[str, Any]]]:
        grouped: Dict[Any, List[Path]] = {}
        for p in self.file_paths:
            analyzer_cls = self.EXT_MAP.get(p.suffix.lower())
            if analyzer_cls:
                grouped.setdefault(analyzer_cls, []).append(p)

        merged_tables = {
            "kind_reference": [],
            "symbol_index": [],
            "imports_table": [],
            "variables_table": [],
            "functions_table": [],
            "classes_table": [],
            "args_table": [],
            "tensor_members_table": [],
            "outputs_table": [],
            "introspection_metadata_table": [],
            "temp_kind_details": [],
        }

        # ------------------------------------------------------------------
        # Cross-analyzer id reconciliation.
        #
        # Every per-language analyzer numbers its own tables from 1 (file_id,
        # symbol_id, class_id, function_id, ... and the static kind_reference).
        # Naively concatenating them corrupts the relational data: the static
        # kind_reference collides on its primary key (a hard crash), entity PKs
        # from different languages overwrite one another, and file_id no longer
        # lines up with the ordered file list that ImportLinkageAnalyzer uses to
        # bridge into file_details. We fix all three here:
        #   * kind_reference is emitted exactly once (it is a constant).
        #   * each analyzer's entity ids are shifted into a disjoint numeric
        #     range (`base`), and every id-valued reference field is shifted by
        #     the same base so intra-analyzer links stay valid.
        #   * file_id is remapped to this Polyglot run's global file ordering
        #     (index in self.file_paths), matching the analyzed_file_paths the
        #     caller passes to ImportLinkageAnalyzer.
        #   * temp_kind_details is rebuilt once over the merged tables so its
        #     ids and Mermaid flowcharts are globally consistent.
        # ------------------------------------------------------------------
        global_file_index = {p: i for i, p in enumerate(self.file_paths, start=1)}

        shift_scalar = {
            "imports_table": ["import_id"],
            "variables_table": ["variable_id", "source_import_id"],
            "functions_table": ["function_id", "class_id", "source_import_id"],
            "classes_table": ["class_id", "source_import_id"],
            "args_table": ["args_id"],
            "outputs_table": ["output_id"],
            "tensor_members_table": ["member_id"],
            "introspection_metadata_table": ["metadata_id"],
            "symbol_index": ["symbol_id", "target_entity_id"],
        }
        shift_list = {
            "functions_table": ["args_ids", "function_outputs_ids"],
            "classes_table": [
                "parent_class_ids",
                "method_ids",
                "args_ids",
                "attr_ids",
                "tensor_member_ids",
            ],
        }
        pk_by_table = {
            "imports_table": "import_id",
            "variables_table": "variable_id",
            "functions_table": "function_id",
            "classes_table": "class_id",
            "args_table": "args_id",
            "outputs_table": "output_id",
            "tensor_members_table": "member_id",
            "introspection_metadata_table": "metadata_id",
            "symbol_index": "symbol_id",
        }

        id_offset = 0  # running base for the next analyzer's id range
        kind_ref_set = False

        for analyzer_cls, paths in grouped.items():
            # A missing/failed language backend (e.g. tree-sitter not installed)
            # must degrade to skipping only THOSE files, not abort the whole run
            # and lose the languages that CAN be analyzed.
            try:
                analyzer = analyzer_cls(file_paths=paths, dump_file_type="memory")
                tables = analyzer.analyze()
            except ImportError as err:
                exts = "/".join(sorted({p.suffix for p in paths}))
                print(
                    f"Warning: skipping {len(paths)} {exts} file(s); "
                    f"{analyzer_cls.__name__} backend unavailable: {err}"
                )
                continue
            except Exception as err:
                exts = "/".join(sorted({p.suffix for p in paths}))
                print(
                    f"Warning: {analyzer_cls.__name__} failed on {len(paths)} "
                    f"{exts} file(s); skipping them: {err}"
                )
                continue

            # kind_reference is a constant lookup table; keep exactly one copy.
            if not kind_ref_set:
                merged_tables["kind_reference"] = [
                    dict(r) for r in tables.get("kind_reference", [])
                ]
                kind_ref_set = True

            # Reconstruct this analyzer's local file_id -> global file_id map.
            # Tree-sitter analyzers number over a filtered valid_files list;
            # PythonCodeAnalyzer numbers over the paths it was given (positions
            # preserved across skips). Either way local file_id is 1-based over
            # that ordered list.
            if hasattr(analyzer, "extensions"):
                _exts = {e.lower() for e in analyzer.extensions}
                ordered_files = [
                    p for p in paths if p.suffix.lower() in _exts and p.exists()
                ]
            else:
                ordered_files = list(paths)
            local_to_global_file = {
                j: global_file_index.get(Path(p).resolve())
                for j, p in enumerate(ordered_files, start=1)
            }

            base = id_offset

            # Shift scalar id columns.
            for tname, cols in shift_scalar.items():
                for row in tables.get(tname, []):
                    for c in cols:
                        if row.get(c) is not None:
                            row[c] = row[c] + base
            # Shift list-of-id columns.
            for tname, cols in shift_list.items():
                for row in tables.get(tname, []):
                    for c in cols:
                        if row.get(c):
                            row[c] = [x + base for x in row[c]]
            # introspection entity_id is polymorphic: a "module" row points at a
            # file_id (remap to global), everything else at a shifted entity id.
            for row in tables.get("introspection_metadata_table", []):
                if row.get("entity_type") == "module":
                    row["entity_id"] = local_to_global_file.get(row.get("entity_id"))
                elif row.get("entity_id") is not None:
                    row["entity_id"] = row["entity_id"] + base
            # symbol_index.file_id -> global file ordering.
            for row in tables.get("symbol_index", []):
                row["file_id"] = local_to_global_file.get(row.get("file_id"))

            # Advance the base past every id this analyzer actually used.
            local_max = 0
            for tname, pk in pk_by_table.items():
                for row in tables.get(tname, []):
                    v = row.get(pk)
                    if isinstance(v, int) and (v - base) > local_max:
                        local_max = v - base
            id_offset = base + local_max

            for k in merged_tables:
                if k in ("kind_reference", "temp_kind_details"):
                    continue
                merged_tables[k].extend(tables.get(k, []))

        exporter = BaseCodeAnalyzer(
            dump_file_path=self.dump_file_path, dump_file_type=self.dump_file_type
        )
        for k in merged_tables:
            setattr(exporter, k, merged_tables[k])
        # Rebuild temp_kind_details once over the fully-merged, reconciled tables
        # so its ids and Mermaid flowcharts span all languages consistently.
        exporter._build_temp_kind_details_table()
        merged_tables["temp_kind_details"] = exporter.temp_kind_details
        exporter.export()
        return merged_tables


# ----------------------------------------------------------------------------
# Fold the shell / command-language / automation-script analyzers into the
# `code` domain.  Registering their extensions here (and nowhere else) is what
# routes every shell extension to `code`: the router derives its code-extension
# universe lazily from `PolyglotCodeAnalyzer.EXT_MAP`, and this dispatcher then
# analyzes shell files in the same pass as programming-language files, with the
# same id reconciliation and identical table shape.  Kept at module bottom so
# the class is fully defined before py.shell (which subclasses it) is imported.
# ----------------------------------------------------------------------------
from ..shell import SHELL_EXT_MAP as _SHELL_EXT_MAP

for _ext, _cls in _SHELL_EXT_MAP.items():
    _existing = PolyglotCodeAnalyzer.EXT_MAP.get(_ext)
    if _existing is not None and _existing is not _cls:
        raise RuntimeError(
            f"shell extension {_ext} collides with programming-language "
            f"analyzer {_existing.__name__}"
        )
    PolyglotCodeAnalyzer.EXT_MAP[_ext] = _cls


# ----------------------------------------------------------------------------
# Fold the mainstream command-language / build-script dialects (bash/sh/zsh/ksh,
# fish, PowerShell, batch, CMake, Gradle, Bazel Starlark, F# script, Perl) into
# the `code` domain the same way: registering their extensions here routes every
# script extension to `code`.  Kept below the shell fold so both maps see the
# fully-defined dispatcher.
# ----------------------------------------------------------------------------
from ..script import SCRIPT_EXT_MAP as _SCRIPT_EXT_MAP

for _ext, _cls in _SCRIPT_EXT_MAP.items():
    _existing = PolyglotCodeAnalyzer.EXT_MAP.get(_ext)
    if _existing is not None and _existing is not _cls:
        raise RuntimeError(
            f"script extension {_ext} collides with existing "
            f"analyzer {_existing.__name__}"
        )
    PolyglotCodeAnalyzer.EXT_MAP[_ext] = _cls
