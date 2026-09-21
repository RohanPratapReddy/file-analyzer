"""prog_lang: per-language {Lang}Analyzer classes, the shared analysis
engine bases (RegexCodeAnalyzer / BaseTreeSitterAnalyzer /
PythonEmbeddedAnalyzer / BaseCodeAnalyzer) and the PolyglotCodeAnalyzer
dispatcher (ext -> analyzer via EXT_MAP).
"""

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
from .apl_analyzer import AplAnalyzer
from .asl_analyzer import AslAnalyzer
from .aspnet_ashx_analyzer import AspNetAshxAnalyzer
from .aspnet_asmx_analyzer import AspNetAsmxAnalyzer
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
from .cobol_analyzer import CobolAnalyzer
from .coffeescript_analyzer import CoffeeScriptAnalyzer
from .coldfusion_analyzer import ColdFusionAnalyzer
from .cppmodule_analyzer import CppModuleAnalyzer
from .crystal_analyzer import CrystalAnalyzer
from .csharp_analyzer import CSharpAnalyzer
from .curry_analyzer import CurryAnalyzer
from .cython_analyzer import CythonAnalyzer
from .d_analyzer import DAnalyzer
from .dagman_analyzer import DagmanAnalyzer
from .dagster_analyzer import DagsterAnalyzer
from .devicetree_analyzer import DeviceTreeAnalyzer
from .drools_analyzer import DroolsAnalyzer
from .dynamics_nav_analyzer import DynamicsNAVAnalyzer
from .easytrieve_analyzer import EasytrieveAnalyzer
from .edgeworker_analyzer import EdgeWorkerAnalyzer
from .eiffel_analyzer import EiffelAnalyzer
from .elixir_analyzer import ElixirAnalyzer
from .elm_analyzer import ElmAnalyzer
from .emacslisp_analyzer import EmacsLispAnalyzer
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
from .go_analyzer import GoAnalyzer
from .gren_analyzer import GrenAnalyzer
from .harbour_analyzer import HarbourAnalyzer
from .haxe_analyzer import HaxeAnalyzer
from .hip_analyzer import HipAnalyzer
from .hy_analyzer import HyAnalyzer
from .icon_analyzer import IconAnalyzer
from .ideal_analyzer import IdealAnalyzer
from .idris_analyzer import IdrisAnalyzer
from .ink_analyzer import InkAnalyzer
from .intercal_analyzer import IntercalAnalyzer
from .io_analyzer import IoAnalyzer
from .isabelle_analyzer import IsabelleAnalyzer
from .j_analyzer import JAnalyzer
from .jai_analyzer import JaiAnalyzer
from .janet_analyzer import JanetAnalyzer
from .java_analyzer import JavaAnalyzer
from .javascript_analyzer import JavaScriptAnalyzer, TypeScriptAnalyzer, _SingleChild
from .jbi_analyzer import JbiAnalyzer
from .jsbundle_analyzer import JSBundleAnalyzer
from .k6_analyzer import K6Analyzer
from .k_analyzer import KAnalyzer
from .koka_analyzer import KokaAnalyzer
from .kotlin_analyzer import KotlinAnalyzer
from .krl_analyzer import KRLAnalyzer
from .labview_vi_analyzer import LabviewViAnalyzer
from .lark_analyzer import LarkAnalyzer
from .lean_analyzer import LeanAnalyzer
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
from .luigi_analyzer import LuigiAnalyzer
from .macro_asm_analyzer import MacroAsmAnalyzer
from .magik_analyzer import MagikAnalyzer
from .marko_analyzer import MarkoAnalyzer
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
from .nasm_analyzer import NasmAnalyzer
from .natural_analyzer import NaturalAnalyzer
from .nemerle_analyzer import NemerleAnalyzer
from .netlogo_analyzer import NetLogoAnalyzer
from .oberon_analyzer import OberonAnalyzer
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
from .php_analyzer import PhpAnalyzer
from .piet_analyzer import PietAnalyzer
from .pinescript_analyzer import PineScriptAnalyzer
from .plantuml_analyzer import PlantUMLAnalyzer
from .pli_analyzer import PLIAnalyzer
from .polyglot import PolyglotCodeAnalyzer
from .pony_analyzer import PonyAnalyzer
from .prefect_analyzer import PrefectAnalyzer
from .processing_analyzer import ProcessingAnalyzer
from .progress_analyzer import ProgressAnalyzer
from .prolog_analyzer import PrologAnalyzer
from .puppet_analyzer import PuppetAnalyzer
from .purescript_analyzer import PureScriptAnalyzer
from .pyquil_analyzer import PyQuilAnalyzer
from .python_analyzer import PythonCodeAnalyzer
from .q_analyzer import QAnalyzer

# ---- Batch 17 ----
from .qir_analyzer import QIRAnalyzer
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
from .regex_base import RegexCodeAnalyzer
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
from .spice_analyzer import SpiceAnalyzer
from .spice_lib_analyzer import SpiceLibAnalyzer
from .squirrel_analyzer import SquirrelAnalyzer
from .stim_analyzer import StimAnalyzer
from .stl_analyzer import STLAnalyzer
from .structuredtext_analyzer import StructuredTextAnalyzer
from .swift_analyzer import SwiftAnalyzer
from .swiftinterface_analyzer import SwiftInterfaceAnalyzer
from .sycl_analyzer import SyclAnalyzer
from .tal_analyzer import TALAnalyzer
from .teal_analyzer import TealAnalyzer
from .test_def_analyzer import TestDefAnalyzer
from .tradestation_tsl_analyzer import TradeStationTSLAnalyzer
from .tree_sitter_base import BaseTreeSitterAnalyzer
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
from .verilog_header_analyzer import VerilogHeaderAnalyzer
from .vyper_analyzer import VyperAnalyzer
from .wat_analyzer import WatAnalyzer
from .whitespace_analyzer import WhitespaceAnalyzer
from .wolfram_analyzer import WolframAnalyzer
from .wren_analyzer import WrenAnalyzer
from .yacc_analyzer import YaccAnalyzer
from .yara_analyzer import YaraAnalyzer
from .zimpl_analyzer import ZIMPLAnalyzer

__all__ = [
    "BaseCodeAnalyzer",
    "PythonCodeAnalyzer",
    "BaseTreeSitterAnalyzer",
    "JavaAnalyzer",
    "RustAnalyzer",
    "JavaScriptAnalyzer",
    "TypeScriptAnalyzer",
    "CAnalyzer",
    "CppAnalyzer",
    "CSharpAnalyzer",
    "RAnalyzer",
    "RubyAnalyzer",
    "PhpAnalyzer",
    "SwiftAnalyzer",
    "KotlinAnalyzer",
    "ScalaAnalyzer",
    "ElixirAnalyzer",
    "GoAnalyzer",
    "RegexCodeAnalyzer",
    "ValaAnalyzer",
    "CrystalAnalyzer",
    "HaxeAnalyzer",
    "DAnalyzer",
    "OdinAnalyzer",
    "PonyAnalyzer",
    "WrenAnalyzer",
    "GDScriptAnalyzer",
    "CoffeeScriptAnalyzer",
    "MojoAnalyzer",
    "AdaAnalyzer",
    "ActionScriptAnalyzer",
    "ALAnalyzer",
    "BallerinaAnalyzer",
    "BooAnalyzer",
    "CairoAnalyzer",
    "CeylonAnalyzer",
    "ChapelAnalyzer",
    "VyperAnalyzer",
    "CobolAnalyzer",
    "FortranAnalyzer",
    "PascalAnalyzer",
    "LispAnalyzer",
    "SchemeAnalyzer",
    "RacketAnalyzer",
    "SMLAnalyzer",
    "ElmAnalyzer",
    "VBAnalyzer",
    "AbapAnalyzer",
    "RakuAnalyzer",
    "PureScriptAnalyzer",
    "GleamAnalyzer",
    "ReasonMLAnalyzer",
    "IdrisAnalyzer",
    "LeanAnalyzer",
    "LogtalkAnalyzer",
    "EiffelAnalyzer",
    "FennelAnalyzer",
    "HyAnalyzer",
    "JanetAnalyzer",
    "EmacsLispAnalyzer",
    "FactorAnalyzer",
    "ForthAnalyzer",
    "PrologAnalyzer",
    "MercuryAnalyzer",
    "CurryAnalyzer",
    "MoveAnalyzer",
    "ClarityAnalyzer",
    "AgdaAnalyzer",
    "FSharpAnalyzer",
    "RegoAnalyzer",
    "RobotFrameworkAnalyzer",
    "WatAnalyzer",
    "MoonScriptAnalyzer",
    "SquirrelAnalyzer",
    "LexAnalyzer",
    "YaccAnalyzer",
    "OCamllexAnalyzer",
    "OCamlyaccAnalyzer",
    "PegAnalyzer",
    "LarkAnalyzer",
    "QSharpAnalyzer",
    "OpenQASMAnalyzer",
    "QuilAnalyzer",
    "IsabelleAnalyzer",
    "TealAnalyzer",
    "MichelsonAnalyzer",
    "LigoAnalyzer",
    "ScillaAnalyzer",
    "BluespecAnalyzer",
    "MLIRAnalyzer",
    "LLVMIRAnalyzer",
    "SMTLibAnalyzer",
    "NasmAnalyzer",
    "MotokoAnalyzer",
    "BicepAnalyzer",
    "VerilogHeaderAnalyzer",
    "DeviceTreeAnalyzer",
    "PineScriptAnalyzer",
    "MQLAnalyzer",
    "StructuredTextAnalyzer",
    "QAnalyzer",
    "AplAnalyzer",
    "JAnalyzer",
    "KAnalyzer",
    "IoAnalyzer",
    "SmaliAnalyzer",
    "MizarAnalyzer",
    "SimulaAnalyzer",
    "RebolAnalyzer",
    "RedAnalyzer",
    "Modula2Analyzer",
    "Modula3Analyzer",
    "OberonAnalyzer",
    "PLIAnalyzer",
    "RPGAnalyzer",
    "YaraAnalyzer",
    "PuppetAnalyzer",
    "OpenSCADAnalyzer",
    "IconAnalyzer",
    "QMLAnalyzer",
    "ProcessingAnalyzer",
    "FregeAnalyzer",
    "RocAnalyzer",
    "UnisonAnalyzer",
    "VCLAnalyzer",
    "DroolsAnalyzer",
    "AMPLAnalyzer",
    "GAMSAnalyzer",
    "SpiceAnalyzer",
    "MermaidAnalyzer",
    "PlantUMLAnalyzer",
    "FlixAnalyzer",
    "GrenAnalyzer",
    "CarbonAnalyzer",
    "LookMLAnalyzer",
    "CedarAnalyzer",
    "KokaAnalyzer",
    "JaiAnalyzer",
    "NemerleAnalyzer",
    "MagikAnalyzer",
    "LilyPondAnalyzer",
    "InkAnalyzer",
    "TweeAnalyzer",
    "ScilabAnalyzer",
    "WolframAnalyzer",
    "LOLCODEAnalyzer",
    "CppModuleAnalyzer",
    "MarkoAnalyzer",
    "RiotAnalyzer",
    "ColdFusionAnalyzer",
    "SentinelAnalyzer",
    "FourGLAnalyzer",
    "KRLAnalyzer",
    "RAPIDAnalyzer",
    "HarbourAnalyzer",
    "ProgressAnalyzer",
    "NaturalAnalyzer",
    "TALAnalyzer",
    "STLAnalyzer",
    "AFLAnalyzer",
    "QmodAnalyzer",
    "AlgolAnalyzer",
    "SnobolAnalyzer",
    "URScriptAnalyzer",
    "QIRAnalyzer",
    "ChiselAnalyzer",
    "SyclAnalyzer",
    "HipAnalyzer",
    "UPCAnalyzer",
    "CythonAnalyzer",
    "RenPyAnalyzer",
    "EasytrieveAnalyzer",
    "ZIMPLAnalyzer",
    "CirqAnalyzer",
    "PyQuilAnalyzer",
    "PennyLaneAnalyzer",
    "TritonAnalyzer",
    "DagsterAnalyzer",
    "LuigiAnalyzer",
    "PrefectAnalyzer",
    "LocustAnalyzer",
    "K6Analyzer",
    "JSBundleAnalyzer",
    "EdgeWorkerAnalyzer",
    "SwiftInterfaceAnalyzer",
    "LiveScriptAnalyzer",
    "BmsAnalyzer",
    "AslAnalyzer",
    "RcAnalyzer",
    "MetafontAnalyzer",
    "NetLogoAnalyzer",
    "DagmanAnalyzer",
    "CaskAnalyzer",
    "Ml4Analyzer",
    "JbiAnalyzer",
    "BrainfuckAnalyzer",
    "BefungeAnalyzer",
    "OokAnalyzer",
    "WhitespaceAnalyzer",
    "IntercalAnalyzer",
    "PietAnalyzer",
    "GmshGeoAnalyzer",
    "OpenDSSAnalyzer",
    "StimAnalyzer",
    "SpiceLibAnalyzer",
    "GaussianInputAnalyzer",
    "DynamicsNAVAnalyzer",
    "SLangAnalyzer",
    "BlackbirdAnalyzer",
    "TradeStationTSLAnalyzer",
    "FocusAnalyzer",
    "RamisAnalyzer",
    "ReScriptAnalyzer",
    "ESignalEFSAnalyzer",
    "MacroAsmAnalyzer",
    "QuestAnalyzer",
    "BloqadeAnalyzer",
    "GaugeSpecAnalyzer",
    "TestDefAnalyzer",
    "LabviewViAnalyzer",
    "AlembicAnalyzer",
    "CdkAnalyzer",
    "ApacheBeamAnalyzer",
    "TreeSitterGrammarAnalyzer",
    "IdealAnalyzer",
    "AspNetAsmxAnalyzer",
    "AspNetAshxAnalyzer",
    "VBUserControlAnalyzer",
    "PolyglotCodeAnalyzer",
]
