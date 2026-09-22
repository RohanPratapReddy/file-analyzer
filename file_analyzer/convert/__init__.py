"""
Format conversion subpackage.

:class:`FormatConverter` transcodes files the analyzers cannot structurally parse
(opaque / legacy / proprietary formats) into *renderable* targets -- PNG, WAV,
MP4, PDF, TXT -- using real stdlib decoders where possible and delegating to
``ffmpeg`` / ``soffice`` (LibreOffice) only when those tools are on ``PATH``.
Outcomes are always honest: ``unsupported`` / ``tool_unavailable`` are reported
rather than faked, and the raw payload is never persisted.
"""

from .format_converter import (
    RENDERABLE_TARGETS,
    ConversionError,
    FormatConverter,
    encode_png,
)
from .text_analyzer import ANALYZABLE_TARGETS, AnalysisError, TextAnalyzer

__all__ = [
    "FormatConverter",
    "ConversionError",
    "RENDERABLE_TARGETS",
    "encode_png",
    "TextAnalyzer",
    "AnalysisError",
    "ANALYZABLE_TARGETS",
]
