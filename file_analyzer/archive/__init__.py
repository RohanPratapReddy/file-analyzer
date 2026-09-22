"""tabgen archive/container analysis subpackage.

``ArchiveAnalyzer`` handles zip/tar/compression *containers* (the ``archive``
routing class): it extracts each container into ``temp/sandbox/`` and runs a
nested ``AnalysisEngine`` over the extracted tree, then links the resulting
per-archive sub-database and member census back to the main engine's database
via the ``archive_index`` / ``archive_members`` relational tables.

Data-meaningful single-file containers (``.npz``/``.docx``/``.xlsx``/``.pdf``/
``.glb``/``.gpkg``/``.ods``) are NOT archives here -- they stay with
``DataAnalyzer``, which profiles them in place.
"""

from .archive_analyzer import ArchiveAnalyzer

__all__ = ["ArchiveAnalyzer"]
