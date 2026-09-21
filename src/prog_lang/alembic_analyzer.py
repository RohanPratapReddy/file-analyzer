# Alembic migration script (.alembic).
#
# An Alembic migration is ordinary, importable Python: the file grammar IS
# Python (AST-parsed by the shared base).  Every migration carries the same
# domain shape:
#
#     """add users table"""
#     from alembic import op                 -> import
#     import sqlalchemy as sa                 -> import
#     revision = "a1b2c3"                     -> variable (migration id)
#     down_revision = "0009"                  -> variable
#     branch_labels = None                    -> variable
#     depends_on = None                       -> variable
#     def upgrade(): op.create_table(...)     -> function (forward migration)
#     def downgrade(): op.drop_table(...)     -> function (rollback)
#
# The full class/function/import/variable extraction is inherited unchanged from
# PythonEmbeddedAnalyzer; `_dsl_enrich` additionally tags the upgrade/downgrade
# entry points and the revision identifiers as Alembic-specific metadata.
import ast

from .python_embedded_base import PythonEmbeddedAnalyzer

_REV_VARS = {"revision", "down_revision", "branch_labels", "depends_on"}
_MIGRATION_FNS = {"upgrade", "downgrade"}


class AlembicAnalyzer(PythonEmbeddedAnalyzer):
    LANG_KEY = "alembic"
    EXTENSIONS = (".alembic",)

    def _dsl_enrich(self, file_id, tree, code_text):
        super()._dsl_enrich(file_id, tree, code_text)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name in _MIGRATION_FNS:
                    self._dsl_tag(file_id, node.name, "migration:" + node.name)
            elif isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id in _REV_VARS:
                        val = None
                        if isinstance(node.value, ast.Constant):
                            val = node.value.value
                        self._dsl_tag(
                            file_id, tgt.id, "revision-field", extra={"value": val}
                        )
