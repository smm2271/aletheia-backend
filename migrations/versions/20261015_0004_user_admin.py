"""Add basic administrator flag.

Revision ID: 20261015_0004
Revises: 20261014_0003
"""
from alembic import op
import sqlalchemy as sa

revision = "20261015_0004"
down_revision = "20261014_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("is_admin", sa.Boolean(), server_default=sa.text("false"), nullable=False))


def downgrade() -> None:
    op.drop_column("users", "is_admin")
