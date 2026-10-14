"""create users table

Revision ID: 20260911_0001
Revises:
Create Date: 2026-09-11
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260911_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

affiliation_enum = postgresql.ENUM(
    "student",
    "teacher",
    "alumni",
    name="user_affiliation",
    create_type=False,
)


def upgrade() -> None:
    affiliation_enum.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "users",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("google_sub", sa.String(length=255), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("avatar_url", sa.Text(), nullable=True),
        sa.Column(
            "affiliation",
            affiliation_enum,
            nullable=False,
        ),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_reason", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("email", name="uq_users_email"),
        sa.UniqueConstraint("google_sub", name="uq_users_google_sub"),
    )
    op.create_index("ix_users_affiliation", "users", ["affiliation"])
    op.create_index("ix_users_disabled_at", "users", ["disabled_at"])


def downgrade() -> None:
    op.drop_index("ix_users_disabled_at", table_name="users")
    op.drop_index("ix_users_affiliation", table_name="users")
    op.drop_table("users")
    affiliation_enum.drop(op.get_bind(), checkfirst=True)
