"""Add short-lived Google OAuth handshakes.

Revision ID: 20261014_0003
Revises: 20261014_0002
"""

from alembic import op
import sqlalchemy as sa

revision = "20261014_0003"
down_revision = "20261014_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "oauth_attempts",
        sa.Column("state_hash", sa.String(64), nullable=False),
        sa.Column("browser_hash", sa.String(64), nullable=False),
        sa.Column("nonce", sa.String(64), nullable=False),
        sa.Column("code_verifier", sa.String(128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("state_hash"),
    )
    op.create_index("ix_oauth_attempts_expires_at", "oauth_attempts", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_oauth_attempts_expires_at", table_name="oauth_attempts")
    op.drop_table("oauth_attempts")
