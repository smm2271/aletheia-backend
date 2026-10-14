"""Separate provider identities from the stable Aletheia user.

Revision ID: 20261014_0002
Revises: 20260911_0001
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20261014_0002"
down_revision = "20260911_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "external_identities",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider", sa.String(255), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_external_identities"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("provider", "subject", name="uq_external_identities_provider_subject"),
    )
    op.create_index("ix_external_identities_user_id", "external_identities", ["user_id"])
    op.execute("INSERT INTO external_identities (user_id, provider, subject) SELECT id, 'google', google_sub FROM users")
    op.drop_constraint("uq_users_google_sub", "users", type_="unique")
    op.drop_column("users", "google_sub")


def downgrade() -> None:
    # The old schema requires exactly one Google identity per user. Refuse a
    # lossy rollback if new providers or multiple Google accounts were added.
    op.execute("""
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM external_identities WHERE provider <> 'google')
               OR EXISTS (
                   SELECT u.id FROM users u
                   LEFT JOIN external_identities e ON e.user_id = u.id AND e.provider = 'google'
                   GROUP BY u.id HAVING count(e.id) <> 1
               ) THEN
                RAISE EXCEPTION 'Cannot downgrade: identities cannot be represented by users.google_sub';
            END IF;
        END $$;
    """)
    op.add_column("users", sa.Column("google_sub", sa.String(255), nullable=True))
    op.execute("UPDATE users u SET google_sub = e.subject FROM external_identities e WHERE e.user_id = u.id AND e.provider = 'google'")
    op.alter_column("users", "google_sub", nullable=False)
    op.create_unique_constraint("uq_users_google_sub", "users", ["google_sub"])
    op.drop_index("ix_external_identities_user_id", table_name="external_identities")
    op.drop_table("external_identities")
