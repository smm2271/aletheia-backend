"""Bind OAuth login to a browser authorization continuation."""
from alembic import op
import sqlalchemy as sa

revision = "20261015_0006"
down_revision = "20261015_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("oauth_attempts", sa.Column("continuation_hash", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("oauth_attempts", "continuation_hash")
