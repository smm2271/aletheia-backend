"""Create SSO clients and hashed credentials."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20261015_0005"
down_revision = "20261015_0004"
branch_labels = None
depends_on = None

client_type = postgresql.ENUM("public", "confidential", name="sso_client_type", create_type=False)
trust_level = postgresql.ENUM("first_party", "external", name="sso_trust_level", create_type=False)


def upgrade() -> None:
    client_type.create(op.get_bind(), checkfirst=True)
    trust_level.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "sso_clients",
        sa.Column("client_id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("client_type", client_type, nullable=False),
        sa.Column("trust_level", trust_level, nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("redirect_uris", postgresql.JSONB(), nullable=False),
        sa.Column("allowed_scopes", postgresql.JSONB(), nullable=False),
        sa.Column("secret_hash", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("(client_type = 'public' AND secret_hash IS NULL) OR (client_type = 'confidential' AND secret_hash IS NOT NULL)", name="ck_sso_clients_secret_type"),
    )


def downgrade() -> None:
    op.drop_table("sso_clients")
    trust_level.drop(op.get_bind(), checkfirst=True)
    client_type.drop(op.get_bind(), checkfirst=True)
