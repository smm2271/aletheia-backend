import argparse
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from database import create_database_engine
from models import User


def set_admin(engine, user_id: uuid.UUID, enabled: bool) -> None:
    with Session(engine) as session:
        user = session.scalar(select(User).where(User.id == user_id).with_for_update())
        if user is None:
            raise ValueError("User not found; complete Google login first")
        if enabled and user.disabled_at is not None:
            raise ValueError("Cannot grant administrator access to a disabled user")
        user.is_admin = enabled
        session.commit()


def main() -> None:
    parser = argparse.ArgumentParser(description="Grant or revoke admin access for an existing Aletheia User UUID")
    parser.add_argument("--user-id", required=True, type=uuid.UUID)
    parser.add_argument("--revoke", action="store_true")
    args = parser.parse_args()
    engine = create_database_engine()
    try:
        set_admin(engine, args.user_id, not args.revoke)
    except ValueError as error:
        parser.exit(1, str(error) + "\n")
    finally:
        engine.dispose()
    print("Administrator access " + ("revoked" if args.revoke else "granted"))


if __name__ == "__main__":
    main()
