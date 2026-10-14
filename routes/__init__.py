from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError


router = APIRouter()


@router.get("/health", tags=["Health"])
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/db", tags=["Health"])
def database_health_check(request: Request) -> dict[str, str]:
    try:
        with request.app.state.database_engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        raise HTTPException(status_code=503, detail="Database unavailable") from None
    return {"status": "ok"}
