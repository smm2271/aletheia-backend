from fastapi import FastAPI

from routes import router


app = FastAPI(title="Aletheia API")
app.include_router(router)


@app.get("/")
async def root() -> dict[str, str]:
    return {"message": "Aletheia API is running"}
