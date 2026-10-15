from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPBearer

from student.eligibility import EligibilityResponse, current_eligibility

router = APIRouter(tags=["Student eligibility"])


@router.get("/api/v1/student/eligibility", response_model=EligibilityResponse,
            dependencies=[Depends(HTTPBearer(auto_error=False))],
            responses={401: {"description": "Invalid or missing Access Token"},
                       403: {"description": "Scope or client authorization missing"},
                       503: {"description": "Signing keys unavailable"}})
async def eligibility(request: Request, response: Response):
    response.headers["Cache-Control"] = "no-store"
    try:
        if request.query_params:
            raise HTTPException(400, "This endpoint only supports the current token subject")
        return await current_eligibility(request)
    except HTTPException as error:
        error.headers = {**(error.headers or {}), "Cache-Control": "no-store"}
        raise
