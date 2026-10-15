from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from fastapi.security import HTTPBearer
from pydantic import BaseModel

from qr.verification import VerificationRequest, VerificationResponse, verify_for_client


class NoStoreRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def no_store(request: Request):
            try:
                response = await handler(request)
            except RequestValidationError:
                # Validation errors can contain the submitted bearer credential.
                response = JSONResponse({"detail": "Invalid verification request"}, status_code=422)
            except HTTPException as error:
                error.headers = {**(error.headers or {}), "Cache-Control": "no-store"}
                raise
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
            return response

        return no_store


class VerificationError(BaseModel):
    detail: str


router = APIRouter(tags=["Static QR verification"], route_class=NoStoreRoute)


@router.post("/api/v1/qr/static/verify", response_model=VerificationResponse,
             dependencies=[Depends(HTTPBearer(auto_error=False))],
             summary="Verify a current static QR credential",
             description=("Requires an SSO Access Token for the configured resource audience with "
                          "qr:static:verify scope and a currently enabled user and client. "
                          "Checks signature and current credential mapping. Does not authorize admission."),
             responses={code: {"model": VerificationError, "description": description} for code, description in (
                 (400, "Invalid QR credential or unsupported query parameters"),
                 (401, "Invalid Access Token or disabled scanner/client"),
                 (403, "Required scope missing or no longer granted to client"),
                 (422, "Invalid request body"), (503, "Verification keys or stores unavailable"))})
async def verify_credential(request: Request, body: VerificationRequest):
    if request.query_params:
        raise HTTPException(400, "Query parameters are unsupported")
    await verify_for_client(request, body.token)
    return VerificationResponse()
