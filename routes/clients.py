import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from auth.admin import require_admin
from auth.session import require_same_origin
from models import ClientType, SSOClient
from sso.clients import ClientCreate, ClientPatch, client_profile, new_secret

router = APIRouter(prefix="/api/v1/admin/clients", tags=["SSO Clients"], dependencies=[Depends(require_admin)])


def response(client, secret=None, status=200):
    data = client_profile(client)
    if secret is not None:
        data["client_secret"] = secret
    return JSONResponse(jsonable_encoder(data), status_code=status, headers={"Cache-Control": "no-store"})


def get_client(session, client_id, lock=False):
    query = select(SSOClient).where(SSOClient.client_id == client_id)
    client = session.scalar(query.with_for_update() if lock else query)
    if client is None:
        raise HTTPException(404, "Client not found")
    return client


@router.post("", status_code=201)
def create_client(body: ClientCreate, request: Request):
    require_same_origin(request)
    values = body.model_dump()
    secret = None
    if body.client_type == ClientType.CONFIDENTIAL:
        secret, values["secret_hash"] = new_secret()
    with Session(request.app.state.database_engine) as session:
        client = SSOClient(client_id=secrets.token_urlsafe(24), **values)
        session.add(client)
        session.commit()
        return response(client, secret, 201)


@router.get("")
def list_clients(request: Request, offset: int = 0, limit: int = 50):
    if offset < 0 or not 1 <= limit <= 100:
        raise HTTPException(422, "Invalid pagination")
    with Session(request.app.state.database_engine) as session:
        clients = session.scalars(select(SSOClient).order_by(SSOClient.created_at, SSOClient.client_id).offset(offset).limit(limit)).all()
        return JSONResponse(jsonable_encoder([client_profile(c) for c in clients]), headers={"Cache-Control": "no-store"})


@router.get("/{client_id}")
def read_client(client_id: str, request: Request):
    with Session(request.app.state.database_engine) as session:
        return response(get_client(session, client_id))


@router.patch("/{client_id}")
def update_client(client_id: str, body: ClientPatch, request: Request):
    require_same_origin(request)
    with Session(request.app.state.database_engine) as session:
        client = get_client(session, client_id, lock=True)
        for key, value in body.model_dump(exclude_unset=True).items():
            setattr(client, key, value)
        session.commit()
        return response(client)


@router.post("/{client_id}/rotate-secret")
def rotate_secret(client_id: str, request: Request):
    require_same_origin(request)
    with Session(request.app.state.database_engine) as session:
        client = get_client(session, client_id, lock=True)
        if client.client_type != ClientType.CONFIDENTIAL:
            raise HTTPException(409, "Public clients do not have a secret")
        secret, client.secret_hash = new_secret()
        session.commit()
        return response(client, secret)


@router.delete("/{client_id}", status_code=204)
def delete_client(client_id: str, request: Request):
    require_same_origin(request)
    with Session(request.app.state.database_engine) as session:
        session.delete(get_client(session, client_id, lock=True))
        session.commit()
    return Response(status_code=204, headers={"Cache-Control": "no-store"})
