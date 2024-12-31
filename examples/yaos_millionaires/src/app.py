"""app module."""

import base64
import json
import os
import struct
from http import HTTPStatus
from pathlib import Path
from typing import List, Optional

from cenclave_lib_crypto.seal_box import seal, unseal
from fastapi import FastAPI, Request, Response
from pydantic import BaseModel

import globs

app = FastAPI()

CONFIG = json.loads((Path(__file__).parent / "config.json").read_text(encoding="utf-8"))

ENCLAVE_SK: bytes = Path(os.environ["ENCLAVE_SK_PATH"]).read_bytes()


class PushItemReq(BaseModel):
    """Item request from /push endpoint."""

    pk: str
    data: str


class RichestItemReq(BaseModel):
    """Item request from /richest endpoint."""

    recipient_pk: str


class ParticipantsItemResp(BaseModel):
    """Item response from /participants endpoint."""

    participants: List[str]


class RichestItemResp(BaseModel):
    """Item response from /richest endpoint."""

    max: Optional[str]


@app.get("/health")
async def health_check(request: Request) -> Response:
    """Health check of the application."""
    if "tls" in request.scope["extensions"]:
        client_cert = request.scope["extensions"]["tls"]["client_cert_chain"]
        print(f"client_cert: {client_cert}")
    return Response(status_code=HTTPStatus.OK)


@app.post("/push")
def push(item: PushItemReq) -> Response:
    """Add a number to the pool."""
    if item.pk not in CONFIG["participants"]:
        return Response(status_code=HTTPStatus.UNAUTHORIZED)

    if item.pk in dict(globs.POOL):
        return Response(status_code=HTTPStatus.CONFLICT)

    n: bytes = unseal(base64.b64decode(item.data), ENCLAVE_SK)
    deser_n, *_ = struct.unpack("<d", n)
    globs.POOL.append((item.pk, deser_n))

    return Response(status_code=HTTPStatus.OK)


@app.get("/participants")
def participants():
    """Get all the public keys of participants"""
    return ParticipantsItemResp(participants=CONFIG["participants"])


@app.post("/richest")
def richest(item: RichestItemReq):
    """Get the richest in pool."""
    if len(globs.POOL) < 1:
        return RichestItemResp(max=None)

    if item.recipient_pk not in CONFIG["participants"]:
        return Response(status_code=HTTPStatus.UNPROCESSABLE_ENTITY)

    raw_recipient_pk: bytes = base64.b64decode(item.recipient_pk)

    (pk, _) = max(globs.POOL, key=lambda t: t[1])

    encrypted_b64_result: str = base64.b64encode(
        seal(base64.b64decode(pk), raw_recipient_pk)
    ).decode("utf-8")

    return RichestItemResp(max=encrypted_b64_result)


@app.delete("/")
def reset() -> Response:
    """Reset the current pool."""
    globs.POOL = []

    return Response(status_code=HTTPStatus.OK)
