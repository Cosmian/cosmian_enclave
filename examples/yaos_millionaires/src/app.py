"""app module."""

import base64
import json
import logging
import os
from http import HTTPStatus
from pathlib import Path
from typing import Any, Optional

import globs
from cenclave_lib_crypto.seal_box import seal
from flask import Flask, Response, request
from flask.logging import create_logger

app = Flask(__name__)

LOG = create_logger(app)

logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.DEBUG)

SECRETS = json.loads(Path(os.getenv("SECRETS_PATH")).read_text(encoding="utf-8"))


@app.get("/health")
def health_check():
    """Health check of the application."""
    return Response(response="OK", status=HTTPStatus.OK)


@app.post("/")
def push():
    """Add a number to the pool."""
    data: Optional[Any] = request.get_json(silent=True)

    if data is None or not isinstance(data, dict):
        LOG.error("TypeError with data: '%s'", data)
        return Response(status=HTTPStatus.UNPROCESSABLE_ENTITY)

    n: Optional[float] = data.get("n")
    pk: Optional[str] = data.get("pk")

    if n is None or not isinstance(n, (float, int)):
        LOG.error("TypeError with data content: '%s' (%s)", n, type(n))
        return Response(status=HTTPStatus.UNPROCESSABLE_ENTITY)

    if pk is None or not isinstance(pk, str):
        LOG.error("TypeError with data content: '%s' (%s)", pk, type(pk))
        return Response(status=HTTPStatus.UNPROCESSABLE_ENTITY)

    if pk not in SECRETS["participants"]:
        LOG.error(
            "The public key provided is not in the participants: '%s' (%s)",
            pk,
            SECRETS["participants"],
        )
        return Response(status=HTTPStatus.UNPROCESSABLE_ENTITY)

    globs.POOL.append((pk, n))

    LOG.info("Successfully added (%s, %s)", n, pk)
    return Response(status=HTTPStatus.OK)


@app.get("/participants")
def participants():
    """Get all the public keys of participants"""
    if "participants" not in SECRETS:
        LOG.error("no participants found")
        return {"participants": None}

    return {"participants": SECRETS["participants"]}


@app.post("/richest")
def richest():
    """Get the current max in pool."""
    if len(globs.POOL) < 1:
        LOG.error("need more than 1 value to compute the max")
        return {"max": None}

    if "participants" not in SECRETS:
        LOG.error("no participants found")
        return Response(status=HTTPStatus.UNPROCESSABLE_ENTITY)

    data: Optional[Any] = request.get_json(silent=True)

    if data is None or not isinstance(data, dict):
        LOG.error("TypeError with data: '%s'", data)
        return Response(status=HTTPStatus.UNPROCESSABLE_ENTITY)

    recipient_pk: Optional[str] = data.get("recipient_pk")

    if recipient_pk is None or not isinstance(recipient_pk, str):
        LOG.error("TypeError with data content: '%s' (%s)", pk, type(pk))
        return Response(status=HTTPStatus.UNPROCESSABLE_ENTITY)

    if recipient_pk not in SECRETS["participants"]:
        LOG.error(
            "The public key provided is not in the participants: '%s' (%s)",
            recipient_pk,
            SECRETS["participants"],
        )
        return Response(status=HTTPStatus.UNPROCESSABLE_ENTITY)

    raw_recipient_pk: bytes = base64.b64decode(recipient_pk)

    (pk, _) = max(globs.POOL, key=lambda t: t[1])

    encrypted_b64_result: bytes = base64.b64encode(
        seal(base64.b64decode(pk), raw_recipient_pk)
    ).decode("utf-8")

    return {"max": encrypted_b64_result}


@app.delete("/")
def reset():
    """Reset the current pool."""
    globs.POOL = []

    LOG.info("Reset successfully")

    return Response(status=HTTPStatus.OK)
