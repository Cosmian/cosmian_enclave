"""app module."""

import base64
import json
import os
import struct
from http import HTTPStatus
from pathlib import Path
from typing import Any, Optional

from cenclave_lib_crypto.seal_box import seal, unseal
from flask import Flask, Response, jsonify, request

import globs

app = Flask(__name__)

CONFIG = json.loads((Path(__file__).parent / "config.json").read_text(encoding="utf-8"))

ENCLAVE_SK: bytes = Path(os.environ["ENCLAVE_SK_PATH"]).read_bytes()


@app.get("/health")
def health_check() -> Response:
    """Health check of the application."""
    return Response(response="OK", status=HTTPStatus.OK)


@app.post("/")
def push() -> Response:
    """Add a number to the pool."""
    content: Optional[Any] = request.get_json(silent=True)

    if content is None or not isinstance(content, dict):
        app.logger.error("TypeError with data: '%s'", content)
        return Response(status=HTTPStatus.UNPROCESSABLE_ENTITY)

    data: Optional[Any] = content.get("data")
    pk: Optional[str] = content.get("pk")

    if data is None or not isinstance(data, dict):
        app.logger.error("TypeError with data content: '%s' (%s)", data, type(data))
        return Response(status=HTTPStatus.UNPROCESSABLE_ENTITY)

    if pk is None or not isinstance(pk, str):
        app.logger.error("TypeError with data content: '%s' (%s)", pk, type(pk))
        return Response(status=HTTPStatus.UNPROCESSABLE_ENTITY)

    if pk not in CONFIG["participants"]:
        app.logger.error(
            "The public key provided is not in the participants: '%s' (%s)",
            pk,
            CONFIG["participants"],
        )
        return Response(status=HTTPStatus.UNPROCESSABLE_ENTITY)

    if pk in dict(globs.POOL):
        app.logger.error("Public key already pushed data")
        return Response(status=HTTPStatus.CONFLICT)

    n: bytes = unseal(base64.b64decode(data["n"]), ENCLAVE_SK)

    deser_n, *_ = struct.unpack("<d", n)
    globs.POOL.append((pk, deser_n))

    app.logger.info("Successfully added (%s, %s)", deser_n, pk)
    return Response(status=HTTPStatus.OK)


@app.get("/participants")
def participants() -> Response:
    """Get all the public keys of participants"""
    return jsonify(CONFIG)


@app.post("/richest")
def richest():
    """Get the current max in pool."""
    if len(globs.POOL) < 1:
        app.logger.error("need more than 1 value to compute the max")
        return {"max": None}

    data: Optional[Any] = request.get_json(silent=True)

    if data is None or not isinstance(data, dict):
        app.logger.error("TypeError with data: '%s'", data)
        return Response(status=HTTPStatus.UNPROCESSABLE_ENTITY)

    recipient_pk: Optional[str] = data.get("recipient_pk")

    if recipient_pk is None or not isinstance(recipient_pk, str):
        app.logger.error(
            "TypeError with data content: '%s' (%s)", recipient_pk, type(recipient_pk)
        )
        return Response(status=HTTPStatus.UNPROCESSABLE_ENTITY)

    if recipient_pk not in CONFIG["participants"]:
        app.logger.error(
            "The public key provided is not in the participants: '%s' (%s)",
            recipient_pk,
            CONFIG["participants"],
        )
        return Response(status=HTTPStatus.UNPROCESSABLE_ENTITY)

    raw_recipient_pk: bytes = base64.b64decode(recipient_pk)

    (pk, _) = max(globs.POOL, key=lambda t: t[1])

    encrypted_b64_result: str = base64.b64encode(
        seal(base64.b64decode(pk), raw_recipient_pk)
    ).decode("utf-8")

    return jsonify({"max": encrypted_b64_result})


@app.delete("/")
def reset():
    """Reset the current pool."""
    globs.POOL = []

    app.logger.info("Reset successfully")

    return Response(status=HTTPStatus.OK)
