from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel

from app.core.sealed import unseal_to_dict


class SealedBody(BaseModel):
    sealed: dict


def unsealed_dict(body: SealedBody, aad: bytes) -> dict[str, Any]:
    raw = unseal_to_dict(body.sealed, aad=aad)
    if not raw:
        raise HTTPException(
            status_code=400,
            detail="Unable to unseal payload (check transport key/flag).",
        )
    return raw
