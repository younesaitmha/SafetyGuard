from __future__ import annotations

import logging
import time

import httpx
from fastapi import HTTPException, status
from jose import jwt
from jose.exceptions import JWTError

from .config import settings
from .models import SecurityContext

logger = logging.getLogger("identity")

_jwks_cache: dict | None = None
_jwks_cache_time: float = 0.0
_JWKS_CACHE_TTL: float = 3600.0


async def _fetch_jwks() -> dict:
    """Fetch and cache JWKS from the configured identity provider."""
    global _jwks_cache, _jwks_cache_time
    now = time.time()
    if _jwks_cache is not None and (now - _jwks_cache_time) < _JWKS_CACHE_TTL:
        return _jwks_cache
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(settings.jwks_url)
        resp.raise_for_status()
        data = resp.json()
    _jwks_cache = data
    _jwks_cache_time = now
    logger.info("jwks_cache_refreshed url=%s", settings.jwks_url)
    return data


async def build_security_context(authorization: str | None) -> SecurityContext:
    if settings.require_bearer_token and not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header",
        )

    if not authorization:
        return SecurityContext(
            subject="anonymous",
            user_id="anonymous",
            tenant_id=None,
            roles=[],
            permissions=[],
            auth_level="anonymous",
            step_up_authenticated=False,
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            claims={},
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization scheme",
        )

    token = authorization.split(" ", 1)[1].strip()

    if settings.dev_mode:
        # Development mode: accept any token
        try:
            claims = jwt.get_unverified_claims(token)
        except JWTError:
            # If not a JWT, create a default dev context
            claims = {
                "sub": "dev-user",
                "user_id": "dev-user",
                "tenant_id": "dev-tenant",
                "roles": ["admin"],
                "permissions": ["llm:chat", "llm:read", "llm:write", "*"],
                "auth_level": "standard",
            }
        # Ensure dev mode users have required permissions
        if "permissions" not in claims or not claims["permissions"]:
            claims["permissions"] = ["llm:chat", "llm:read", "llm:write", "*"]
        elif "llm:chat" not in claims["permissions"] and "*" not in claims["permissions"]:
            claims["permissions"].append("llm:chat")
    elif settings.jwt_verify_signature:
        try:
            jwks = await _fetch_jwks()
            claims = jwt.decode(
                token,
                jwks,
                algorithms=settings.jwt_algorithms.split(","),
                audience=settings.jwt_audience,
                issuer=settings.jwt_issuer,
                options={"verify_exp": True},
            )
        except Exception as exc:
            logger.warning("jwt_verification_failed type=%s", type(exc).__name__)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token verification failed",
            )
    else:
        try:
            claims = jwt.get_unverified_claims(token)
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )

    subject = claims.get("sub")
    user_id = claims.get("user_id") or subject
    tenant_id = claims.get("tenant_id")
    roles = claims.get("roles", [])
    permissions = claims.get("permissions", [])
    auth_level = claims.get("auth_level", "standard")
    step_up_authenticated = bool(claims.get("step_up_authenticated", False))
    issuer = claims.get("iss", settings.jwt_issuer)
    audience = claims.get("aud", settings.jwt_audience)

    if not subject or not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required token claims",
        )

    return SecurityContext(
        subject=subject,
        user_id=user_id,
        tenant_id=tenant_id,
        roles=roles if isinstance(roles, list) else [],
        permissions=permissions if isinstance(permissions, list) else [],
        auth_level=auth_level,
        step_up_authenticated=step_up_authenticated,
        issuer=issuer,
        audience=audience,
        claims=claims,
    )
