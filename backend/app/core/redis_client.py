from __future__ import annotations

from redis.asyncio import Redis

from app.settings import settings

_pool: Redis | None = None


def get_redis() -> Redis:
    global _pool
    if _pool is None:
        _pool = Redis.from_url(settings.redis_url, decode_responses=False)
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.aclose()
        _pool = None
