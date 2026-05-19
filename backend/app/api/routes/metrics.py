from __future__ import annotations

import os
import platform
import socket

from fastapi import APIRouter, Depends

from app.core.event_bus import EventBus
from app.core.redis_client import get_redis
from app.settings import settings

router = APIRouter()


def _detect_container() -> bool:
    if os.path.exists("/.dockerenv"):
        return True
    try:
        with open("/proc/1/cgroup") as f:
            cgroup = f.read()
        if any(k in cgroup for k in ("docker", "kubepods", "containerd")):
            return True
    except Exception:
        pass
    return False


_platform_cache: dict[tuple[str, bool], dict] = {}


def _platform_info() -> dict:
    from app.settings import settings as _settings

    cache_key = (_settings.environment.strip().lower(), _settings.is_local)
    if cache_key in _platform_cache:
        return _platform_cache[cache_key]

    plat = platform.system().lower()
    is_local = _settings.is_local
    info: dict = {
        "os": plat,
        "os_pretty": platform.platform() if is_local else plat,
        "arch": platform.machine() if is_local else "redacted",
        "hostname": socket.gethostname() if is_local else "redacted",
        "in_container": _detect_container(),
        "kernel_version": platform.release() if is_local else "redacted",
        "python_version": platform.python_version() if is_local else "redacted",
    }
    if plat == "linux":
        info["kernel_scanner_available"] = True
        info["scanner_hint"] = (
            "Full kernel protection available — run kernel/scanner.py on this host."
        )
    elif plat == "darwin":
        info["kernel_scanner_available"] = True
        info["scanner_hint"] = (
            "macOS security scanner available — run macos/scanner.py on this host."
        )
    elif plat == "windows":
        info["kernel_scanner_available"] = True
        info["scanner_hint"] = (
            "Windows security scanner available — run windows\\scanner.py on this host."
        )
    else:
        info["kernel_scanner_available"] = False
        info["scanner_hint"] = "No scanner available for this platform."
    _platform_cache[cache_key] = info
    return info


@router.get("/health")
async def health(redis=Depends(get_redis)) -> dict:
    try:
        await redis.ping()
        redis_status = "connected"
        status = "ok"
    except Exception:
        redis_status = "unreachable"
        status = "degraded"

    if not settings.is_local:
        return {"status": status}

    return {"status": status, "redis": redis_status, "platform": _platform_info()}


@router.get("/metrics")
async def metrics(redis=Depends(get_redis)) -> dict:
    bus = EventBus(redis)
    events = await bus.consume_latest(count=1000)
    total = len(events)
    by_type: dict[str, int] = {}
    for e in events:
        by_type[e.type] = by_type.get(e.type, 0) + 1

    return {
        "events_total_recent": total,
        "events_by_type_recent": by_type,
    }
