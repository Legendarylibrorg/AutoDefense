"""Parse ``Sec-WebSocket-Protocol`` ``auth.<token>`` used by the dashboard WebSocket."""


def parse_ws_auth_protocol(header_value: str | None) -> tuple[str | None, str]:
    """
    Return ``(subprotocol_value, token)`` for ``auth.<secret>``.
    ``subprotocol_value`` is the full ``auth....`` string for ``accept(subprotocol=...)``.
    """
    for proto in (header_value or "").split(","):
        p = proto.strip()
        if p.startswith("auth."):
            return p, p.removeprefix("auth.")
    return None, ""
