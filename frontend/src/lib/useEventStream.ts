import { useEffect, useRef, useState } from "react";
import { API, HttpError, type EventItem } from "./api";

export function useEventStream(maxItems: number = 500) {
  const [events, setEvents] = useState<EventItem[]>([]);
  const [connected, setConnected] = useState(false);
  const [authRequired, setAuthRequired] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const retriesRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    let cancelled = false;

    API.fetchEvents({ signal: controller.signal })
      .then((initial) => {
        setEvents(initial.slice(-maxItems));
        setAuthRequired(false);
      })
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        if (err instanceof HttpError && err.status === 401) setAuthRequired(true);
      });

    function connect() {
      if (cancelled) return;
      const ws = new WebSocket(API.wsUrl, API.wsProtocols);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        retriesRef.current = 0;
      };

      ws.onclose = (ev) => {
        setConnected(false);
        if (ev.code === 1008) setAuthRequired(true);
        if (!cancelled) {
          const delay = Math.min(1000 * 2 ** retriesRef.current, 30_000);
          retriesRef.current += 1;
          reconnectTimerRef.current = setTimeout(connect, delay);
        }
      };

      ws.onerror = () => setConnected(false);

      ws.onmessage = (msg) => {
        try {
          const e = JSON.parse(String(msg.data)) as EventItem;
          setEvents((prev) => {
            const next = [...prev, e];
            return next.length > maxItems ? next.slice(next.length - maxItems) : next;
          });
        } catch {
          // ignore malformed frames
        }
      };
    }

    connect();

    return () => {
      cancelled = true;
      controller.abort();
      if (reconnectTimerRef.current !== null) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      try {
        wsRef.current?.close();
      } catch {
        /* ignore */
      }
    };
  }, [maxItems]);

  return { events, connected, authRequired };
}
