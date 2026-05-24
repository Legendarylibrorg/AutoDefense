import { useEffect, useRef, useState } from "react";
import { API, type EventItem } from "./api";

export function useEventStream(maxItems: number = 500) {
  const [events, setEvents] = useState<EventItem[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const retriesRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    let cancelled = false;

    API.fetchEvents()
      .then((initial) => {
        if (cancelled) return;
        setEvents(initial.slice(-maxItems));
      })
      .catch(() => {});

    function connect() {
      if (cancelled) return;
      const ws = new WebSocket(API.wsUrl, API.wsProtocols);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        retriesRef.current = 0;
      };

      ws.onclose = () => {
        setConnected(false);
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

  return { events, connected };
}
