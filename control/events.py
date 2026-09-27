"""Eventos en vivo para el panel (SSE)."""
import json
import queue
import threading


_SUBS_LOCK = threading.Lock()


_SUBSCRIBERS = []  # (grupo o None, queue)


def publish(evt, data, group_id=None):
    msg = f"event: {evt}\ndata: {json.dumps(data)}\n\n"
    with _SUBS_LOCK:
        for scope, q in _SUBSCRIBERS:
            if scope is None or scope == group_id or group_id is None:
                try:
                    q.put_nowait(msg)
                except queue.Full:
                    pass


def sse(h, query):
    # EventSource no manda headers, por eso ?token=
    ok, scope = h.admin_scope(token=(query.get("token") or [None])[0])
    if not ok:
        return
    q = queue.Queue(maxsize=256)
    with _SUBS_LOCK:
        _SUBSCRIBERS.append((scope, q))
    try:
        h.send_response(200)
        h.send_header("Content-Type", "text/event-stream")
        h.send_header("Cache-Control", "no-cache")
        h.send_header("Connection", "keep-alive")
        h.end_headers()
        h.wfile.write(b": connected\n\n")
        h.wfile.flush()
        while True:
            try:
                msg = q.get(timeout=20)
            except queue.Empty:
                msg = ": ping\n\n"
            h.wfile.write(msg.encode("utf-8"))
            h.wfile.flush()
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        with _SUBS_LOCK:
            try:
                _SUBSCRIBERS.remove((scope, q))
            except ValueError:
                pass
