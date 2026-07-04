"""Filtering DNS resolver — the AdGuard/NextDNS-style core.

Listens for DNS queries, blocks domains on the compiled list (sinkhole / NODATA),
forwards everything else to an upstream resolver, and logs + labels every query
so `snare report` can study the traffic. Pure stdlib (socketserver + dnswire).
"""

from __future__ import annotations

import datetime
import socketserver

from . import dnswire, labels, qlog


class SnareResolver:
    def __init__(self, blockmap: dict, upstream: str = "1.1.1.1",
                 sinkhole: str = "0.0.0.0", log_path: str = None, forwarder=None):
        self.blockmap = blockmap or {}
        self.upstream = upstream
        self.sinkhole = sinkhole
        self.log_path = log_path or qlog.DEFAULT_LOG
        self.forward = forwarder or dnswire.forward

    def handle_query(self, data: bytes, client_ip: str = "?") -> bytes:
        try:
            qname, qtype, qend = dnswire.parse_question(data)
        except Exception:
            return None
        cls = labels.classify(qname, self.blockmap)
        entry = {
            "ts": datetime.datetime.now().isoformat(timespec="seconds"),
            "client": client_ip, "domain": qname,
            "qtype": dnswire.QTYPE_NAMES.get(qtype, str(qtype)),
            "action": "block" if cls["blocked"] else "allow",
            "label": cls["label"], "block_category": cls["block_category"],
        }
        if cls["blocked"]:
            resp = dnswire.build_response(data, qend, qtype, self.sinkhole)
        else:
            try:
                resp = self.forward(data, self.upstream)
            except Exception:
                resp = dnswire.build_response(data, qend, qtype, self.sinkhole)
                entry["action"] = "allow-upstream-failed"
        qlog.append(entry, self.log_path)
        return resp


def serve(blockmap: dict, host: str = "127.0.0.1", port: int = 5353, **kw) -> None:
    resolver = SnareResolver(blockmap, **kw)

    class _Handler(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            resp = resolver.handle_query(data, self.client_address[0])
            if resp:
                sock.sendto(resp, self.client_address)

    srv = socketserver.ThreadingUDPServer((host, port), _Handler)
    print(f"[snare] resolver up on {host}:{port} → upstream {resolver.upstream} · "
          f"{len(resolver.blockmap):,} domains blocked · log {resolver.log_path}")
    print("[snare] point your OS/browser DNS at this address. Ctrl-C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[snare] stopped")
        srv.shutdown()
