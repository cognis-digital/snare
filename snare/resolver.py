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
                 sinkhole: str = "0.0.0.0", log_path: str = None, forwarder=None,
                 allowlist=None, doh_url: str = None, profiles=None):
        self.blockmap = blockmap or {}
        self.upstream = upstream
        self.sinkhole = sinkhole
        self.log_path = log_path or qlog.DEFAULT_LOG
        self.allowlist = set(allowlist or ())
        self.doh_url = doh_url
        # Per-client profiles (NextDNS-style): {client_ip: {"block_labels":[...], "allow":[...]}}
        self.profiles = profiles or {}
        if forwarder:
            self.forward = forwarder
        elif doh_url:
            self.forward = lambda q, up: dnswire.forward_doh(q, doh_url)
        else:
            self.forward = dnswire.forward

    def _allowlisted(self, domain: str) -> bool:
        if domain in self.allowlist:
            return True
        parts = domain.split(".")
        return any(".".join(parts[k:]) in self.allowlist for k in range(1, len(parts)))

    def handle_query(self, data: bytes, client_ip: str = "?") -> bytes:
        try:
            qname, qtype, qend = dnswire.parse_question(data)
        except Exception:
            return None
        cls = labels.classify(qname, self.blockmap)
        prof = self.profiles.get(client_ip) or self.profiles.get("*") or {}
        prof_allow = set(prof.get("allow", ()))
        prof_block_labels = set(prof.get("block_labels", ()))
        allowed_override = (cls["blocked"] and self._allowlisted(qname)) or (qname in prof_allow)
        blocked = cls["blocked"] and not allowed_override
        # per-client policy can additionally block a whole label (e.g. kids device blocks "social")
        if not blocked and not allowed_override and cls["label"] in prof_block_labels:
            blocked = True
        entry = {
            "ts": datetime.datetime.now().isoformat(timespec="seconds"),
            "client": client_ip, "domain": qname,
            "qtype": dnswire.QTYPE_NAMES.get(qtype, str(qtype)),
            "action": "block" if blocked else ("allow-listed" if allowed_override else "allow"),
            "label": cls["label"], "block_category": cls["block_category"],
        }
        if blocked:
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
