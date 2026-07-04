"""Local web dashboard — a NextDNS-style UI over the query log (Cognis-branded).

Pure stdlib http.server. Serves a self-contained page (inline CSS, no external
assets) that shows block rate, category breakdown, top blocked/allowed, and the
recent query stream, auto-refreshing. Read-only view of `qlog`.
"""

from __future__ import annotations

import html
import http.server
import json

from . import qlog

_CSS = """
:root{--bg:#0E0B14;--bg2:#16121F;--panel:#1B1626;--line:#2A2338;--ink:#ECE8F2;
--mut:#8B82A6;--dim:#655B7D;--accent:#8B5CF6;--accent2:#A78BFA;--ok:#3FB950;--bad:#F85149;
--mono:ui-monospace,Consolas,monospace;--sans:"Segoe UI",system-ui,Arial,sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans)}
.wrap{max-width:1000px;margin:0 auto;padding:24px}
header{display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--line);padding-bottom:14px;
font-family:var(--mono);font-size:13px;letter-spacing:.05em}
.glyph{width:14px;height:14px;border-radius:3px;background:var(--accent);box-shadow:0 0 12px rgba(139,92,246,.7)}
.brand{font-weight:700;letter-spacing:.14em;text-transform:uppercase}
.stat{margin-left:auto;color:var(--mut)}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--line);border:1px solid var(--line);
border-radius:12px;overflow:hidden;margin:20px 0}
.kpi{background:var(--bg2);padding:18px}.kpi .v{font-family:var(--mono);font-size:26px;font-weight:700}
.kpi .l{font-size:10px;letter-spacing:.09em;text-transform:uppercase;color:var(--dim);margin-top:4px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:720px){.grid{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.card h2{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--dim);margin:0 0 12px}
.bar{display:flex;align-items:center;gap:8px;margin:5px 0;font-family:var(--mono);font-size:12px}
.bar .track{flex:1;height:8px;background:#0b0910;border-radius:4px;overflow:hidden}
.bar .fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2))}
.bar .n{color:var(--mut);width:52px;text-align:right}
table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12px}
td{padding:4px 6px;border-bottom:1px solid var(--line)}
.tag{padding:2px 7px;border-radius:5px;font-size:10px;letter-spacing:.06em;text-transform:uppercase}
.b{color:var(--bad);border:1px solid var(--bad)}.a{color:var(--ok);border:1px solid var(--ok)}
.foot{margin-top:22px;color:var(--dim);font-family:var(--mono);font-size:12px;border-top:1px solid var(--line);padding-top:14px}
"""


def _bars(d, total):
    out = []
    mx = max(d.values()) if d else 1
    for k, v in list(d.items())[:8]:
        pct = int(100 * v / mx) if mx else 0
        out.append(f'<div class="bar"><span style="width:130px">{html.escape(str(k))}</span>'
                   f'<span class="track"><span class="fill" style="width:{pct}%"></span></span>'
                   f'<span class="n">{v:,}</span></div>')
    return "".join(out) or '<div class="bar" style="color:var(--dim)">no data yet</div>'


def render(rep: dict, recent: list) -> str:
    rows = ""
    for e in reversed(recent[-40:]):
        act = "block" if e.get("action") == "block" else "allow"
        rows += (f'<tr><td style="color:var(--dim)">{html.escape(str(e.get("ts","")))}</td>'
                 f'<td><span class="tag {"b" if act=="block" else "a"}">{act}</span></td>'
                 f'<td style="color:var(--mut)">{html.escape(str(e.get("label","")))}</td>'
                 f'<td>{html.escape(str(e.get("domain","")))}</td></tr>')
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="5"><title>Snare — by Cognis Digital</title>
<style>{_CSS}</style></head><body><div class="wrap">
<header><span class="glyph"></span><span class="brand">Snare</span>
<span style="color:var(--dim)">// by Cognis Digital · local DNS firewall</span>
<span class="stat">auto-refresh 5s</span></header>
<div class="kpis">
 <div class="kpi"><div class="v">{rep['total']:,}</div><div class="l">Queries</div></div>
 <div class="kpi"><div class="v" style="color:var(--bad)">{rep['blocked']:,}</div><div class="l">Blocked</div></div>
 <div class="kpi"><div class="v" style="color:var(--ok)">{rep['allowed']:,}</div><div class="l">Allowed</div></div>
 <div class="kpi"><div class="v">{rep['block_rate']*100:.1f}%</div><div class="l">Block rate</div></div>
</div>
<div class="grid">
 <div class="card"><h2>Traffic by label</h2>{_bars(rep['by_label'], rep['total'])}</div>
 <div class="card"><h2>Blocked by category</h2>{_bars(rep['by_block_category'], rep['blocked'])}</div>
</div>
<div class="grid" style="margin-top:16px">
 <div class="card"><h2>Top blocked</h2>{_bars({d:1 for d in rep['top_blocked']}, 1) if False else ''.join(f'<div class="bar"><span>{html.escape(d)}</span></div>' for d in rep['top_blocked']) or '<div class="bar" style="color:var(--dim)">none</div>'}</div>
 <div class="card"><h2>Top clients</h2>{_bars(rep['top_clients'], rep['total'])}</div>
</div>
<div class="card" style="margin-top:16px"><h2>Recent queries</h2><table>{rows or '<tr><td style="color:var(--dim)">no queries logged yet</td></tr>'}</table></div>
<div class="foot">Snare · self-hosted DNS ad/tracker/scam firewall · © 2026 Cognis Digital LLC · cognis.digital</div>
</div></body></html>"""


def serve(host: str = "127.0.0.1", port: int = 8353, log_path: str = None) -> None:
    lp = log_path or qlog.DEFAULT_LOG

    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            entries = qlog.load(lp)
            if self.path.rstrip("/") == "/api":
                body = json.dumps(qlog.report(entries)).encode()
                ctype = "application/json"
            else:
                body = render(qlog.report(entries), entries).encode()
                ctype = "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = http.server.ThreadingHTTPServer((host, port), _H)
    print(f"[snare] dashboard → http://{host}:{port}  (reading {lp})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
