"""Minimal DNS wire-format parsing/building (stdlib only).

Enough to run a filtering resolver: read the question from a query, and craft a
sinkhole response (A -> 0.0.0.0) or a NODATA response for blocked names. Question
sections don't use name compression, so parsing stays simple.
"""

from __future__ import annotations

import socket
import struct

TYPE_A = 1
TYPE_AAAA = 28
QTYPE_NAMES = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS", 6: "SOA", 12: "PTR", 33: "SRV", 65: "HTTPS"}


def parse_question(data: bytes):
    """Return (qname, qtype, question_end_offset). qname is lowercase, no trailing dot."""
    if len(data) < 12:
        raise ValueError("short DNS packet")
    i = 12
    labels = []
    while i < len(data):
        ln = data[i]
        i += 1
        if ln == 0:
            break
        if ln & 0xC0:  # compression pointer (not expected in a question)
            i += 1
            break
        labels.append(data[i:i + ln].decode("ascii", "replace"))
        i += ln
    qtype = struct.unpack(">H", data[i:i + 2])[0] if i + 2 <= len(data) else 0
    i += 4  # qtype(2) + qclass(2)
    return ".".join(labels).lower().rstrip("."), qtype, i


def txn_id(data: bytes) -> int:
    return struct.unpack(">H", data[:2])[0]


def build_query(name: str, qtype: int = TYPE_A, tid: int = 0x1234) -> bytes:
    """Build a standard recursive DNS query (for tests / clients)."""
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        q += bytes([len(label)]) + label.encode("ascii")
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    return q


def answer_ip(resp: bytes):
    """Best-effort extract the first A-record IP from a response (for tests)."""
    ancount = struct.unpack(">H", resp[6:8])[0]
    if ancount < 1:
        return None
    # skip header + question
    _, _, qend = parse_question(resp)
    i = qend
    # first answer: name(2 ptr) type(2) class(2) ttl(4) rdlen(2) rdata
    if resp[i] & 0xC0:
        i += 2
    else:
        while resp[i] != 0:
            i += resp[i] + 1
        i += 1
    atype = struct.unpack(">H", resp[i:i + 2])[0]
    i += 8  # type(2)+class(2)+ttl(4)
    rdlen = struct.unpack(">H", resp[i:i + 2])[0]
    i += 2
    if atype == TYPE_A and rdlen == 4:
        return socket.inet_ntoa(resp[i:i + 4])
    return None


def build_response(query: bytes, qend: int, qtype: int, sinkhole: str = "0.0.0.0", ttl: int = 60) -> bytes:
    """Craft a blocked response: A -> sinkhole IP; otherwise NODATA (NOERROR, 0 answers)."""
    tid = query[:2]
    flags = b"\x81\x80"  # QR=1, RD=1, RA=1, RCODE=0
    question = query[12:qend]
    if qtype == TYPE_A:
        counts = struct.pack(">HHHH", 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack(">HHIH", TYPE_A, 1, ttl, 4) + socket.inet_aton(sinkhole)
        return tid + flags + counts + question + answer
    # NODATA for AAAA / everything else (don't hand out an IP)
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    return tid + flags + counts + question


def forward(query: bytes, upstream: str = "1.1.1.1", port: int = 53, timeout: float = 3.0) -> bytes:
    """Relay a query to an upstream resolver over UDP and return its raw response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(query, (upstream, port))
        data, _ = s.recvfrom(4096)
        return data
    finally:
        s.close()


# Well-known DNS-over-HTTPS endpoints (RFC 8484, application/dns-message).
DOH_ENDPOINTS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google": "https://dns.google/dns-query",
    "quad9": "https://dns.quad9.net/dns-query",
    "adguard": "https://dns.adguard-dns.com/dns-query",
}


def forward_doh(query: bytes, url: str = DOH_ENDPOINTS["cloudflare"], timeout: float = 5.0) -> bytes:
    """Relay a query over DNS-over-HTTPS (encrypted upstream). Body is the raw
    DNS wire message; response is the same."""
    import urllib.request
    req = urllib.request.Request(url, data=query, method="POST", headers={
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
        "User-Agent": "snare/0.3 (+https://cognis.digital)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()
