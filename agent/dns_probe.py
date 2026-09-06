# -*- coding: utf-8 -*-
"""Small, dependency-free DNS wire probe used by DNS Rescue.

Only a fixed canary name is ever queried.  Results intentionally contain no
question name, packet payload, credentials, or upstream URL so they are safe
for the durable incident journal.
"""
import os
import socket
import struct
import time

CANARY_NAME = "example.com"


class DNSProbeError(Exception):
    pass


def build_query(txid=None, name=CANARY_NAME):
    if name != CANARY_NAME:
        raise DNSProbeError("only the fixed rescue canary is permitted")
    txid = int.from_bytes(os.urandom(2), "big") if txid is None else int(txid)
    labels = name.split(".")
    question = b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels)
    return txid, struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question + b"\0\0\1\0\1"


def parse_response(data, txid):
    if not isinstance(data, (bytes, bytearray)) or len(data) < 12:
        raise DNSProbeError("short DNS response")
    rid, flags, qd, answers, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if rid != txid:
        raise DNSProbeError("DNS transaction id mismatch")
    if not flags & 0x8000:
        raise DNSProbeError("not a DNS response")
    rcode = flags & 0xF
    return {"ok": rcode == 0 and qd == 1 and answers > 0,
            "rcode": rcode, "answers": answers, "bytes": len(data)}


def probe(host, port, transport="udp", timeout=3.0):
    """Probe a local listener over UDP or TCP; return bounded metadata only."""
    txid, packet = build_query()
    started = time.monotonic()
    family = socket.AF_INET6 if ":" in str(host) else socket.AF_INET
    sock_type = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    if transport not in ("udp", "tcp"):
        raise DNSProbeError("unsupported DNS transport")
    try:
        with socket.socket(family, sock_type) as sock:
            sock.settimeout(float(timeout))
            if transport == "udp":
                sock.sendto(packet, (host, int(port)))
                data, _peer = sock.recvfrom(4096)
            else:
                sock.connect((host, int(port)))
                sock.sendall(struct.pack("!H", len(packet)) + packet)
                header = sock.recv(2)
                if len(header) != 2:
                    raise DNSProbeError("short TCP DNS length")
                remaining = struct.unpack("!H", header)[0]
                chunks = []
                while remaining:
                    chunk = sock.recv(remaining)
                    if not chunk:
                        raise DNSProbeError("short TCP DNS response")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                data = b"".join(chunks)
        result = parse_response(data, txid)
        result["latency_ms"] = max(0, int((time.monotonic() - started) * 1000))
        result["transport"] = transport
        return result
    except (OSError, ValueError, DNSProbeError) as error:
        return {"ok": False, "rcode": None, "answers": 0, "bytes": 0,
                "latency_ms": max(0, int((time.monotonic() - started) * 1000)),
                "transport": transport, "error_kind": type(error).__name__}
