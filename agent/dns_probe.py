# -*- coding: utf-8 -*-
"""Small, dependency-free DNS wire probe used by DNS Rescue.

Only the built-in test name or a caller-supplied, validated one-shot owned
canary is queried. Results contain no question name, packet payload,
credentials, or upstream URL, so the durable incident journal stays bounded.
"""
import os
import socket
import struct
import time

CANARY_NAME = "example.com"


class DNSProbeError(Exception):
    pass


def _question_wire(name=CANARY_NAME):
    labels = name.split(".")
    return b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels) + b"\0\0\1\0\1"


def _validate_name(name):
    value = str(name or "").strip().lower().rstrip(".")
    labels = value.split(".")
    if (not value or len(value) > 253 or any(
            not label or len(label) > 63 or not label.isascii()
            or not label.replace("-", "a").isalnum()
            or label.startswith("-") or label.endswith("-") for label in labels)):
        raise DNSProbeError("invalid DNS canary name")
    return value


def _build_query(txid, name):
    name = _validate_name(name)
    txid = int.from_bytes(os.urandom(2), "big") if txid is None else int(txid)
    return txid, struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + _question_wire(name)


def build_query(txid=None, name=CANARY_NAME):
    if name != CANARY_NAME:
        raise DNSProbeError("only the fixed public test canary is permitted")
    return _build_query(txid, name)


def _read_name(data, offset):
    labels, seen = [], set()
    next_offset = None
    for _unused in range(128):
        if offset >= len(data):
            raise DNSProbeError("truncated DNS name")
        size = data[offset]
        if size & 0xC0 == 0xC0:
            if offset + 2 > len(data):
                raise DNSProbeError("truncated DNS name pointer")
            pointer = ((size & 0x3F) << 8) | data[offset + 1]
            if pointer >= len(data) or pointer in seen:
                raise DNSProbeError("invalid DNS name pointer")
            seen.add(pointer)
            if next_offset is None:
                next_offset = offset + 2
            offset = pointer
            continue
        if size & 0xC0 or size > 63:
            raise DNSProbeError("invalid DNS name label")
        offset += 1
        if size == 0:
            return ".".join(labels).lower(), (next_offset or offset)
        if offset + size > len(data):
            raise DNSProbeError("truncated DNS name label")
        try:
            labels.append(bytes(data[offset:offset + size]).decode("ascii"))
        except UnicodeDecodeError as error:
            raise DNSProbeError("non-ASCII DNS name") from error
        offset += size
    raise DNSProbeError("DNS name compression limit exceeded")


def parse_response(data, txid, name=CANARY_NAME, expected_ipv4=None):
    name = _validate_name(name)
    if not isinstance(data, (bytes, bytearray)) or len(data) < 12:
        raise DNSProbeError("short DNS response")
    if len(data) > 4096:
        raise DNSProbeError("oversized DNS response")
    rid, flags, qd, answers, ns_count, ar_count = struct.unpack("!HHHHHH", data[:12])
    if rid != txid:
        raise DNSProbeError("DNS transaction id mismatch")
    if not flags & 0x8000:
        raise DNSProbeError("not a DNS response")
    if flags & 0x0200:
        raise DNSProbeError("truncated DNS response")
    if ((flags >> 11) & 0xF) != 0:
        raise DNSProbeError("unexpected DNS opcode")
    question = _question_wire(name)
    if qd != 1 or data[12:12 + len(question)] != question:
        raise DNSProbeError("DNS response question mismatch")
    offset = 12 + len(question)
    if answers + ns_count + ar_count > 128:
        raise DNSProbeError("too many DNS records")
    valid_a = 0
    expected_wire = (socket.inet_aton(str(expected_ipv4))
                     if expected_ipv4 is not None else None)
    for record_index in range(answers + ns_count + ar_count):
        owner_name, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            raise DNSProbeError("truncated DNS answer header")
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            raise DNSProbeError("truncated DNS answer data")
        if (record_index < answers and owner_name == name
                and rtype == 1 and rclass == 1 and rdlength == 4
                and 0 <= ttl <= 300
                and (expected_wire is None
                     or bytes(data[offset:offset + rdlength]) == expected_wire)):
            valid_a += 1
        offset += rdlength
    if offset != len(data):
        raise DNSProbeError("trailing DNS response bytes")
    rcode = flags & 0xF
    return {"ok": rcode == 0 and valid_a > 0,
            "rcode": rcode, "answers": answers, "bytes": len(data)}


def _recv_exact(sock, size, deadline):
    chunks = []
    remaining = int(size)
    while remaining:
        timeout = deadline - time.monotonic()
        if timeout <= 0:
            raise DNSProbeError("TCP DNS deadline exceeded")
        sock.settimeout(timeout)
        chunk = sock.recv(remaining)
        if not chunk:
            raise DNSProbeError("short TCP DNS response")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def probe(host, port, transport="udp", timeout=3.0, name=CANARY_NAME,
          expected_ipv4=None):
    """Probe a local listener over UDP or TCP; return bounded metadata only."""
    txid, packet = _build_query(None, name)
    started = time.monotonic()
    family = socket.AF_INET6 if ":" in str(host) else socket.AF_INET
    sock_type = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    if transport not in ("udp", "tcp"):
        raise DNSProbeError("unsupported DNS transport")
    try:
        with socket.socket(family, sock_type) as sock:
            deadline = started + max(0.05, float(timeout))
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            if transport == "udp":
                # A connected datagram socket lets the kernel discard packets
                # from every source except the selected DNS IP and port.
                sock.connect((host, int(port)))
                sock.send(packet)
                data = sock.recv(4096)
            else:
                sock.connect((host, int(port)))
                sock.sendall(struct.pack("!H", len(packet)) + packet)
                header = _recv_exact(sock, 2, deadline)
                remaining = struct.unpack("!H", header)[0]
                if remaining < 12 or remaining > 4096:
                    raise DNSProbeError("invalid TCP DNS response length")
                data = _recv_exact(sock, remaining, deadline)
        result = parse_response(data, txid, name=name,
                                expected_ipv4=expected_ipv4)
        result["latency_ms"] = max(0, int((time.monotonic() - started) * 1000))
        result["transport"] = transport
        return result
    except (OSError, ValueError, DNSProbeError) as error:
        return {"ok": False, "rcode": None, "answers": 0, "bytes": 0,
                "latency_ms": max(0, int((time.monotonic() - started) * 1000)),
                "transport": transport, "error_kind": type(error).__name__}
