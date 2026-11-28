"""ZenXNet subscription adapter. Only an allowlisted VLESS profile is imported."""
import base64
import datetime
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import urllib.parse
import uuid

from .base import Provider, ProviderCapabilities, Capability, ProviderError, _retry_after

HOSTS = frozenset({"key.zenx.zone", "zenxnet.com", "www.zenxnet.com"})
MAX_BYTES = 2 * 1024 * 1024
MAX_NODES = 256
QUERY_KEYS = frozenset({"encryption", "flow", "fp", "pbk", "security", "sid",
                        "sni", "spx", "type"})


def invalid(message):
    return ProviderError("ZenXNet: " + message, kind="invalid")


def validate_url(value):
    """Validate the credential without ever including it in diagnostics."""
    if not isinstance(value, str) or not 8 <= len(value.strip()) <= 2048:
        raise invalid("нужна ссылка подписки")
    value = value.strip()
    try:
        u = urllib.parse.urlsplit(value)
        if (u.scheme != "https" or u.hostname not in HOSTS or u.port not in (None, 443)
                or u.username or u.password or u.fragment or not u.path.strip("/")
                or any(ord(c) <= 32 or ord(c) >= 127 for c in value)):
            raise ValueError
    except ValueError:
        raise invalid("нужна HTTPS-ссылка подписки ZenXNet") from None
    return value


def public_addresses(host, port=443):
    try:
        addresses = sorted({x[4][0] for x in socket.getaddrinfo(
            host, port, socket.AF_INET, socket.SOCK_STREAM)})
        if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
            raise ValueError
        return addresses
    except (OSError, ValueError):
        raise ProviderError("ZenXNet: адрес сервера недоступен или запрещён",
                            kind="network", unsent=True) from None


class _PinnedHTTPS(http.client.HTTPSConnection):
    """Connect to the validated IP while retaining hostname TLS verification."""
    def __init__(self, host, address):
        super().__init__(host, timeout=20, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        sock = socket.create_connection((self.address, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def fetch_subscription(url, hwid):
    original = urllib.parse.urlsplit(validate_url(url)).hostname
    for _ in range(3):
        u = urllib.parse.urlsplit(validate_url(url))
        if u.hostname != original:
            raise invalid("перенаправление на другой домен отклонено")
        connection = _PinnedHTTPS(u.hostname, public_addresses(u.hostname)[0])
        try:
            connection.request("GET", urllib.parse.urlunsplit(("", "", u.path, u.query, "")),
                headers={"User-Agent": "sing-box/1.14.5 REDUT/ZenXNet",
                         "Accept": "text/plain, application/octet-stream",
                         "Accept-Encoding": "identity", "x-hwid": hwid,
                         "x-device-os": "Linux", "x-device-model": "REDUT",
                         "x-ver-os": "Linux"})
            response = connection.getresponse()
            headers = {k.lower(): v for k, v in response.getheaders()}
            if response.status in (301, 302, 303, 307, 308):
                url = urllib.parse.urljoin(url, headers.get("location", ""))
                continue
            if response.status != 200:
                kinds = {401: "auth", 403: "auth", 404: "not-found", 410: "expired",
                         429: "rate-limit"}
                raise ProviderError("ZenXNet: HTTP %s; проверьте подписку и лимит устройств"
                                    % response.status, code=response.status,
                                    kind=kinds.get(response.status, "network"),
                                    retry_after=_retry_after(headers))
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise invalid("подписка превышает допустимый размер")
            if headers.get("content-encoding", "identity") != "identity":
                raise invalid("неподдерживаемое сжатие подписки")
            return body, headers
        except ProviderError:
            raise
        except (OSError, http.client.HTTPException, ValueError):
            raise ProviderError("ZenXNet: не удалось загрузить подписку", kind="network") from None
        finally:
            connection.close()
    raise invalid("слишком много перенаправлений")


def _country(label):
    match = re.search(r"([\U0001f1e6-\U0001f1ff]{2})", label)
    return "" if not match else "".join(chr(ord(c) - 0x1f1e6 + 97) for c in match[1])


def parse_node(line):
    try:
        u = urllib.parse.urlsplit(line)
        pairs = urllib.parse.parse_qsl(u.query, keep_blank_values=True, strict_parsing=True)
        q = dict(pairs)
        if (u.scheme != "vless" or u.password is not None or not u.hostname
                or u.path not in ("", "/") or len(q) != len(pairs)
                or set(q) - QUERY_KEYS or not 1 <= (u.port or 0) <= 65535):
            raise ValueError
        credential = str(uuid.UUID(u.username or ""))
        if (q.get("encryption", "none") != "none" or q.get("type", "tcp") != "tcp"
                or q.get("security") != "reality" or q.get("flow") != "xtls-rprx-vision"
                or q.get("fp", "firefox") not in {"chrome", "firefox", "safari", "edge", "ios"}
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", q.get("pbk", ""))
                or not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", q.get("sid", ""))
                or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", q.get("sni", ""))
                or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", u.hostname)):
            raise ValueError
        # spiderX is Xray's client-only camouflage path; it has no sing-box
        # handshake equivalent. Only its empty/default form is supported.
        if q.get("spx", "/") not in ("", "/"):
            raise ValueError
        try:
            if not ipaddress.ip_address(u.hostname).is_global:
                raise ValueError
        except ValueError:
            if re.fullmatch(r"[0-9.]+", u.hostname) or "." not in u.hostname:
                raise ValueError
        label = urllib.parse.unquote(u.fragment)
        label = "".join(c for c in label if c.isprintable())[:128]
        outbound = {"type": "vless", "server": u.hostname, "server_port": u.port,
                    "uuid": credential, "flow": "xtls-rprx-vision",
                    "tls": {"enabled": True, "server_name": q["sni"],
                            "utls": {"enabled": True, "fingerprint": q.get("fp", "firefox")},
                            "reality": {"enabled": True, "public_key": q["pbk"],
                                        "short_id": q.get("sid", "")}}}
        encoded = json.dumps(outbound, sort_keys=True, separators=(",", ":"))
        identity = json.dumps([u.hostname, u.port, q["sni"], q["pbk"]])
        return {"provider": "zenxnet", "ext_id": hashlib.sha256(identity.encode()).hexdigest()[:24],
                "ip": u.hostname, "host": u.hostname, "protocol": "vless",
                "endpoint_port": u.port, "connection_json": encoded,
                "connection_digest": hashlib.sha256(encoded.encode()).hexdigest(),
                "country": _country(label), "ip_version": 4, "kind": "subscription",
                "descr": label or "ZenXNet", "date_end": None,
                "port_http": None, "port_socks5": None, "user": "", "password": ""}
    except (ValueError, KeyError, TypeError, UnicodeError):
        raise invalid("неподдерживаемая или повреждённая VLESS-запись") from None


def parse_subscription(body):
    if not isinstance(body, bytes) or not 1 <= len(body) <= MAX_BYTES:
        raise invalid("пустая или слишком большая подписка")
    try:
        text = body.decode("utf-8-sig").strip()
        if not text.startswith("vless://"):
            compact = "".join(text.split())
            text = base64.b64decode(compact + "=" * (-len(compact) % 4),
                                    altchars=b"-_", validate=True).decode("utf-8-sig")
        lines = [x.strip() for x in text.splitlines() if x.strip()]
        if not 1 <= len(lines) <= MAX_NODES:
            raise ValueError
    except (ValueError, UnicodeError):
        raise invalid("ожидался список VLESS-серверов; проверьте HWID и лимит устройств") from None
    nodes = {}
    for line in lines:
        row = parse_node(line)
        old = nodes.get(row["ext_id"])
        if old and old["connection_digest"] != row["connection_digest"]:
            raise invalid("неоднозначные идентификаторы серверов")
        nodes[row["ext_id"]] = row
    return list(nodes.values())


def pin_nodes(nodes):
    """Keep subscription IDs stable, but dial only an approved public address.

    Runtime and probes use the same address. DNS cannot turn a validated
    provider hostname into an internal destination after catalog import.
    """
    addresses = {}
    for row in nodes:
        host = row["host"]
        if host not in addresses:
            addresses[host] = public_addresses(host, row["endpoint_port"])[0]
        outbound = json.loads(row["connection_json"])
        outbound["server"] = addresses[host]
        row["host"] = row["ip"] = addresses[host]
        row["connection_json"] = json.dumps(outbound, sort_keys=True, separators=(",", ":"))
        row["connection_digest"] = hashlib.sha256(row["connection_json"].encode()).hexdigest()
    return nodes


class ZenXNet(Provider):
    name = "zenxnet"
    caps = ProviderCapabilities(Capability.LIST)

    def __init__(self, api_key, hwid=None, cache_path=None):
        super().__init__(validate_url(api_key))
        if not isinstance(hwid, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", hwid):
            raise invalid("не задан постоянный идентификатор устройства")
        self.hwid = hwid
        self.cache_path = cache_path
        self.metadata = {}
        self._cache = None
        self._refresh_at = 0

    def list(self):
        def load():
            if self._cache is not None and time.monotonic() < self._refresh_at:
                if self.metadata.get("expire", 0) and self.metadata["expire"] <= time.time():
                    raise ProviderError("ZenXNet: срок подписки истёк", kind="expired")
                return self._cache
            identity = hashlib.sha256((self.api_key + "\0" + self.hwid).encode()).hexdigest()
            cached = None
            if self.cache_path:
                try:
                    with open(self.cache_path, encoding="utf-8") as handle:
                        stored = json.load(handle)
                    if stored.get("identity") == identity and stored.get("retry_at", 0) > time.time():
                        raise ProviderError("ZenXNet: повторное обновление отложено", kind="rate-limit",
                                            retry_after=stored["retry_at"] - time.time())
                    if (stored.get("identity") == identity and stored.get("refresh_at", 0) > time.time()
                            and isinstance(stored.get("body"), str) and isinstance(stored.get("headers"), dict)
                            and len(stored["body"]) <= MAX_BYTES * 2
                            and all(isinstance(v, str) for v in stored["headers"].values())):
                        base64.b64decode(stored["body"], validate=True)
                        cached = stored
                except (OSError, ValueError, TypeError, AttributeError):
                    pass
            if cached:
                body, headers = base64.b64decode(cached["body"]), cached["headers"]
            else:
                try:
                    body, headers = fetch_subscription(self.api_key, self.hwid)
                except ProviderError as error:
                    if self.cache_path:
                        import apply
                        delay = max(60, min(86400, float(error.retry_after or 300)))
                        apply.dump_json_replace({"identity": identity, "retry_at": time.time() + delay}, self.cache_path)
                    raise
            nodes = pin_nodes(parse_subscription(body))
            info = {}
            for item in headers.get("subscription-userinfo", "").split(";"):
                key, sep, value = item.strip().partition("=")
                if sep and key in ("upload", "download", "total", "expire") and value.isdigit():
                    info[key] = int(value)
            if info.get("expire"):
                if info["expire"] <= time.time():
                    raise ProviderError("ZenXNet: срок подписки истёк", kind="expired")
                try:
                    expiry = datetime.datetime.fromtimestamp(info["expire"], datetime.timezone.utc)
                except (ValueError, OverflowError, OSError):
                    raise invalid("неверный срок подписки") from None
                for row in nodes:
                    row["date_end"] = expiry.isoformat()
            try:
                interval = max(1, min(168, int(headers.get("profile-update-interval", "1")))) * 3600
            except ValueError:
                interval = 3600
            self.metadata = dict(info, node_count=len(nodes), refresh_seconds=interval)
            remaining = max(0, cached["refresh_at"] - time.time()) if cached else interval
            if self.cache_path and not cached:
                import apply
                safe_headers = {key: headers[key] for key in ("profile-update-interval", "subscription-userinfo") if key in headers}
                apply.dump_json_replace({"identity": identity, "refresh_at": time.time() + interval,
                                         "body": base64.b64encode(body).decode(), "headers": safe_headers}, self.cache_path)
            self._cache, self._refresh_at = nodes, time.monotonic() + remaining
            return nodes
        def serialized():
            if not self.cache_path:
                return load()
            import fcntl
            descriptor = os.open(self.cache_path + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
            with os.fdopen(descriptor, "a") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                return load()
        return self._guarded("list", serialized)
