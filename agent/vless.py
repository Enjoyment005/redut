"""Validated VLESS outbounds and isolated protocol probes; no system routes."""
import contextlib
import copy
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time


def outbound(row, tag="socks-out"):
    from providers.zenxnet import parse_node, public_addresses
    from urllib.parse import urlencode, quote
    try:
        raw = json.loads(row["connection_json"])
        tls = raw["tls"]
        # Re-validate stored data too; never let imported JSON define listeners,
        # routes, file paths, command execution, or a second outbound.
        query = {"type": "tcp", "encryption": "none", "security": "reality",
                 "flow": raw["flow"], "sni": tls["server_name"],
                 "pbk": tls["reality"]["public_key"],
                 "sid": tls["reality"].get("short_id", ""),
                 "fp": tls["utls"]["fingerprint"]}
        uri = "vless://%s@%s:%s?%s" % (quote(raw["uuid"], safe=""), raw["server"],
                                         int(raw["server_port"]), urlencode(query))
        result = json.loads(parse_node(uri)["connection_json"])
        result["tag"] = tag
        return result
    except (KeyError, ValueError, TypeError):
        raise ValueError("Некорректные сохранённые параметры VLESS") from None


def outbounds(row):
    main = outbound(row)
    telegram = copy.deepcopy(main)
    telegram["tag"] = "http-tg"
    return main, telegram, False


@contextlib.contextmanager
def probe_listener(row, binary=None):
    """Ephemeral loopback SOCKS inlet used solely to measure a real VLESS exit."""
    from providers.zenxnet import public_addresses
    binary = binary or os.environ.get("REDUT_SINGBOX_BIN") or shutil.which("sing-box")
    if not binary:
        raise ValueError("Для проверки VLESS требуется установленный sing-box")
    ob = outbound(row)
    ob["server"] = public_addresses(ob["server"], ob["server_port"])[0]
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="redut-vless-") as directory:
        path = os.path.join(directory, "config.json")
        config = {"log": {"disabled": True}, "inbounds": [{"type": "socks",
                  "tag": "probe", "listen": "127.0.0.1", "listen_port": port}],
                  "outbounds": [ob], "route": {"final": "socks-out"}}
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(config, handle)
        checked = subprocess.run([binary, "check", "-c", path], capture_output=True, timeout=15)
        if checked.returncode:
            raise ValueError("Ядро отклонило параметры VLESS")
        process = subprocess.Popen([binary, "run", "-c", path],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise ValueError("Изолированная проверка VLESS не запустилась")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise ValueError("Таймаут запуска проверки VLESS")
            yield port
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def probe(row, latency_runs=3):
    import probe as probe_mod
    try:
        with probe_listener(row) as port:
            local = dict(row, protocol="socks", host="127.0.0.1", ip="127.0.0.1",
                         port_socks5=port, port_http=None, user="", password="")
            result = probe_mod.probe(local, latency_runs=latency_runs)
            result.update(protocol="vless", vless_ok=result.get("ok", False),
                          socks_ok=False, http_ok=False, socks_port=None, http_port=None,
                          matrix={"%s/vless" % row["endpoint_port"]: result.get("exit_ip")},
                          connection_digest=row.get("connection_digest"))
            return result
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        return {"ok": False, "disqualified": "vless-probe-unavailable",
                "protocol": "vless", "connection_digest": row.get("connection_digest"), "vless_ok": False, "socks_ok": False,
                "http_ok": False, "socks_port": None, "http_port": None,
                "exit_ip": None, "exit_cc": None, "tg_ok": False, "latency_ms": None,
                "evidence": [], "matrix": {}, "probe_error": type(error).__name__}
