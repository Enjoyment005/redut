#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vpn-panel HTTP(S)-сервер (stdlib). Публичная админка над vpn-agent (§11–12).

Запуск на сервере через systemd (vpn-panel.service). Слушает 0.0.0.0:<panel_port>
с self-signed TLS (/etc/vpn-panel/panel.{crt,key}). Аутентификация — webpanel.auth.

Эндпоинты (§12, реализованное в фазе 1-бэкенде):
  GET  /healthz                     без авторизации, "ok"
  GET  /login   POST /login         пароль + TOTP (или recovery)
  POST /logout
  GET  /                            дашборд
  GET  /api/status                  upstream/final/sing-box/размеры пула/балансы(кэш)
  POST /api/egress                  живая проба выхода через tun0
  GET  /api/pool                    пул из кэша
  POST /api/pool/refresh            обновить у провайдеров (+ баланс в setting)
  POST /api/proxy/<uid>/probe       проба кандидата
  POST /api/proxy/<uid>/apply       §9 смена upstream + verify + автооткат
  POST /api/proxy/<uid>/role        {role}
  POST /api/rollback                откат из кольца
  GET  /api/events?limit=N          журнал
  --- деньги (фаза 2, гейты money.py §6.2/§6.4) ---
  GET  /api/market                  getcountry+getprice: что и почём (PROXY6)
  GET  /api/money                   лимиты, траты за сутки, последние записи money
  POST /api/buy                     {country?, period?}  идемпотентно + постпроба §6.1
  POST /api/proxy/<uid>/prolong     {days}
  POST /api/proxy/<uid>/delete      необратимо, гейты §6.4 (эксперимент возврата — CLI)
  --- автоматика (фаза 3, машина состояний §8; отдельным процессом vpn-agent) ---
  POST /api/rotate                  запустить диагностику -> RETUNE/ROTATING/REPLENISH/EMERGENCY
  POST /api/emergency               {on: bool} — прямой выход через WAN вкл/выкл
  (состояние автомата + пульс — в GET /api/status: automat/emergency/heartbeat)
"""
import json
import os
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

PANEL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PANEL_DIR)

import alerts as alerts_mod        # noqa: E402
import apply as apply_mod          # noqa: E402
import country as country_mod      # noqa: E402
import money as money_mod          # noqa: E402
import pool as pool_mod            # noqa: E402
import probe as probe_mod          # noqa: E402
import states as states_mod        # noqa: E402
from providers import make_providers, ProviderError, PROVIDER_CLASSES  # noqa: E402
from webpanel import auth, views    # noqa: E402
from webpanel import clients as clients_mod   # noqa: E402
from webpanel import qrcode as qr_mod         # noqa: E402

ETC_CONFIG = "/etc/vpn-panel/config.json"
ETC_SECRETS = "/etc/vpn-panel/secrets.json"
CERT = "/etc/vpn-panel/panel.crt"
KEY = "/etc/vpn-panel/panel.key"

_DB_LOCK = threading.Lock()        # sqlite из потоков http-сервера — сериализуем доступ


def _has(row, col):
    """Есть ли колонка в sqlite3.Row (база могла остаться от старой схемы)."""
    try:
        return col in row.keys()
    except AttributeError:
        return col in (row or {})


def load_config():
    env = os.environ.get("VPN_PANEL_CONFIG")
    for cand in ([env] if env else []) + [ETC_CONFIG, os.path.join(PANEL_DIR, "config.local.json")]:
        if os.path.isfile(cand):
            with open(cand, encoding="utf-8") as f:
                cfg = json.load(f)
            server_paths = cand == ETC_CONFIG
            cfg.setdefault("db", "/var/lib/vpn-panel/state.db"
                           if server_paths else os.path.join(PANEL_DIR, "state.db"))
            cfg.setdefault("ring", "/var/lib/vpn-panel/cfg"
                           if server_paths else os.path.join(PANEL_DIR, "cfg"))
            cfg.setdefault("singbox_config", "/etc/sing-box/config.json")
            cfg.setdefault("boot_script", "/usr/local/bin/vpn-boot-setup.sh")
            cfg.setdefault("singbox_bin", "sing-box")
            cfg.setdefault("lock", "/run/vpn-agent.lock")
            cfg.setdefault("panel_port", 8443)
            cfg["_source"] = cand
            return cfg
    raise SystemExit("Нет config.json (%s)" % ETC_CONFIG)


def load_secrets():
    env = os.environ.get("VPN_PANEL_SECRETS")
    for cand in ([env] if env else []) + [ETC_SECRETS, os.path.join(PANEL_DIR, ".secrets.local.json")]:
        if os.path.isfile(cand):
            with open(cand, encoding="utf-8") as f:
                return json.load(f), cand
    return {}, None


def _agent_cmd():
    """Команда запуска vpn-agent как ОТДЕЛЬНОГО процесса (§8, фаза 3).

    rotate/emergency гоняют долгую машину состояний с рестартом sing-box и своим
    flock — держать их в потоке http-сервера (общий conn БД) нельзя. Subprocess
    полностью изолирован (свой conn + тот же flock, что у сторожа) и повторяет
    ровно тот путь, которым автоматику зовёт cron/watchdog."""
    wrapper = "/usr/local/bin/vpn-agent"
    base = [wrapper] if os.path.isfile(wrapper) else [sys.executable, os.path.join(PANEL_DIR, "agent.py")]
    src = (APP.cfg or {}).get("_source")
    if src and os.path.isfile(src):
        base += ["--config", src]     # тот же config.json, что у панели
    return base


def _run_agent(args, timeout=240):
    try:
        p = subprocess.run(_agent_cmd() + list(args), capture_output=True, text=True, timeout=timeout)
        return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()
    except Exception as e:
        return -1, str(e)


def _make_mask(secrets):
    """Маска секретов для тела писем (§15): ключи провайдеров, SMTP-пароль."""
    vals = []
    for v in (secrets or {}).values():
        if isinstance(v, dict):
            for kk in ("api_key", "password"):
                if v.get(kk) and len(str(v[kk])) >= 6:
                    vals.append(str(v[kk]))
    def mask(text):
        t = str(text)
        for x in vals:
            t = t.replace(x, "****")
        return t
    return mask


class App:
    """Разделяемое состояние: конфиг, соединение с БД, пул, провайдеры, admin."""

    def __init__(self):
        self.cfg = load_config()
        self.pool = pool_mod.Pool(self.cfg["db"], server=self.cfg.get("server") or "panel")
        self.store = auth.AuthStore(self.pool.conn)
        # мастер первого входа (чистая установка): пока нет admin — режим онбординга.
        self.setup = {}                       # незаписанные шаги мастера (в памяти)
        self.setup_csrf = auth.new_csrf_token()
        self._load_secrets()

    def _load_secrets(self):
        self.secrets, self.secrets_path = load_secrets()
        self.admin = self.secrets.get("admin")
        self.provisioned = bool(self.admin)   # admin есть -> панель настроена
        self.providers = make_providers(self.secrets)
        self.alerter = alerts_mod.make_alerter(self.secrets, self.cfg,
                                               log=lambda m: None, mask=_make_mask(self.secrets))

    def reload_secrets(self):
        """Перечитать secrets.json на лету (после мастера/смены ключей) — без рестарта."""
        self._load_secrets()

    def write_secrets(self, data):
        """Атомарно записать secrets.json (0600) и перечитать состояние."""
        path = self.secrets_path or ETC_SECRETS
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
        self.reload_secrets()

    def read_singbox(self):
        try:
            return apply_mod.load_json(self.cfg["singbox_config"])
        except (OSError, ValueError):
            return None

    def current_host(self):
        return apply_mod.current_upstream(self.read_singbox() or {})

    def probe_row(self, row):
        prov = self.providers.get(row["provider"])
        cb = (lambda: prov.check(row["ext_id"])) if prov and prov.caps.get("check") else None
        # сеть (curl) — вне лока (долго); запись в БД — под общим локом
        res = probe_mod.probe(row, provider_check=cb)
        res["score"] = probe_mod.score(row, res, is_current=(row["host"] == self.current_host()))
        with _DB_LOCK:
            self.pool.record_probe(row["uid"], res)
        return res


APP = None


class Handler(BaseHTTPRequestHandler):
    server_version = "vpn-panel"
    protocol_version = "HTTP/1.1"

    # ------- утилиты ответа -------
    def _headers(self, code, ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'")
        for k, v in (extra or []):
            self.send_header(k, v)

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self._headers(code, ctype, extra)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _json(self, code, obj, extra=None):
        self._send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8", extra)

    def _redirect(self, to, extra=None):
        self._headers(303, extra=(extra or []) + [("Location", to)])
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ------- куки / сессия / CSRF -------
    def _cookies(self):
        out = {}
        for part in (self.headers.get("Cookie") or "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                out[k] = v
        return out

    def _client_ip(self):
        return self.client_address[0]

    def _session(self):
        tok = self._cookies().get(auth.COOKIE_NAME)
        with _DB_LOCK:
            return APP.store.get_session(tok)

    def _require_session(self):
        s = self._session()
        if not s:
            self._json(401, {"error": "не авторизовано"})
            return None
        return s

    def _check_csrf(self, s):
        # API-POST шлёт токен заголовком (JS). /login и /logout идут мимо этой
        # проверки (форма без сессии / csrf-поле) и защищены cookie SameSite=Strict.
        tok = self.headers.get("X-CSRF-Token")
        return bool(tok and s and auth.hmac.compare_digest(tok, s["csrf"]))

    def _body(self):
        ln = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(ln) if ln else b""

    def log_message(self, fmt, *args):
        pass  # без access-логов (OPSEC); значимое пишем в event

    # ------------------------------------------------ GET
    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        if path == "/healthz":
            return self._send(200, "ok", "text/plain; charset=utf-8")
        if not APP.provisioned:                     # чистая установка -> мастер первого входа
            if path == "/setup":
                return self._send(200, views.setup_page(APP.setup_csrf))
            return self._redirect("/setup")
        if path == "/setup":
            return self._redirect("/login")         # уже настроено — мастер закрыт
        if path == "/login":
            return self._send(200, views.login_page())
        if path == "/":
            s = self._session()
            if not s:
                return self._redirect("/login")
            return self._send(200, views.dashboard_page(APP.cfg.get("server") or "panel", s["csrf"]))
        if path.startswith("/api/"):
            s = self._require_session()
            if not s:
                return
            return self._api_get(path, parse_qs(u.query))
        self._send(404, "not found", "text/plain; charset=utf-8")

    def _api_get(self, path, qs):
        if path == "/api/status":
            return self._json(200, self._status())
        if path == "/api/pool":
            with _DB_LOCK:
                rows = APP.pool.list(include_gone=True)
            cur = APP.current_host()
            return self._json(200, {"proxies": [self._pool_row(r, cur) for r in rows]})
        if path == "/api/events":
            limit = int((qs.get("limit") or ["50"])[0])
            with _DB_LOCK:
                evs = APP.pool.conn.execute(
                    "SELECT ts,actor,action,result,detail FROM event ORDER BY id DESC LIMIT ?",
                    (min(limit, 500),)).fetchall()
            return self._json(200, {"events": [dict(zip(("ts", "actor", "action", "result", "detail"), e))
                                               for e in evs]})
        if path == "/api/market":
            return self._json(200, self._market(qs))
        if path == "/api/money":
            day = time.strftime("%Y-%m-%d")
            with _DB_LOCK:
                rows = APP.pool.conn.execute(
                    "SELECT ts,provider,op,uid,price,currency,balance_after FROM money"
                    " ORDER BY id DESC LIMIT 100").fetchall()
                spent = APP.pool.spent_today("RUB")
                buys = APP.pool.buys_today()
            return self._json(200, {"limits": money_mod.limits(APP.cfg),
                                    "today": {"buys": buys, "spent_rub": spent, "day": day},
                                    "rows": [dict(zip(("ts", "provider", "op", "uid", "price",
                                                       "currency", "balance_after"), r)) for r in rows]})
        if path == "/api/clients":
            try:
                return self._json(200, {"clients": clients_mod.list_clients(APP.cfg),
                                        "next_ip": clients_mod.next_free_ip(APP.cfg)})
            except clients_mod.ClientError as e:
                return self._json(500, {"error": str(e)})
        parts = path.strip("/").split("/")   # api clients <name> config|qr
        if len(parts) == 4 and parts[:2] == ["api", "clients"]:
            name = unquote(parts[2])
            try:
                conf = clients_mod.client_conf_text(name)
            except clients_mod.ClientError as e:
                return self._json(404, {"error": str(e)})
            if parts[3] == "config":
                return self._send(200, conf, "text/plain; charset=utf-8",
                                  extra=[("Content-Disposition", "attachment; filename=\"%s.conf\"" % name)])
            if parts[3] == "qr":
                return self._send(200, qr_mod.qr_svg(conf, ecl="M", module=5),
                                  "image/svg+xml; charset=utf-8")
        self._json(404, {"error": "нет такого метода"})

    def _market(self, qs):
        """§12 GET /api/market: что и почём доступно (getcountry+getprice PROXY6).

        Per-country getcount не гоняем (17 стран × троттлинг — долго): наличие
        берём из getcountry, точный count по стране считает уже поток покупки."""
        prov = APP.providers.get("proxy6")
        lim = money_mod.limits(APP.cfg)
        wl = money_mod.whitelist(APP.cfg)
        out = {"whitelist": wl, "limits": lim, "available": [], "price": None}
        if prov is None:
            out["error"] = "нет ключа PROXY6"
            return out
        version = int(lim["buy_version"])
        period = int((qs.get("period") or [str(lim["buy_period_days"])])[0])
        out["version"], out["period"] = version, period
        try:
            avail = set(prov.getcountry(version))
            out["available"] = [cc for cc in wl if cc in avail]
        except ProviderError as e:
            out["country_error"] = str(e)
        try:
            pr = prov.getprice(1, period, version)
            out["price"] = {"price": pr["price"], "currency": pr["currency"], "balance": pr["balance"]}
        except ProviderError as e:
            out["price_error"] = str(e)
        return out

    # ------------------------------------------------ POST
    def do_POST(self):
        u = urlparse(self.path)
        path = u.path
        if path.startswith("/api/setup/"):
            return self._do_setup(path)          # мастер онбординга (свой токен, без сессии)
        if path == "/login":
            if not APP.provisioned:
                return self._redirect("/setup")  # ещё не настроено — сначала мастер
            return self._do_login()
        if path == "/logout":
            body = parse_qs(self._body().decode("utf-8", "replace"))
            s = self._session()
            if s and (body.get("csrf") or [""])[0] == s["csrf"]:
                with _DB_LOCK:
                    APP.store.destroy_session(s["token"])
            return self._redirect("/login")

        s = self._require_session()
        if not s:
            return
        if not self._check_csrf(s):
            return self._json(403, {"error": "CSRF-токен неверен"})
        try:
            return self._api_post(path)
        except ProviderError as e:
            self._json(502, {"error": "провайдер: %s" % e})
        except apply_mod.ApplyError as e:
            self._json(409, {"error": str(e)})
        except Exception as e:
            self._json(500, {"error": "%s: %s" % (type(e).__name__, e)})

    def _api_post(self, path):
        if path == "/api/pool/refresh":
            with _DB_LOCK:
                summary = APP.pool.refresh(APP.providers, actor="user")
                for name, prov in APP.providers.items():
                    if name in summary["errors"]:
                        continue
                    try:
                        b = prov.balance()
                        APP.pool.conn.execute("INSERT OR REPLACE INTO setting(key,value) VALUES(?,?)",
                                              ("balance:%s" % name, "%s %s" % (b.get("balance"), b.get("currency"))))
                    except ProviderError:
                        pass
                APP.pool.conn.commit()
            return self._json(200, summary)
        if path == "/api/egress":
            v = apply_mod.verify_egress()
            with _DB_LOCK:
                APP.pool.set_egress(v)      # чтобы дашборд знал состояние и после перезагрузки
            return self._json(200, {"egress": v["egress_ip"], "egress_cc": v["exit_cc"],
                                    "tg_code": v["tg_code"], "ok": v["ok"], "why": v.get("why", "")})
        if path == "/api/rollback":
            r = apply_mod.rollback_from_ring(APP.cfg)
            with _DB_LOCK:
                APP.pool.log_event("rollback", actor="user", result="ok" if r["ok"] else "verify-fail",
                                   detail=json.dumps({"bad": r["bad_ip"], "good": r["good_ip"]}, ensure_ascii=False),
                                   src_ip=self._client_ip())
                APP.pool.set_egress(r.get("verify"))
            return self._json(200, {"ok": r["ok"], "bad_ip": r["bad_ip"], "good_ip": r["good_ip"],
                                    "egress": r["verify"]["egress_ip"]})
        if path == "/api/rotate":
            # машина состояний §8 отдельным процессом (см. _agent_cmd)
            rc, out = _run_agent(["rotate", "--reason", "panel"])
            with _DB_LOCK:
                st = APP.pool.get_setting("automat_state") or "OK"
                APP.pool.log_event("panel-rotate", actor="user", result=st, src_ip=self._client_ip())
            return self._json(200, {"ok": rc == 0, "state": st, "output": (out or "")[-1500:]})
        if path == "/api/emergency":
            body = json.loads(self._body() or b"{}") or {}
            on = bool(body.get("on"))
            rc, out = _run_agent(["emergency", "on" if on else "off"])
            with _DB_LOCK:
                st = APP.pool.get_setting("automat_state") or "OK"
                APP.pool.log_event("panel-emergency", actor="user",
                                   result="on" if on else "off", src_ip=self._client_ip())
            return self._json(200, {"ok": rc == 0, "state": st, "on": on, "output": (out or "")[-600:]})

        parts = path.strip("/").split("/")   # api proxy <uid> <action>
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "proxy":
            uid, action = unquote(parts[2]), parts[3]
            with _DB_LOCK:
                row = APP.pool.get(uid)
            if not row:
                return self._json(404, {"error": "uid не найден"})
            if action == "prolong":
                return self._do_prolong(row)
            if action == "delete":
                return self._do_delete(row)
            if action == "role":
                role = (json.loads(self._body() or b"{}") or {}).get("role")
                with _DB_LOCK:
                    APP.pool.set_role(uid, role)
                    APP.pool.log_event("role", actor="user", to_uid=uid, result=role, src_ip=self._client_ip())
                return self._json(200, {"ok": True, "uid": uid, "role": role})
            if action == "probe":
                res = APP.probe_row(row)
                return self._json(200, {"ok": res["ok"], "score": res["score"], "exit_ip": res["exit_ip"],
                                        "exit_cc": res["exit_cc"], "tg_ok": res["tg_ok"],
                                        "disqualified": res["disqualified"]})
            if action == "apply":
                return self._do_apply(row)
        # --- клиентские WireGuard-конфиги (панель = root, правит wg0) ---
        if path == "/api/clients":
            body = json.loads(self._body() or b"{}") or {}
            try:
                r = clients_mod.add_client(APP.cfg, (body.get("name") or "").strip())
            except clients_mod.ClientError as e:
                return self._json(400, {"error": str(e)})
            with _DB_LOCK:
                APP.pool.log_event("client-add", actor="user", result="ok",
                                   detail="%s %s" % (r["name"], r["ip"]), src_ip=self._client_ip())
            return self._json(200, r)
        if len(parts) == 4 and parts[1] == "clients" and parts[3] == "delete":
            name = unquote(parts[2])
            try:
                r = clients_mod.delete_client(APP.cfg, name)
            except clients_mod.ClientError as e:
                return self._json(400, {"error": str(e)})
            with _DB_LOCK:
                APP.pool.log_event("client-del", actor="user", result="ok",
                                   detail=name, src_ip=self._client_ip())
            return self._json(200, r)
        if path == "/api/buy":
            return self._do_buy(json.loads(self._body() or b"{}") or {})
        self._json(404, {"error": "нет такого метода"})

    # ------------------------------------------------ деньги (§6, гейты money.py)
    def _do_buy(self, body):
        """POST /api/buy {country?, period?} — гейты §6.2 + идемпотентность +
        постфактум-проба страны выхода §6.1. Те же гейты, что и у agent.py buy."""
        prov = APP.providers.get("proxy6")
        if prov is None:
            return self._json(400, {"error": "нет ключа PROXY6 — покупка недоступна"})
        lim = money_mod.limits(APP.cfg)
        wl = money_mod.whitelist(APP.cfg)
        country = str(body.get("country") or "").strip().lower()
        # чёрный список — «нет» всегда; страна с низкой оценкой — можно, но человек
        # должен видеть, на что идёт (предупреждение уедет в ответ и в журнал).
        if country and country_mod.is_blocked(country, APP.cfg):
            return self._json(400, {"error": "страна %s в чёрном списке — не покупаем никогда" % country})
        warn = ""
        if country and not country_mod.auto_allowed(country, True, APP.cfg):
            warn = "%s: %s" % (country, country_mod.explain(country))
        try:
            period = int(body.get("period") or lim["buy_period_days"])
        except (TypeError, ValueError):
            return self._json(400, {"error": "period должен быть числом"})
        version = int(lim["buy_version"])
        # страну назвали — берём её; нет — идём по умной оценке (лучшие страны первыми)
        pick = None
        for cc in ([country] if country else money_mod.buy_candidates(APP.cfg)):
            try:
                if prov.getcount(cc, version) > 0:
                    pick = cc
                    break
            except ProviderError:
                continue
        if not pick:
            return self._json(409, {"error": "нет прокси version=%d в наличии среди подходящих стран" % version})
        try:
            with _DB_LOCK:   # покупка под общим локом: атомарность суточных лимитов
                r = money_mod.plan_and_buy(APP.pool, prov, APP.cfg, country=pick, period=period,
                                           count=1, version=version, server=APP.cfg.get("server"),
                                           actor="user", src_ip=self._client_ip(),
                                           auto=False)   # покупает человек из панели
        except money_mod.SpendDenied as e:
            with _DB_LOCK:
                APP.pool.log_event("buy", actor="user", result="denied", detail=str(e),
                                   src_ip=self._client_ip())
            return self._json(409, {"error": "гейт трат: %s" % e})
        # §6.1 постфактум: реальная страна выхода (пробы — ВНЕ лока, они долгие)
        post = self._postbuy(prov, r["proxies"])
        return self._json(200, {"ok": True, "recovered": r["recovered"], "price": r["price"],
                                "currency": r["currency"], "balance_after": r["balance_after"],
                                "order_id": r["order_id"], "country": r["country"],
                                "uids": ["%s:%s" % (x["provider"], x["ext_id"]) for x in r["proxies"]],
                                "postcheck": post})

    def _postbuy(self, prov, proxies):
        post = []
        try:
            with _DB_LOCK:
                APP.pool.refresh({"proxy6": prov})   # getproxy: полные поля новых uid
        except Exception:
            pass
        cur = APP.current_host()
        for pxy in proxies:
            uid = "%s:%s" % (pxy["provider"], pxy["ext_id"])
            with _DB_LOCK:
                row = APP.pool.get(uid) or dict(pxy, uid=uid)
            try:
                res = APP.probe_row(row)          # curl-проба, свой лок внутри
            except Exception as e:
                post.append({"uid": uid, "error": str(e)})
                continue
            blocked = (res.get("exit_cc") in probe_mod.HARD_BLOCK_CC
                       or str(res.get("disqualified") or "").startswith("blocked-cc"))
            if blocked:
                with _DB_LOCK:
                    APP.pool.set_role(uid, "off")
                    APP.pool.log_event("buy-postcheck", actor="user", to_uid=uid, result="blocked-cc",
                                       detail="реальный выход cc=%s (жёсткий блок §6.1) -> off"
                                       % res.get("exit_cc"), src_ip=self._client_ip())
            post.append({"uid": uid, "exit_cc": res.get("exit_cc"), "score": res.get("score"),
                         "blocked": blocked})
        return post

    def _do_prolong(self, row):
        prov = APP.providers.get(row["provider"])
        if prov is None or not prov.caps.get("prolong"):
            return self._json(400, {"error": "провайдер %s не умеет продление" % row["provider"]})
        body = json.loads(self._body() or b"{}") or {}
        try:
            days = int(body.get("days"))
        except (TypeError, ValueError):
            return self._json(400, {"error": "нужно поле days (целое)"})
        try:
            with _DB_LOCK:
                r = money_mod.prolong_with_limits(APP.pool, prov, APP.cfg, row=row, days=days,
                                                  actor="user", src_ip=self._client_ip())
        except money_mod.SpendDenied as e:
            return self._json(409, {"error": "гейт трат: %s" % e})
        return self._json(200, {"ok": True, "uid": r["uid"], "days": r["days"], "price": r["price"],
                                "currency": r["currency"], "balance_after": r["balance_after"],
                                "date_end": r["date_end"]})

    def _do_delete(self, row):
        """§6.4: полный набор гейтов (тумблер, роль, не текущий upstream, проба
        ≥2 провалов, check провайдера false). Эксперимент возврата — только CLI."""
        prov = APP.providers.get(row["provider"])
        if prov is None or not prov.caps.get("delete"):
            return self._json(400, {"error": "провайдер %s не умеет удаление" % row["provider"]})
        if row["role"] == "chrome":
            return self._json(403, {"error": "роль chrome защищена от удаления (§5)"})
        cur = APP.current_host()
        pchk = None
        try:
            pchk = prov.check(row["ext_id"])
        except ProviderError:
            pass
        ok, reason = money_mod.can_delete(row, APP.cfg, current_host=cur, provider_check=pchk)
        if not ok:
            return self._json(409, {"error": "гейт §6.4: %s" % reason})
        with _DB_LOCK:
            n = money_mod.delete_and_record(APP.pool, prov, row, actor="user", currency="RUB",
                                            src_ip=self._client_ip())
        return self._json(200, {"ok": True, "deleted": n, "uid": row["uid"]})

    def _do_apply(self, row):
        if row["role"] == "chrome":
            return self._json(403, {"error": "роль chrome защищена (§5)"})
        res = APP.probe_row(row)
        if res["disqualified"] or not res["ok"]:
            with _DB_LOCK:
                APP.pool.log_event("apply", actor="user", to_uid=row["uid"], result="fail",
                                   detail="disqualified: %s" % (res["disqualified"] or "проба"),
                                   src_ip=self._client_ip())
            return self._json(409, {"error": "кандидат дисквалифицирован: %s" % (res["disqualified"] or "проба не прошла")})
        r = apply_mod.apply_candidate(APP.cfg, row, res, log=lambda m: None)
        with _DB_LOCK:
            APP.pool.mark_used(row["uid"])
            APP.pool.log_event("apply", actor="user", to_uid=row["uid"], result="ok",
                               detail=json.dumps({"old_ip": r["old_ip"], "new_ip": r["new_ip"],
                                                  "verify": r["verify"]}, ensure_ascii=False),
                               src_ip=self._client_ip())
            APP.pool.set_egress(r.get("verify"))
        return self._json(200, {"ok": True, "old_ip": r["old_ip"], "new_ip": r["new_ip"],
                                "egress": r["verify"]["egress_ip"], "egress_cc": r["verify"]["exit_cc"]})

    # ------------------------------------------------ логин
    def _do_login(self):
        ip = self._client_ip()
        with _DB_LOCK:
            ban = APP.store.is_banned(ip)
        if ban:
            return self._send(429, views.login_page(error="Слишком много попыток. Бан ещё %d мин." % (ban // 60 + 1)))
        body = parse_qs(self._body().decode("utf-8", "replace"))
        password = (body.get("password") or [""])[0]
        otp = (body.get("otp") or [""])[0]
        admin = APP.admin
        ok = False
        if admin and auth.verify_password(password, admin.get("pw", "")):
            if auth.totp_verify(admin.get("totp", ""), otp):
                ok = True
            elif otp and APP.secrets_path and auth.consume_recovery_code(None, APP.secrets_path, otp):
                # recovery-код одноразовый: перечитать секреты (список изменился)
                APP.secrets, _ = load_secrets()
                APP.admin = APP.secrets.get("admin")
                ok = True
        if not ok:
            with _DB_LOCK:
                fails, banned = APP.store.record_fail(ip)
                APP.pool.log_event("login", actor="user", result="fail",
                                   detail="fails=%d ban=%ds" % (fails, banned), src_ip=ip)
            return self._send(401, views.login_page(error="Неверный пароль или код второго фактора."))
        with _DB_LOCK:
            APP.store.record_success(ip)
            token, csrf = APP.store.create_session(ip)
            APP.pool.log_event("login", actor="user", result="ok", src_ip=ip)
        cookie = "%s=%s; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=%d" % (
            auth.COOKIE_NAME, token, auth.SESSION_TTL)
        self._redirect("/", extra=[("Set-Cookie", cookie)])

    # ------------------------------------------------ мастер первого входа (§чистая установка)
    def _do_setup(self, path):
        if APP.provisioned:
            return self._json(403, {"error": "панель уже настроена"})
        tok = self.headers.get("X-Setup-Token")
        if not (tok and auth.hmac.compare_digest(tok, APP.setup_csrf)):
            return self._json(403, {"error": "setup-токен неверен — перезагрузи /setup"})
        try:
            body = json.loads(self._body() or b"{}") or {}
        except ValueError:
            body = {}
        try:
            if path == "/api/setup/password":
                return self._setup_password(body)
            if path == "/api/setup/totp/new":
                return self._setup_totp_new()
            if path == "/api/setup/totp/verify":
                return self._setup_totp_verify(body)
            if path == "/api/setup/provider":
                return self._setup_provider(body)
            if path == "/api/setup/smtp":
                return self._setup_smtp(body)
            if path == "/api/setup/finish":
                return self._setup_finish()
        except Exception as e:
            return self._json(500, {"error": "%s: %s" % (type(e).__name__, e)})
        self._json(404, {"error": "нет такого шага"})

    def _setup_password(self, body):
        import secrets as _s
        pw = (body.get("password") or "").strip() or _s.token_urlsafe(12)
        if len(pw) < 8:
            return self._json(400, {"error": "пароль минимум 8 символов"})
        APP.setup["pw"] = pw
        return self._json(200, {"password": pw, "generated": not body.get("password")})

    def _setup_totp_new(self):
        seed = auth.totp_new_seed()
        APP.setup["totp"] = seed
        APP.setup.pop("totp_ok", None)
        uri = auth.totp_uri(seed, APP.cfg.get("server") or "vpn-panel")
        return self._json(200, {"secret": seed, "uri": uri,
                                "qr": qr_mod.qr_svg(uri, ecl="M", module=5)})

    def _setup_totp_verify(self, body):
        seed = APP.setup.get("totp")
        if not seed:
            return self._json(400, {"error": "сначала сгенерируй 2FA (QR)"})
        if not auth.totp_verify(seed, body.get("code") or ""):
            return self._json(400, {"error": "код не подходит — проверь время на телефоне и повтори"})
        plain, hashes = auth.gen_recovery_codes(10)
        APP.setup["recovery"] = hashes
        APP.setup["totp_ok"] = True
        return self._json(200, {"recovery": plain})

    def _setup_provider(self, body):
        """Валидируем ключи живьём (balance). proxy6 в приоритете (умеет возврат)."""
        res, keys = {}, {}
        for name in PROVIDER_CLASSES:
            key = (body.get(name) or "").strip()
            if not key:
                continue
            try:
                bal = PROVIDER_CLASSES[name](key).balance()
                res[name] = {"ok": True, "balance": bal.get("balance"), "currency": bal.get("currency")}
                keys[name] = key
            except Exception as e:
                res[name] = {"ok": False, "error": str(e)}
        if not keys:
            return self._json(400, {"error": "нужен хотя бы один рабочий ключ", "result": res})
        APP.setup["providers"] = keys
        return self._json(200, {"result": res})

    def _setup_smtp(self, body):
        if body.get("skip"):
            APP.setup.pop("smtp", None)
            APP.setup["smtp_done"] = True
            return self._json(200, {"skipped": True})
        smtp = {k: body.get(k) for k in ("host", "port", "user", "password", "from", "to")}
        if not (smtp["host"] and smtp["to"]):
            return self._json(400, {"error": "нужны минимум host и to (или «Пропустить»)"})
        try:
            smtp["port"] = int(smtp["port"] or 587)
        except (TypeError, ValueError):
            return self._json(400, {"error": "порт — число"})
        APP.setup["smtp"] = smtp
        APP.setup["smtp_done"] = True
        return self._json(200, {"ok": True})

    def _setup_finish(self):
        st = APP.setup
        if not st.get("pw"):
            return self._json(400, {"error": "не задан пароль"})
        if not (st.get("totp") and st.get("totp_ok")):
            return self._json(400, {"error": "2FA не подтверждена"})
        if not st.get("providers"):
            return self._json(400, {"error": "нет ключа провайдера"})
        data = {"admin": {"pw": auth.hash_password(st["pw"]), "totp": st["totp"],
                          "recovery": st.get("recovery", [])}}
        for name, key in st["providers"].items():
            data[name] = {"api_key": key}
        if st.get("smtp"):
            data["smtp"] = st["smtp"]
        APP.write_secrets(data)
        with _DB_LOCK:
            APP.pool.log_event("setup", actor="user", result="ok",
                               detail="онбординг: провайдеры=%s smtp=%s"
                               % (",".join(st["providers"]), bool(st.get("smtp"))),
                               src_ip=self._client_ip())
        APP.setup = {}
        return self._json(200, {"ok": True, "next": "/login"})

    # ------------------------------------------------ сборка status/pool
    def _status(self):
        sb = APP.read_singbox() or {}
        out = {"server": APP.cfg.get("server"), "role": APP.cfg.get("role"),
               "subnet": APP.cfg.get("subnet"), "final": (sb.get("route") or {}).get("final"),
               "singbox": "?", "upstream": {}, "balances": {}, "egress": None,
               # белый список стран — дашборд предупреждает, если выход идёт мимо него
               "cc_whitelist": (APP.cfg.get("countries") or {}).get("whitelist") or []}
        for o in sb.get("outbounds", []):
            if o.get("tag") == "socks-out":
                out["upstream"]["socks_out"] = "%s:%s %s" % (o.get("server"), o.get("server_port"), o.get("type"))
            if o.get("tag") == "http-tg":
                out["upstream"]["http_tg"] = "%s:%s %s" % (o.get("server"), o.get("server_port"), o.get("type"))
        if os.name == "posix":
            rc, act = apply_mod.run_cmd(["systemctl", "is-active", "sing-box"])
            out["singbox"] = act or "?"
        with _DB_LOCK:
            rows = APP.pool.list(include_gone=True)
            out["pool_alive"] = len([r for r in rows if not r["gone"]])
            for k, v in APP.pool.conn.execute("SELECT key,value FROM setting WHERE key LIKE 'balance:%'"):
                out["balances"][k.split(":", 1)[1]] = v
            # автомат состояний (§8) + пульс (§6.3)
            out["automat"] = APP.pool.get_setting("automat_state") or "OK"
            out["emergency"] = out["automat"] == "EMERGENCY"
            out["emergency_since"] = APP.pool.get_setting("emergency_since")
            out["frozen"] = APP.pool.get_setting("automat_frozen") == "1"
            out["heartbeat"] = APP.pool.last_heartbeat()
            # последняя проба выхода: сам статус её не делает (curl через tun0 — до 15 с
            # на каждый опрос), отдаём то, что записали панель или агент §8.
            eg = APP.pool.get_egress()
        if eg:
            out.update(eg)
        # оценка страны текущего выхода — панель объясняет её человеку
        out["cc_tier"] = country_mod.tier(out.get("egress_cc"), True, APP.cfg)
        out["cc_hint"] = country_mod.explain(out.get("egress_cc"), True, APP.cfg)
        out["cc_blacklist"] = sorted(country_mod.blacklist(APP.cfg))
        out["auto_prolong"] = states_mod.auto_prolong_cfg(APP.cfg)
        return out

    def _pool_row(self, r, cur):
        days = probe_mod.days_left(r["date_end"])
        cc = r["exit_cc"] if _has(r, "exit_cc") and r["exit_cc"] else r["country"]
        agree = True if not _has(r, "geo_agree") or r["geo_agree"] is None else bool(r["geo_agree"])
        return {"uid": r["uid"], "provider": r["provider"], "country": r["country"],
                "host": r["host"], "port_socks5": r["port_socks5"], "port_http": r["port_http"],
                "role": r["role"], "score": r["score"], "gone": r["gone"],
                "socks_ok": r["socks_ok"], "http_ok": r["http_ok"], "tg_ok": r["tg_ok"],
                "days": None if days is None else round(days),
                "last_probe": (r["last_probe_at"] or "")[5:16],
                "is_current": bool(cur and r["host"] == cur),
                # умная оценка страны (§6.1): что показать человеку и почему
                "exit_cc": r["exit_cc"] if _has(r, "exit_cc") else None,
                "exit_cc_alt": r["exit_cc_alt"] if _has(r, "exit_cc_alt") else None,
                "geo_agree": agree,
                "cc_tier": country_mod.tier(cc, agree, APP.cfg),
                "cc_hint": country_mod.explain(cc, agree, APP.cfg)}


def _pulse_monitor():
    """§6.3: панель — независимый долгоживущий процесс (Restart=always), поэтому
    именно она надёжно ловит «агент умер»: раз в час сверяет пульс агента (метку
    последнего успешного цикла в state.db) и шлёт письмо, если он старше 24 ч.
    Работает, даже если сам agent.py сломан — панель это отдельный файл/процесс."""
    while True:
        time.sleep(3600)
        try:
            with _DB_LOCK:
                states_mod.heartbeat_check(APP.pool, APP.alerter)
        except Exception as e:
            print("pulse-monitor: %s" % e, file=sys.stderr)


def main():
    global APP
    APP = App()
    port = int(APP.cfg.get("panel_port") or 8443)
    if not APP.provisioned:
        print("⚠️ Панель НЕ настроена — открой https://<host>:%d/setup (мастер первого входа: "
              "провайдер, 2FA, пароль, почта)" % port, file=sys.stderr)
    threading.Thread(target=_pulse_monitor, daemon=True).start()   # §6.3 пульс агента
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    if os.path.isfile(CERT) and os.path.isfile(KEY):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT, KEY)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    else:
        scheme = "http"
        print("⚠️ Нет %s — работаю без TLS (только для локального теста!)" % CERT, file=sys.stderr)
    print("vpn-panel на %s://0.0.0.0:%d (сервер %s)" % (scheme, port, APP.cfg.get("server")))
    APP.store.gc()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
