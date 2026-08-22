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
  GET  /api/ipinfo                  технический паспорт текущего IP выхода (ASN, оператор,
                                    город, пояс, PTR, датацентр; кэш по IP — для карты)
  --- настройки (§12; лимиты трат по-прежнему только по SSH) ---
  GET  /api/strategy                четыре стратегии выбора стран + предпросмотр на живых данных
  POST /api/strategy                {strategy} — сменить правило (config.json, без рестарта)
  --- ключи провайдеров (§12; сам ключ обратно не отдаётся никогда) ---
  GET  /api/key/status              по провайдеру: задан ли ключ, хвост, баланс, живых в пуле
  POST /api/key                     {provider, key, force?} — сменить/добавить/убрать ключ
                                    (удаление = П7-2: прокси провайдера удаляются из пула,
                                    боевой канал переключается по стратегии фоновым юнитом)
  POST /api/key/check               {provider} — живая проверка уже сохранённого ключа
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
  --- обновления с GitHub (vpn/UPDATE-PLAN.md) ---
  GET  /api/update/status           версии узла/маяка, когда проверялось, авто вкл/выкл, ход установки
  POST /api/update/check            сверить с маяком сейчас (отдельным процессом vpn-agent)
  POST /api/update/apply            {force?} обновиться сейчас: транзиентный юнит systemd-run
                                    redut-update (переживает рестарт самой панели в середине
                                    обновления); force — переустановить ТУ ЖЕ версию (лечение)
  POST /api/update/config           {auto: bool} — тумблер автообновления (config.json, точечно)
"""
import json
import os
import re
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
import update as update_mod        # noqa: E402
from providers import make_providers, ProviderError, PROVIDER_CLASSES  # noqa: E402
from webpanel import auth, views    # noqa: E402
from webpanel import clients as clients_mod   # noqa: E402
from webpanel import qrcode as qr_mod         # noqa: E402
from webpanel import sysinfo as sysinfo_mod   # noqa: E402
from webpanel import hygiene as hygiene_mod   # noqa: E402

ETC_CONFIG = "/etc/vpn-panel/config.json"
ETC_SECRETS = "/etc/vpn-panel/secrets.json"
CERT = "/etc/vpn-panel/panel.crt"
KEY = "/etc/vpn-panel/panel.key"

_DB_LOCK = threading.Lock()        # sqlite из потоков http-сервера — сериализуем доступ
_SECRETS_LOCK = threading.Lock()   # secrets.json правят и мастер, и экран ключей — по одному
_CONFIG_LOCK = threading.Lock()    # config.json: панель правит из него ровно одну настройку


def _has(row, col):
    """Есть ли колонка в sqlite3.Row (база могла остаться от старой схемы)."""
    try:
        return col in row.keys()
    except AttributeError:
        return col in (row or {})


def events_limit(qs, default=40, cap=500):
    """limit из query /api/events: нечисловое значение — дефолт, не 500-я ошибка."""
    try:
        n = int((qs.get("limit") or [str(default)])[0])
    except (TypeError, ValueError):
        n = default
    return max(1, min(n, cap))


def pool_view_order(rows, cfg, cur=None):
    """Порядок строк «Пула прокси» (П3): боевой — первым, дальше ровно как у ротации
    при текущей стратегии (таблица и превью «выбрало бы» обязаны совпадать: превью
    текущего не рассматривает). Без подъёма боевого колонка «качество» выглядела бы
    неотсортированной: его отображаемая оценка включает +15 стикинеса, а ключ
    ранжирования — нет (ревью 1.3.0). Строки вне ранжирования (чёрный список:
    rating is None) — в конец, стабильно по uid."""
    ranked = states_mod.rank_candidates(rows, cfg)
    order = {r["uid"]: i for i, r in enumerate(ranked)}
    return sorted(rows, key=lambda r: (not (cur and r["host"] == cur),
                                       r["uid"] not in order,
                                       order.get(r["uid"], 0), str(r["uid"])))


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


def _first_channel_kick():
    """После мастера: подтянуть пул и сразу подобрать первый канал (фоновый поток).

    Отдельным процессом vpn-agent (он перечитает secrets.json сам): pool-refresh, затем
    rotate --force --reason setup — force обходит окно повтора EMERGENCY (§8), в котором
    узел публичной сборки сидит с момента установки. Ошибки не роняют панель — только лог.
    """
    try:
        rc, out = _run_agent(["pool-refresh"], timeout=300)
        print("[setup] pool-refresh rc=%s: %s" % (rc, (out or "")[-300:].replace("\n", " | ")), flush=True)
        rc, out = _run_agent(["rotate", "--force", "--reason", "setup"], timeout=600)
        print("[setup] первый канал: rotate rc=%s: %s" % (rc, (out or "")[-300:].replace("\n", " | ")), flush=True)
    except Exception as e:      # noqa: BLE001 — фон, панель жить должна
        print("[setup] подбор первого канала не удался: %s" % e, flush=True)


def _pool_refresh_kick():
    """После смены ключа: подтянуть пул нового кабинета и сразу проверить новые
    каналы (фоновый поток, отдельный процесс).

    Ключ сменили — значит, скорее всего, сменился и кабинет: в пуле лежат прокси
    предыдущего аккаунта. vpn-agent перечитает secrets.json сам и сольёт список
    заново, а --probe-new тут же прогонит пробу по каналам, которых ещё ни разу
    не проверяли (жалоба владельца 19.08: прокси подгрузились, а проверки по
    стратегии не дождались — до двухчасового крона висели «не проверялся»).
    Таймаут с запасом: проба идёт по каналам последовательно, до ~30 с на каждый.
    Ошибки не роняют панель — только лог (как в _first_channel_kick)."""
    try:
        rc, out = _run_agent(["pool-refresh", "--probe-new"], timeout=900)
        print("[key] pool-refresh rc=%s: %s" % (rc, (out or "")[-300:].replace("\n", " | ")), flush=True)
    except Exception as e:      # noqa: BLE001 — фон, панель жить должна
        print("[key] pool-refresh не удался: %s" % e, flush=True)


def _switch_provider_kick(name):
    """П7-2: фоном увести боевой канал с провайдера, у которого удалили ключ.

    На узле — транзиентный юнит (как ротация, F6): переключение длинное (пробы +
    apply + verify), в потоке панели ему не место; коллизия имени юнита = «уже
    идёт» (дедуп повторных удалений ключей). В argv — только имя провайдера,
    прошедшее проверку по PROVIDER_CLASSES. -> (started, err)."""
    if os.name != "posix":
        threading.Thread(target=lambda: _run_agent(
            ["switch-provider", "--from", name, "--reason", "key-removed"], timeout=900),
            name="key-switch", daemon=True).start()
        return True, ""
    rc, out = apply_mod.run_cmd(["systemd-run", "--collect", "-p", "RuntimeMaxSec=900",
                                 "--unit", "redut-switch", "/usr/local/bin/vpn-agent",
                                 "switch-provider", "--from", name, "--reason", "key-removed"])
    if rc == 0 or "already" in (out or "").lower():
        return True, ""
    return False, (out or "systemd-run rc=%s" % rc)[:200]


def _strategy_switch_kick(uid):
    """Фоном применить лучший канал после смены стратегии.

    ``apply`` уже содержит безопасную цепочку probe -> config check -> backup ->
    apply -> verify -> rollback. Здесь лишь не держим HTTP-запрос открытым на
    время сетевых проб. uid приходит из нашей БД, а не из тела запроса.
    """
    if os.name != "posix":
        threading.Thread(target=lambda: _run_agent(["apply", uid], timeout=900),
                         name="strategy-switch", daemon=True).start()
        return True, ""
    rc, out = apply_mod.run_cmd(["systemd-run", "--collect", "-p", "RuntimeMaxSec=900",
                                 "--unit", "redut-strategy-switch",
                                 "/usr/local/bin/vpn-agent", "apply", uid])
    if rc == 0 or "already" in (out or "").lower():
        return True, ""
    return False, (out or "systemd-run rc=%s" % rc)[:200]


# ── ключи провайдеров: правка из панели (§12 POST /api/key) ──────────────────────────
# Ключ ходит только в одну сторону: панель принимает новый и показывает хвост
# (mask_key), но никогда не отдаёт сохранённый обратно — ни в API, ни в HTML.
#
# Набор символов узкий намеренно: ключ PROXY6 подставляется В ПУТЬ URL
# (providers/proxy6: /api/{key}/{method}/), поэтому слеш, «?», «%» и пробел в нём —
# это не «странный ключ», а испорченный запрос. Реальные ключи обоих провайдеров
# укладываются в hex/буквы/цифры с дефисами; если провайдер однажды выдаст что-то
# шире — расширять здесь, осознанно.
_RE_API_KEY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")


def mask_key(key):
    """Хвост ключа для показа человеку: «77b5…78f6». Сам ключ наружу не уходит."""
    k = str(key or "")
    if not k:
        return ""
    if len(k) <= 8:
        return "•" * len(k)
    return "%s…%s" % (k[:4], k[-4:])


def validate_key_format(key):
    """-> (ключ_без_пробелов_по_краям, ошибка_или_None). Проверка ДО обращения к API (§15)."""
    k = str(key or "").strip()
    if not k:
        return "", "пустой ключ"
    if not _RE_API_KEY.match(k):
        return k, ("ключ не похож на API-ключ: допустимы латинские буквы, цифры, точка, "
                   "двоеточие, дефис и подчёркивание (8–128 символов). Проверь, не скопировалось "
                   "ли вместе с ключом что-то лишнее")
    return k, None


def check_key(name, key):
    """Живая проверка ключа у провайдера (balance) -> (ok, info).

    info при успехе: {"balance", "currency"}; при отказе: {"error", "network"}.
    network=True — провайдер недоступен с сервера (не «ключ плохой»), см. providers/base.
    """
    cls = PROVIDER_CLASSES.get(name)
    if cls is None:
        return False, {"error": "неизвестный провайдер %r" % name, "network": False}
    try:
        b = cls(key).balance()
    except ProviderError as e:
        return False, {"error": str(e), "network": bool(e.network)}
    except Exception as e:      # noqa: BLE001 — чужой ответ не должен ронять панель
        return False, {"error": "%s: %s" % (type(e).__name__, e), "network": False}
    return True, {"balance": b.get("balance"), "currency": b.get("currency") or ""}


def provider_keys(secrets):
    """Имена провайдеров, у которых сейчас задан ключ."""
    return {n for n in PROVIDER_CLASSES if ((secrets or {}).get(n) or {}).get("api_key")}


def merge_key(secrets, name, key):
    """Копия secrets с записанным (key) или убранным (key=None/"") ключом провайдера.

    Остальные блоки — admin, smtp, второй провайдер — переносятся как есть; из блока
    провайдера убираем только api_key, а если в нём больше ничего нет — и сам блок."""
    data = dict(secrets or {})
    block = dict(data.get(name) or {})
    if key:
        block["api_key"] = key
        data[name] = block
    else:
        block.pop("api_key", None)
        if block:
            data[name] = block
        else:
            data.pop(name, None)
    return data


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

    def save_provider_key(self, name, key):
        """Записать (key) или убрать (key=None) ключ провайдера, не трогая остальное.

        Файл перечитываем с диска под локом, а не пишем копию из памяти: recovery-коды
        вычёркивает auth.consume_recovery_code мимо этого объекта, и запись устаревшей
        копии воскресила бы уже использованный код."""
        with _SECRETS_LOCK:
            data, _ = load_secrets()
            if not data:
                data = dict(self.secrets or {})
            self.write_secrets(merge_key(data, name, key))

    def save_strategy(self, name):
        """Записать стратегию стран в config.json и применить без рестарта.

        Правим ТОЧЕЧНО файл, из которого читали, а не выгружаем cfg целиком: load_config
        подмешивает в память значения по умолчанию (пути к БД, кольцу, sing-box, порт) и
        служебный `_source` — выгрузка зашила бы их в конфиг сервера навсегда.
        Лимиты трат остаются недосягаемы из браузера (§6.2) — здесь только одна строка."""
        if name not in country_mod.STRATEGIES:
            raise ValueError("неизвестная стратегия %r" % name)
        path = self.cfg.get("_source") or ETC_CONFIG
        with _CONFIG_LOCK:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            data.setdefault("countries", {})["strategy"] = name
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            try:
                os.chmod(tmp, 0o644)     # конфиг читает и агент из-под cron
            except OSError:
                pass
            os.replace(tmp, path)
            self.cfg.setdefault("countries", {})["strategy"] = name

    def save_update_auto(self, on):
        """Тумблер автообновления: точечная правка config.json (по образцу save_strategy —
        cfg целиком не выгружаем, чтобы не зашить в файл подмешанные дефолты)."""
        path = self.cfg.get("_source") or ETC_CONFIG
        with _CONFIG_LOCK:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            data.setdefault("update", {})["auto"] = bool(on)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            try:
                os.chmod(tmp, 0o644)     # конфиг читает и агент из-под cron
            except OSError:
                pass
            os.replace(tmp, path)
            self.cfg.setdefault("update", {})["auto"] = bool(on)

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
        is_cur = row["host"] == self.current_host()
        res["score"] = probe_mod.score(row, res, is_current=is_cur, cfg=self.cfg)
        with _DB_LOCK:
            self.pool.record_probe(row["uid"], res, is_current=is_cur,
                                   strategy=country_mod.strategy(self.cfg))
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
            # П3: боевой первым, дальше порядок перебора ротации при текущей стратегии
            # (чек-лист приёмки: «порядок совпадает с превью „выбрало бы“»)
            rows = pool_view_order(rows, APP.cfg, cur)
            return self._json(200, {"proxies": [self._pool_row(r, cur) for r in rows]})
        if path == "/api/events":
            limit = events_limit(qs)
            with _DB_LOCK:
                evs = APP.pool.conn.execute(
                    "SELECT ts,actor,action,result,detail FROM event ORDER BY id DESC LIMIT ?",
                    (limit,)).fetchall()
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
                stab = APP.pool.stability_all()
            # F8: надёжность пар (provider, страна) по опыту узла — для карточки «Деньги»
            st_out = []
            for s in stab:
                total = int(s["probes_ok"] or 0) + int(s["probes_fail"] or 0)
                if not total:
                    continue
                st_out.append({
                    "provider": s["provider"], "country": s["country"], "probes": total,
                    "days": int(money_mod._days_seen(s)),
                    "rel_pct": round(100.0 * int(s["probes_ok"] or 0) / total),
                    "drops": int(s["battle_drops"] or 0),
                    "learning": not money_mod.stability_mature(s, APP.cfg),
                    "bonus": money_mod.stability_bonus(s, APP.cfg)})
            st_out.sort(key=lambda x: (-x["probes"], x["country"]))
            return self._json(200, {"limits": money_mod.limits(APP.cfg),
                                    "today": {"buys": buys, "spent_rub": spent, "day": day},
                                    "stability": st_out,
                                    "rows": [dict(zip(("ts", "provider", "op", "uid", "price",
                                                       "currency", "balance_after"), r)) for r in rows]})
        if path == "/api/clients":
            try:
                return self._json(200, {"clients": clients_mod.list_clients(APP.cfg),
                                        "next_ip": clients_mod.next_free_ip(APP.cfg)})
            except clients_mod.ClientError as e:
                return self._json(500, {"error": str(e)})
        if path == "/api/key/status":
            return self._json(200, self._key_status())
        if path == "/api/strategy":
            return self._json(200, self._strategy_state())
        if path == "/api/update/status":
            return self._json(200, self._update_status())
        if path == "/api/ipinfo":
            return self._json(200, self._ipinfo())
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

        Белого списка больше нет (приёмка №7): отдаём ВСЕ страны провайдера, кроме
        чёрного списка, — человек вручную волен купить любую. Сортировка внутренним
        рейтингом (money.rank_countries), к каждой стране — её оценка для пометки
        в списке. Per-country getcount не гоняем (много стран × троттлинг — долго):
        наличие берём из getcountry, точный count считает уже поток покупки."""
        prov = APP.providers.get("proxy6")
        lim = money_mod.limits(APP.cfg)
        out = {"limits": lim, "available": [], "price": None}
        if prov is None:
            out["error"] = "нет ключа PROXY6"
            return out
        version = int(lim["buy_version"])
        period = int((qs.get("period") or [str(lim["buy_period_days"])])[0])
        out["version"], out["period"] = version, period
        try:
            avail = prov.getcountry(version)
            with _DB_LOCK:   # F8: rank_countries читает выученную стабильность
                ranked = money_mod.rank_countries(avail, APP.cfg, pool=APP.pool)
            out["available"] = [{"cc": cc, "tier": country_mod.tier(cc, True, APP.cfg)}
                                for cc in ranked]
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
            cur = APP.current_host()
            with _DB_LOCK:
                # active по ключам на диске (🔴 C2): осиротевшие провайдеры удаляются
                # из пула (П7-2), кроме строки боевого канала — её держим до переключения
                summary = APP.pool.refresh(APP.providers, actor="user",
                                           active=provider_keys(APP.secrets),
                                           keep_hosts={cur} if cur else None)
                for name, prov in APP.providers.items():
                    if name in summary["errors"]:
                        continue
                    try:
                        money_mod.store_balance(APP.pool, name, prov.balance())
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
            if os.name != "posix":
                # dev-режим: короткий no-op цикл влезает в таймаут — как раньше
                rc, out = _run_agent(["rotate", "--reason", "panel"])
                with _DB_LOCK:
                    st = APP.pool.get_setting("automat_state") or "OK"
                    APP.pool.log_event("panel-rotate", actor="user", result=st, src_ip=self._client_ip())
                return self._json(200, {"ok": rc == 0, "state": st, "output": (out or "")[-1500:]})
            # F6: транзиентный юнит вместо _run_agent с таймаутом 240 с — цикл с 5
            # кандидатами + apply + откат в таймаут не влезал, панель убивала агента
            # посреди работы с непредсказуемым состоянием маршрутов. RuntimeMaxSec
            # добивает зависший цикл (flock не держится вечно); коллизия имени юнита
            # = «ротация уже идёт» (бесплатный дедуп повторных кликов); в argv юнита —
            # только константы, никаких данных из тела запроса. UI поллит /api/status.
            rc, out = apply_mod.run_cmd(["systemd-run", "--collect", "-p", "RuntimeMaxSec=900",
                                         "--unit", "redut-rotate",
                                         "/usr/local/bin/vpn-agent", "rotate", "--reason", "panel"])
            busy = rc != 0 and "already" in (out or "").lower()
            with _DB_LOCK:
                APP.pool.log_event("panel-rotate", actor="user",
                                   result="started" if rc == 0 else ("busy" if busy else "fail"),
                                   src_ip=self._client_ip())
            if rc == 0:
                return self._json(200, {"ok": True, "started": True})
            if busy:
                return self._json(200, {"ok": True, "started": False, "busy": True})
            return self._json(500, {"error": "systemd-run не запустился: %s" % (out or "rc=%s" % rc)})
        if path == "/api/automat":
            # F7: пауза автоматики из панели (FROZEN) — тот же конвейер session+CSRF
            body = json.loads(self._body() or b"{}") or {}
            if not isinstance(body.get("frozen"), bool):
                return self._json(400, {"error": "ожидаю {frozen: true|false}"})
            with _DB_LOCK:
                APP.pool.set_setting("automat_frozen", "1" if body["frozen"] else None)
                APP.pool.log_event("automat-pause", actor="user",
                                   result="on" if body["frozen"] else "off",
                                   src_ip=self._client_ip())
            return self._json(200, {"ok": True, "frozen": body["frozen"]})
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
        if path == "/api/key":
            return self._do_key(json.loads(self._body() or b"{}") or {})
        if path == "/api/key/check":
            return self._do_key_check(json.loads(self._body() or b"{}") or {})
        if path == "/api/strategy":
            return self._do_strategy(json.loads(self._body() or b"{}") or {})
        if path == "/api/update/check":
            # Отдельным процессом vpn-agent (как rotate): та же кодовая дорожка, что у
            # крона, свой conn к БД; заодно агент сам напишет событие/письмо при новинке.
            rc, out = _run_agent(["self-update", "--check"], timeout=120)
            res = self._update_status()
            res.update({"ok": rc == 0, "output": (out or "")[-800:]})
            return self._json(200, res)
        if path == "/api/update/apply":
            return self._do_update_apply()
        if path == "/api/update/config":
            body = json.loads(self._body() or b"{}") or {}
            if not isinstance(body.get("auto"), bool):
                return self._json(400, {"error": "ожидаю {auto: true|false}"})
            APP.save_update_auto(body["auto"])
            with _DB_LOCK:
                APP.pool.log_event("update-auto", actor="user",
                                   result="on" if body["auto"] else "off", src_ip=self._client_ip())
            return self._json(200, self._update_status())
        self._json(404, {"error": "нет такого метода"})

    def _do_update_apply(self):
        """POST /api/update/apply {force?}: обновиться сейчас.

        force=true (1.6.0) — принудительная переустановка ТОЙ ЖЕ версии (лечение
        узла: скачать выпуск заново и прогнать установщик; анти-даунгрейд остаётся).

        Запускаем ТРАНЗИЕНТНЫМ юнитом (systemd-run): установка перезапустит саму
        панель, и работа, начатая в потоке этого сервера, погибла бы на середине.
        Юнит живёт отдельно от панели, прогресс пишется в /run и state — карточка
        дочитает исход после своего рестарта."""
        if os.name != "posix":
            return self._json(400, {"error": "обновление применяется только на сервере"})
        try:
            body = json.loads(self._body() or b"{}") or {}
        except ValueError:
            body = {}
        force = bool(body.get("force"))
        st = self._update_status()
        if st.get("applying"):
            return self._json(409, {"error": "обновление уже идёт"})
        if not st.get("latest"):
            return self._json(400, {"error": "сначала «Проверить сейчас» — панель ещё не знает свежую версию"})
        if not st.get("newer"):
            if not force:
                return self._json(400, {"error": "обновляться не на что: узел уже на %s"
                                                 % (st.get("local") or "?")})
            if str(st.get("latest")) != str(st.get("local") or ""):
                # анти-даунгрейд (Р3): принудительно можно только ту версию, что стоит
                return self._json(400, {"error": "принудительно можно переустановить только "
                                                 "текущую версию узла (%s), а в репозитории %s — "
                                                 "версии вниз не ставятся"
                                                 % (st.get("local") or "?", st.get("latest"))})
        target = str(st["latest"])
        cmd = ["systemd-run", "--unit", "redut-update", "--collect",
               "/usr/local/bin/vpn-agent", "self-update", "--apply", "--version", target]
        if force:
            cmd.append("--force")
        rc, out = apply_mod.run_cmd(cmd)
        with _DB_LOCK:
            APP.pool.log_event("update-apply-start", actor="user", result=target,
                               detail="принудительная переустановка" if force else "",
                               src_ip=self._client_ip())
        if rc != 0:
            return self._json(500, {"error": "systemd-run не запустился: %s" % (out or "rc=%s" % rc)})
        return self._json(200, {"ok": True, "started": target, "force": force})

    # ------------------------------------------------ стратегия стран (§6.1)
    def _strategy_state(self):
        """GET /api/strategy: четыре стратегии + что изменится ПРЯМО СЕЙЧАС.

        Абстрактное описание («репутация важнее скорости») человеку мало что говорит,
        поэтому к каждой стратегии считаем живые факты: кого из нынешнего пула она
        считает лучшим — ВКЛЮЧАЯ текущий канал (П3: превью обязано совпадать с
        порядком таблицы пула; раньше текущий исключался, и все стратегии «выбирали»
        одного и того же запасного), какие страны пула проходят её авто-гейт покупки
        и где докупка разрешена. Всё считается на месте, без обращений к провайдеру."""
        cur_host = APP.current_host()
        with _DB_LOCK:
            rows = APP.pool.rotation_candidates()
        rows = [r for r in rows if r["provider"] in APP.providers]   # только активные (П7)
        pool_cc = []
        for r in rows:
            cc = (r["exit_cc"] if _has(r, "exit_cc") and r["exit_cc"] else r["country"])
            if cc and cc not in pool_cc:
                pool_cc.append(cc)
        out = []
        for sid in country_mod.STRATEGIES:
            cfg = dict(APP.cfg)
            cfg["countries"] = dict(APP.cfg.get("countries") or {}, strategy=sid)
            st = country_mod.strategy_info(name=sid)
            top = states_mod.rank_candidates(rows, cfg)[:1]
            with _DB_LOCK:   # F8: buy_candidates читает выученную стабильность из БД
                buy = money_mod.buy_candidates(cfg, available=pool_cc, pool=APP.pool)
            pick = self._brief(top[0]) if top else None
            if pick is not None:
                pick["is_current"] = bool(cur_host and pick["host"] == cur_host)
            # авто-гейт покупки над странами ИМЕЮЩЕГОСЯ пула: наглядно, чем стратегии
            # отличаются друг от друга на живых данных (а не только за кромкой топ-8)
            pool_pass = [c for c in pool_cc if country_mod.auto_allowed(c, True, cfg)]
            out.append({"id": sid, "title": st["title"], "short": st["short"], "desc": st["desc"],
                        "current": sid == country_mod.strategy(APP.cfg),
                        "buy": buy[:8], "buy_total": len(buy),
                        "buy_mode": ("gated" if st.get("auto_gate") else "open"),
                        "pool_pass": pool_pass,
                        "pool_block": [c for c in pool_cc if c not in pool_pass],
                        "pick": pick})
        return {"current": country_mod.strategy(APP.cfg), "strategies": out,
                "blacklist": sorted(country_mod.blacklist(APP.cfg)),
                "pool_size": len(rows)}

    @staticmethod
    def _brief(row):
        """Кандидат одной строкой — для предпросмотра «кого выбрала бы стратегия»."""
        cc = (row["exit_cc"] if _has(row, "exit_cc") and row["exit_cc"] else row["country"])
        return {"uid": row["uid"], "host": row["host"], "cc": cc}

    def _do_strategy(self, body):
        """POST /api/strategy {strategy} — сменить правило выбора стран.

        Если лучший канал новой стратегии отличается от текущего, сразу запускаем
        штатный безопасный apply в фоне. Чёрный список не трогает никакая стратегия."""
        name = str(body.get("strategy") or "").strip().lower()
        if name not in country_mod.STRATEGIES:
            return self._json(400, {"error": "неизвестная стратегия"})
        was = country_mod.strategy(APP.cfg)
        if name != was:
            APP.save_strategy(name)
            with _DB_LOCK:
                APP.pool.log_event("strategy", actor="user", result=name,
                                   detail="было: %s" % was, src_ip=self._client_ip())
        state = self._strategy_state()
        selected = next((s for s in state["strategies"] if s["id"] == name), None)
        pick = (selected or {}).get("pick")
        # Повторный выбор активной стратегии тоже должен исправить дрейф:
        # пул мог обновиться уже после её сохранения, и лучшим стал другой канал.
        switch_needed = bool(pick and not pick.get("is_current"))
        switch_started, switch_error = False, ""
        if switch_needed:
            switch_started, switch_error = _strategy_switch_kick(pick["uid"])
            with _DB_LOCK:
                APP.pool.log_event("strategy-apply", actor="user",
                                   result="started" if switch_started else "fail",
                                   detail="%s -> %s%s" % (name, pick["uid"],
                                          (": " + switch_error) if switch_error else ""),
                                   src_ip=self._client_ip())
        state.update({"ok": True, "was": was, "changed": name != was,
                      "switch_needed": switch_needed, "switch_started": switch_started,
                      "switch_error": switch_error, "target": pick})
        return self._json(200, state)

    # ------------------------------------------------ обновления (UPDATE-PLAN)
    def _update_status(self):
        """GET /api/update/status: версии и настройки — без сети (открытие страницы).

        Живой поход к маяку — только по кнопке (POST /api/update/check) или по крону:
        GitHub с опроса каждой загрузки дашборда нам ни к чему."""
        u = update_mod.update_cfg(APP.cfg)
        st = update_mod.load_state(APP.cfg)
        local = update_mod.node_version()
        latest = st.get("latest_seen")
        bad = st.get("bad_versions") or []
        live = update_mod.status_read()
        applying = bool(live and live.get("phase") in
                        ("check", "download", "backup", "install", "verify", "rollback"))
        if os.name == "posix":
            # На узле верим живым признакам, а не фазе в /run (могла остаться от kill -9):
            # лок redut-update держат ОБА пути (кнопка через systemd-run и ночной крон) —
            # без пробы лока крон-обновление было бы для панели невидимым (ревью 17.08).
            lock_busy = False
            try:
                with apply_mod.Flock(update_mod.LOCK_PATH):
                    pass
            except apply_mod.ApplyError:
                lock_busy = True
            rc, act = apply_mod.run_cmd(["systemctl", "is-active", "redut-update"])
            applying = lock_busy or (act or "").strip() in ("active", "activating")
        return {"local": local, "latest": latest,
                "newer": update_mod.is_newer(latest, local),
                "bad": latest in bad, "bad_versions": bad,
                "last_check": st.get("last_check"), "last_error": st.get("last_error"),
                "last_apply": st.get("last_apply"), "live": live, "applying": applying,
                "auto": u["auto"], "window": u["window"],
                "window_ok": update_mod.window_covers_cron(u["window"]),
                "repo": u["repo"]}

    # ------------------------------------------------ паспорт IP выхода (карта)
    def _ipinfo(self):
        """GET /api/ipinfo: технический паспорт ТЕКУЩЕГО IP выхода — для оверлея
        на карте (ASN, оператор, город, пояс, PTR, датацентр).

        Только текущий egress — панель не превращается в geoip-сервис по
        произвольным адресам. Ответ публичных баз кэшируется в setting по IP
        (probe.INTEL_TTL_S): сеть дёргается один раз на новый адрес, а не на
        каждое открытие дашборда; чужие ключи ipintel:* подчищаются, чтобы
        setting не пух от истории адресов."""
        with _DB_LOCK:
            eg = APP.pool.get_egress()
        ip = (eg or {}).get("egress") or ""
        if not ip:
            return {"ok": False, "ip": "", "why": "выход ещё не проверялся"}
        key = "ipintel:%s" % ip
        with _DB_LOCK:
            raw = APP.pool.get_setting(key)
        if raw:
            try:
                data = json.loads(raw)
            except ValueError:
                data = None
            age = states_mod.age_seconds((data or {}).get("at"))
            # кэш старого формата (без риск-разведки, v < INTEL_VERSION) не годится —
            # перечитываем источники, как будто кэша не было
            if (data and data.get("intel") and age is not None
                    and age < probe_mod.INTEL_TTL_S
                    and (data["intel"] or {}).get("v") == probe_mod.INTEL_VERSION):
                return {"ok": True, "ip": ip, "cached_at": data.get("at"),
                        "intel": data["intel"]}
        # пинг до боевого прокси — из последнего замера пула (ничего не меряем)
        ping = None
        cur = APP.current_host()
        if cur:
            with _DB_LOCK:
                for r in APP.pool.list(include_gone=True):
                    if r["host"] == cur and _has(r, "latency_ms"):
                        ping = r["latency_ms"]
                        break
        # риск-источники по ключам (не обязательны): secrets.json -> "ipintel"
        keys = (APP.secrets.get("ipintel") or {}) if isinstance(APP.secrets, dict) else {}
        intel = probe_mod.ip_intel_full(ip, keys=keys, ping_ms=ping)  # сеть — ВНЕ лока БД
        if not intel:
            return {"ok": False, "ip": ip, "why": "гео-базы не ответили"}
        with _DB_LOCK:
            APP.pool.conn.execute("DELETE FROM setting WHERE key LIKE 'ipintel:%' AND key != ?",
                                  (key,))
            APP.pool.set_setting(key, json.dumps({"at": pool_mod.now_iso(), "intel": intel},
                                                 ensure_ascii=False))
        return {"ok": True, "ip": ip, "intel": intel}

    # ------------------------------------------------ ключи провайдеров (§12)
    def _key_status(self):
        """GET /api/key/status: задан ли ключ, его хвост, баланс из кэша, живых в пуле.

        Живьём провайдера здесь не дёргаем — это открытие страницы. Проверка по кнопке:
        POST /api/key/check."""
        with _DB_LOCK:
            rows = APP.pool.list(include_gone=True)
            balances = {k.split(":", 1)[1]: v for k, v in
                        APP.pool.conn.execute("SELECT key,value FROM setting WHERE key LIKE 'balance:%'")}
        out = []
        for name in PROVIDER_CLASSES:
            key = ((APP.secrets or {}).get(name) or {}).get("api_key")
            # без ключа не показываем ни «живых», ни баланс — панель их не видит (П7)
            out.append({"provider": name, "set": bool(key), "masked": mask_key(key),
                        "balance": (balances.get(name) or "") if key else "",
                        "alive": len([r for r in rows if r["provider"] == name and not r["gone"]])
                                 if key else 0})
        return {"providers": out}

    def _do_key(self, body):
        """POST /api/key {provider, key, force?} — сменить, добавить или убрать ключ.

        Ключ проверяется живьём (balance) ДО записи: отвергнутый провайдером не сохраняем.
        «Нет связи» — не приговор ключу (у RU-хостера PROXY6 закрыт напрямую, приёмка 15.08):
        отвечаем needs_force, и по подтверждению человека кладём ключ непроверенным — узел
        достучится до API через собственный канал (providers/base, транспорт tun0).
        Пустой key убирает ключ; последний оставшийся убрать нельзя — панель ослепнет.
        """
        name = str(body.get("provider") or "").strip()
        if name not in PROVIDER_CLASSES:
            return self._json(400, {"error": "неизвестный провайдер"})
        raw = body.get("key")
        if raw is None or not str(raw).strip():
            return self._do_key_delete(name)
        key, bad = validate_key_format(raw)
        if bad:
            return self._json(400, {"error": bad})
        ok, info = check_key(name, key)
        if not ok and not info.get("network"):
            return self._json(400, {"error": "ключ не принят: %s" % info["error"]})
        if not ok and not body.get("force"):
            # провайдер недоступен с сервера — решает человек (сохранить без проверки?)
            return self._json(200, {"ok": False, "saved": False, "needs_force": True,
                                    "network": True, "error": info["error"]})
        APP.save_provider_key(name, key)
        if ok:
            with _DB_LOCK:
                money_mod.store_balance(APP.pool, name, info)
        with _DB_LOCK:
            APP.pool.log_event("key-set", actor="user", result="ok" if ok else "unverified",
                               detail=name, src_ip=self._client_ip())
        # кабинет сменился — список прокси в кэше уже не про него
        threading.Thread(target=_pool_refresh_kick, name="key-pool-refresh", daemon=True).start()
        return self._json(200, {"ok": True, "saved": True, "verified": bool(ok),
                                "provider": name, "masked": mask_key(key),
                                "balance": info.get("balance"), "currency": info.get("currency"),
                                "error": "" if ok else info["error"]})

    def _do_key_delete(self, name):
        """Убрать ключ провайдера (П7-2, 1.6.0): его прокси сразу УДАЛЯЮТСЯ из пула
        (управлять ими больше нечем; раньше висели «пропал» навсегда — жалоба
        владельца 18.08), кэш баланса убирается. Если боевой канал на этом
        провайдере — он продолжает работать (правило «держать IP» на время
        манёвра), а фоном запускается плановое переключение по текущей стратегии
        (проба -> apply -> verify -> автооткат, states.switch_from_provider);
        до переключения строка боевого видна в пуле с пометкой «пропал»."""
        # проверка «последнего ключа» и запись — под ОДНИМ локом по данным с диска
        # (ревью 1.3.0): два одновременных удаления разных провайдеров иначе оба
        # проходили проверку и оставляли панель слепой
        with _SECRETS_LOCK:
            data, _ = load_secrets()
            if not data:
                data = dict(APP.secrets or {})
            if not ((data or {}).get(name) or {}).get("api_key"):
                return self._json(400, {"error": "у %s и так нет ключа" % name})
            if provider_keys(data) <= {name}:
                return self._json(400, {"error": "это последний ключ: без него панель не увидит пул, "
                                                 "не купит замену и не продлит боевой прокси. "
                                                 "Сначала впиши рабочий ключ другого провайдера"})
            APP.write_secrets(merge_key(data, name, None))
        cur_host = APP.current_host()
        with _DB_LOCK:
            battle = None
            if cur_host:
                battle = APP.pool.conn.execute(
                    "SELECT uid FROM proxy WHERE provider=? AND host=?",
                    (name, cur_host)).fetchone()
            pr = APP.pool.purge_provider(name, keep_hosts=({cur_host} if battle else None))
            APP.pool.conn.execute("DELETE FROM setting WHERE key=?", ("balance:%s" % name,))
            APP.pool.conn.commit()
            APP.pool.log_event("key-del", actor="user", result="ok",
                               detail="%s: удалено из пула %d, баланс убран%s"
                               % (name, pr["deleted"],
                                  "; боевой на нём — переключаю по стратегии" if battle else ""),
                               src_ip=self._client_ip())
        warning = ""
        switching = False
        if battle:
            switching, err = _switch_provider_kick(name)
            warning = ("Боевой канал принадлежит %s: он продолжает работать, а панель уже "
                       "переключает его на другого провайдера по текущей стратегии "
                       "(проверка → переключение → проверка → автооткат). Если живых "
                       "кандидатов не найдётся, канал останется как есть, письмо расскажет, "
                       "и попытка повторится при следующем обновлении пула" % name)
            if err:
                warning += ". Не удалось запустить переключение сейчас (%s) — " \
                           "его сделает ближайший цикл обновления пула" % err
        return self._json(200, {"ok": True, "deleted": True, "provider": name,
                                "purged": pr["deleted"], "battle": bool(battle),
                                "switch_started": switching, "warning": warning})

    def _do_key_check(self, body):
        """POST /api/key/check {provider} — живая проверка уже сохранённого ключа."""
        name = str(body.get("provider") or "").strip()
        if name not in PROVIDER_CLASSES:
            return self._json(400, {"error": "неизвестный провайдер"})
        key = ((APP.secrets or {}).get(name) or {}).get("api_key")
        if not key:
            return self._json(400, {"error": "у %s не задан ключ" % name})
        ok, info = check_key(name, key)
        with _DB_LOCK:
            if ok:
                money_mod.store_balance(APP.pool, name, info)
            APP.pool.log_event("key-check", actor="user",
                               result="ok" if ok else ("no-link" if info.get("network") else "fail"),
                               detail="%s: %s" % (name, info.get("error", "")) if not ok else name,
                               src_ip=self._client_ip())
        return self._json(200, {"ok": ok, "provider": name, "balance": info.get("balance"),
                                "currency": info.get("currency"), "network": info.get("network", False),
                                "error": info.get("error", "")})

    # ------------------------------------------------ деньги (§6, гейты money.py)
    def _do_buy(self, body):
        """POST /api/buy {country?, period?} — гейты §6.2 + идемпотентность +
        постфактум-проба страны выхода §6.1. Те же гейты, что и у agent.py buy."""
        prov = APP.providers.get("proxy6")
        if prov is None:
            return self._json(400, {"error": "нет ключа PROXY6 — покупка недоступна"})
        lim = money_mod.limits(APP.cfg)
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
        # страну назвали — берём её; нет — идём по умной оценке (репутация +
        # выученная стабильность F8, лучшие страны первыми)
        if country:
            cands = [country]
        else:
            with _DB_LOCK:
                cands = money_mod.buy_candidates(APP.cfg, pool=APP.pool)
        pick = None
        for cc in cands:
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
        return self._json(200, {"ok": True, "warning": warn,
                                "recovered": r["recovered"], "price": r["price"],
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
            # П9: ручное «В бой» для off разрешено, но успешный apply переводит off->auto —
            # иначе боевой канал невидим selectable_candidates и подсчёту резерва (N+1
            # решал бы «резерва нет» при живом боевом).
            if row["role"] == "off":
                APP.pool.set_role(row["uid"], "auto")
                APP.pool.log_event("role", actor="auto", to_uid=row["uid"], result="auto",
                                   detail="успешный apply переводит off->auto (П9)")
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
            if path == "/api/setup/smtp/test":
                return self._setup_smtp_test(body)
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
        """Валидируем ключи живьём (balance). proxy6 в приоритете (умеет возврат).

        Ключ, который не удалось ПРОВЕРИТЬ из-за недоступности провайдера с сервера
        (ProviderError.network — например, PROXY6 закрыт у российского хостера SNI-блокировкой,
        приёмка 15.08), НЕ выбрасываем: сохраняем как «непроверенный» рядом с хотя бы одним
        рабочим ключом. После установки узел ходит к такому провайдеру через собственный канал
        (providers/base: транспорт tun0), и ключ заработает без правки secrets.json по SSH.
        Ключ, ОТВЕРГНУТЫЙ провайдером (ответ API: неверный ключ), не сохраняем.
        """
        res, keys, verified = {}, {}, 0
        for name in PROVIDER_CLASSES:
            key = (body.get(name) or "").strip()
            if not key:
                continue
            key, bad = validate_key_format(key)     # та же проверка, что и у экрана ключей
            if bad:
                res[name] = {"ok": False, "error": bad}
                continue
            ok, info = check_key(name, key)
            if ok:
                res[name] = {"ok": True, "balance": info["balance"], "currency": info["currency"]}
                keys[name] = key
                verified += 1
            elif info["network"]:
                res[name] = {"ok": False, "network": True, "saved_unverified": True, "error": info["error"]}
                keys[name] = key
            else:
                res[name] = {"ok": False, "error": info["error"]}
        if not verified:
            for name, r in res.items():
                r.pop("saved_unverified", None)     # без единого проверенного ключа не сохраняем ничего
            return self._json(400, {"error": "нужен хотя бы один рабочий ключ", "result": res})
        APP.setup["providers"] = keys
        return self._json(200, {"result": res})

    # Почта включается ТОЛЬКО после реальной проверки связи: мастер шлёт код на ящик,
    # человек вписывает его обратно. Так «сохранено» означает «письма правда доходят», а не
    # «поля заполнены» — до этого узел дважды оставался без алертов, ничего об этом не сказав
    # (пустой «from» 18.08, логины-не-адреса). Обойти можно только явным «Пропустить».
    CODE_TTL_S = 20 * 60          # письмо может идти минуты — не торопим
    CODE_TRIES = 5                # защита от подбора шестизначного кода

    def _smtp_fields(self, body):
        """(smtp, ошибка) — разбор и проверки полей шага «почта».

        Ошибка возвращается СЛОВАРЁМ для _json(400, …), а не готовым ответом: _json ничего
        не возвращает, и «return None, self._json(...)» не прерывал бы вызывающего — тот
        дописал бы в тот же ответ второе тело (поймано тестом 18.08).
        """
        smtp = {k: body.get(k) for k in ("host", "port", "user", "password", "from", "to")}
        if not (smtp["host"] and smtp["to"]):
            return None, {"error": "нужны минимум host и to (или «Пропустить»)"}
        try:
            smtp["port"] = int(smtp["port"] or 587)
        except (TypeError, ValueError):
            return None, {"error": "порт — число"}
        # Адрес получателя проверяем на входе, а не когда первый алерт молча не уйдёт
        # (501 Invalid MAIL FROM): «to» должен быть настоящим e-mail.
        if not alerts_mod._valid_email(smtp["to"]):
            return None, {"error": "«кому слать» — не похоже на e-mail адрес "
                                   "(например you@example.com)"}
        # «from» мастер спрашивает только когда логин не адрес (см. need_from ниже).
        if smtp.get("from") and not alerts_mod._valid_email(smtp["from"]):
            return None, {"error": "«адрес отправителя», если задан, должен быть "
                                   "e-mail адресом"}
        if not smtp.get("from"):
            smtp.pop("from", None)          # не сорить null-ом в secrets.json
        # Отказываем, если с этими данными письмо УЙТИ НЕ МОЖЕТ. Условие — то же, каким живёт
        # отправка (Alerter.configured): обычно отправитель берётся из логина, но логин не всегда
        # адрес (u123456, apikey, postmaster) — тогда просим адрес отправителя, а не делаем вид,
        # что почта настроена.
        if not alerts_mod.Alerter(smtp=smtp).configured:
            return None, {"error": "письма отправлять не с чего: логин SMTP не почтовый адрес — "
                                   "укажите адрес отправителя",
                          "need_from": True}
        return smtp, None

    def _setup_smtp_test(self, body):
        """Отправить код на указанный ящик. Ничего не сохраняем — только запоминаем ожидание."""
        import secrets as _s
        smtp, err = self._smtp_fields(body)
        if err:
            return self._json(400, err)
        code = "%06d" % _s.randbelow(1000000)
        alerter = alerts_mod.Alerter(smtp=smtp, server=APP.cfg.get("server") or "узел",
                                     log=lambda m: None)
        ok = alerter.send("проверка почты — код %s" % code,
                          "Код проверки: %s\n\nВпишите его в мастере настройки узла — только "
                          "после этого узел начнёт слать сюда тревожные письма.\n"
                          "Если вы ничего не настраивали, просто удалите это письмо." % code)
        if not ok:
            return self._json(400, {"error": "письмо не ушло: %s"
                                             % (alerter.last_error or "проверьте сервер, порт, "
                                                                      "логин и пароль")})
        APP.setup["smtp_pending"] = {"smtp": smtp, "code": code, "tries": 0, "at": time.time()}
        return self._json(200, {"sent": True, "to": smtp["to"]})

    def _setup_smtp(self, body):
        if body.get("skip"):
            APP.setup.pop("smtp", None)
            APP.setup.pop("smtp_pending", None)
            APP.setup["smtp_done"] = True
            return self._json(200, {"skipped": True})
        pend = APP.setup.get("smtp_pending")
        if not pend:
            return self._json(400, {"error": "сначала нажмите «Проверить связь» — узел пришлёт "
                                             "код на этот ящик", "need_test": True})
        if time.time() - pend["at"] > self.CODE_TTL_S:
            APP.setup.pop("smtp_pending", None)
            return self._json(400, {"error": "код устарел — проверьте связь заново",
                                    "need_test": True})
        if pend["tries"] >= self.CODE_TRIES:
            APP.setup.pop("smtp_pending", None)
            return self._json(400, {"error": "слишком много попыток — проверьте связь заново",
                                    "need_test": True})
        # Поля правили после отправки кода? Сохранить «проверенным» можно только то, что
        # проверяли: иначе правка молча уехала бы мимо проверки.
        if body.get("host"):
            smtp, err = self._smtp_fields(body)
            if err:
                return self._json(400, err)
            if smtp != pend["smtp"]:
                APP.setup.pop("smtp_pending", None)
                return self._json(400, {"error": "данные почты изменились — проверьте связь заново",
                                        "need_test": True})
        code = (body.get("code") or "").strip()
        if not (code and auth.hmac.compare_digest(code, pend["code"])):
            pend["tries"] += 1
            left = self.CODE_TRIES - pend["tries"]
            return self._json(400, {"error": "код не совпал%s"
                                             % (" (осталось попыток: %d)" % left if left > 0 else
                                                " — проверьте связь заново")})
        APP.setup["smtp"] = pend["smtp"]
        APP.setup["smtp_done"] = True
        APP.setup.pop("smtp_pending", None)
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
        # Первый канал — сразу, а не по расписанию. До этого узел (публичная сборка) сидит в
        # EMERGENCY с окном повтора 15 мин, и после мастера человек ждал до четверти часа
        # (приёмка 15.08: ключ введён 15:51, канал появился 15:54 — просто повезло с окном).
        # Фоном: подтянуть пул у провайдеров и прогнать машину состояний с --force
        # (обходит окно повтора аварии). Ответ мастеру не ждёт — /login открывается сразу.
        threading.Thread(target=_first_channel_kick, name="first-channel", daemon=True).start()
        return self._json(200, {"ok": True, "next": "/login"})

    # ------------------------------------------------ сборка status/pool
    def _status(self):
        sb = APP.read_singbox() or {}
        out = {"server": APP.cfg.get("server"), "role": APP.cfg.get("role"),
               "version": update_mod.node_version(),
               "subnet": APP.cfg.get("subnet"), "final": (sb.get("route") or {}).get("final"),
               "singbox": "?", "upstream": {}, "balances": {}, "egress": None,
               # полоска «Сервер» в шапке: нагрузка/память/диск/swap + оценка
               # вместимости. Всё из /proc без subprocess — дёшево на каждый
               # 30-секундный опрос; вне Linux здесь None, полоска прячется.
               "sys": sysinfo_mod.snapshot(),
               # гигиена узла для карточки статуса: белый список РФ (домены/сети/когда
               # обновляли) и очистка следов (когда, сколько за сутки) — из файлов, без
               # subprocess, как sys. has_dnsmasq берём из конфига узла.
               "hygiene": hygiene_mod.snapshot(APP.cfg)}
        for o in sb.get("outbounds", []):
            if o.get("tag") == "socks-out":
                out["upstream"]["socks_out"] = "%s:%s %s" % (o.get("server"), o.get("server_port"), o.get("type"))
            if o.get("tag") == "http-tg":
                out["upstream"]["http_tg"] = "%s:%s %s" % (o.get("server"), o.get("server_port"), o.get("type"))
        out["rotate_busy"] = False
        if os.name == "posix":
            rc, act = apply_mod.run_cmd(["systemctl", "is-active", "sing-box"])
            out["singbox"] = act or "?"
            # F6: ротация из панели идёт транзиентным юнитом — фронт поллит её ход
            rc, ract = apply_mod.run_cmd(["systemctl", "is-active", "redut-rotate"])
            out["rotate_busy"] = (ract or "").strip() in ("active", "activating")
            # П7-2: плановое переключение с провайдера без ключа — тоже юнит
            rc, sact = apply_mod.run_cmd(["systemctl", "is-active", "redut-switch"])
            out["switch_busy"] = (sact or "").strip() in ("active", "activating")
        with _DB_LOCK:
            rows = APP.pool.list(include_gone=True)
            # только провайдеры с ключом: осиротевший пул — не «живой» (П7)
            out["pool_alive"] = len([r for r in rows
                                     if not r["gone"] and r["provider"] in APP.providers])
            # карта выхода: страны живых прокси — точки «куда можно переключиться».
            # Запрещённые страны не показываем: панель ими всё равно не пользуется.
            bl = country_mod.blacklist(APP.cfg)
            ccs = set()
            for r in rows:
                if r["gone"] or r["provider"] not in APP.providers:
                    continue
                c = (r["exit_cc"] if _has(r, "exit_cc") and r["exit_cc"] else r["country"]) or ""
                c = c.strip().lower()
                if c and c not in bl:
                    ccs.add(c)
            out["pool_cc"] = sorted(ccs)
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
        st = country_mod.strategy_info(APP.cfg)
        out["strategy"] = st["id"]
        out["strategy_title"] = st["title"]
        out["strategy_short"] = st["short"]
        out["auto_prolong"] = states_mod.auto_prolong_cfg(APP.cfg)
        return out

    def _pool_row(self, r, cur):
        days = probe_mod.days_left(r["date_end"])
        cc = r["exit_cc"] if _has(r, "exit_cc") and r["exit_cc"] else r["country"]
        agree = True if not _has(r, "geo_agree") or r["geo_agree"] is None else bool(r["geo_agree"])
        # П1: строка запрещённой страны прячется фронтом. Проверяем ВСЕ ТРИ известные
        # страны строки — probe дисквалифицирует по любой из geoip-баз (probe.py),
        # отображение должно совпадать с автоматикой, иначе строка «только по второй
        # базе в блоке» просочится в таблицу.
        blocked = any(country_mod.is_blocked(x, APP.cfg) for x in (
            r["exit_cc"] if _has(r, "exit_cc") else None,
            r["exit_cc_alt"] if _has(r, "exit_cc_alt") else None,
            r["country"]))
        is_cur = bool(cur and r["host"] == cur)
        # П3: оценка на лету под текущую стратегию (колонка score в БД — лишь
        # последний замер той стратегии, что была активна в момент пробы)
        live_score, _ = probe_mod.score_from_row(r, APP.cfg, is_current=is_cur)
        # подпись страны — глазами АКТИВНОЙ стратегии (приёмка №7): под «скорость
        # и отклик» страна на оценку не влияет, и тревожный бейдж «спорная» врал бы
        st_info = country_mod.strategy_info(APP.cfg)
        if not st_info["country_first"] and not st_info["weight"]:
            cc_mode = "ignored"    # «скорость и отклик»: решают только замеры
        else:
            cc_mode = "rated"      # репутация/баланс — обычный бейдж по рейтингу
        return {"uid": r["uid"], "provider": r["provider"], "country": r["country"],
                "provider_active": r["provider"] in APP.providers,
                "host": r["host"], "port_socks5": r["port_socks5"], "port_http": r["port_http"],
                "role": r["role"], "score": live_score, "gone": r["gone"], "blocked": blocked,
                "cc_mode": cc_mode,
                "latency": r["latency_ms"] if _has(r, "latency_ms") else None,
                "socks_ok": r["socks_ok"], "http_ok": r["http_ok"], "tg_ok": r["tg_ok"],
                "days": None if days is None else round(days),
                "last_probe": (r["last_probe_at"] or "")[5:16],
                "is_current": is_cur,
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


def requires_tls(cfg):
    """Боевой узел (в конфиге внешний server_ip) обязан работать по HTTPS — HTTP-фолбэк только
    для локальной разработки (server_ip пуст или loopback). Снос №6: без этого панель на чистой
    установке молча уходила в HTTP при гонке выпуска сертификата."""
    server_ip = str((cfg or {}).get("server_ip") or "").strip()
    return bool(server_ip) and not server_ip.startswith("127.") and server_ip != "::1"


# Таймаут клиентского соединения (с): TLS-рукопожатие, чтение запроса и простой keep-alive
# не должны длиться вечно. Без него медленный/молчащий клиент (сканер, slowloris) держит
# поток и сокет бесконечно.
_CONN_TIMEOUT = 30


class PanelHTTPSServer(ThreadingHTTPServer):
    """HTTPS-сервер панели: TLS-рукопожатие НЕ в главном потоке приёма + таймаут соединения.

    Штатный приём оборачивает СЛУШАЮЩИЙ сокет (`ctx.wrap_socket(httpd.socket)`), из-за чего
    accept() выполняет TLS-рукопожатие прямо в главном потоке: один клиент, не завершающий
    рукопожатие (сканер/slowloris), блокирует приём ВСЕХ остальных — процесс жив, порт слушает,
    а панель «висит» (найдено на node2 19.08). Здесь accept() отдаёт сокет сразу
    (`do_handshake_on_connect=False` — рукопожатие откладывается до первого чтения, а оно уже
    в потоке-обработчике), и на соединение поставлен таймаут: медленный клиент занимает лишь
    свой поток и отваливается сам, не трогая остальных."""

    daemon_threads = True
    ssl_ctx = None            # ставится в main(), когда есть cert/key (иначе dev-HTTP)

    def get_request(self):
        sock, addr = self.socket.accept()      # обычный TCP-приём — без рукопожатия, быстрый
        sock.settimeout(_CONN_TIMEOUT)
        if self.ssl_ctx is not None:
            # рукопожатие отложено (do_handshake_on_connect=False): произойдёт при первом
            # чтении в рабочем потоке под таймаутом выше, а не здесь, в главном цикле приёма
            sock = self.ssl_ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        return sock, addr

    def handle_error(self, request, client_address):
        pass                  # битые/медленные соединения (сканеры) не шумят в лог (OPSEC, как log_message)


def main():
    global APP
    APP = App()
    port = int(APP.cfg.get("panel_port") or 8443)
    if not APP.provisioned:
        print("⚠️ Панель НЕ настроена — открой https://<host>:%d/setup (мастер первого входа: "
              "провайдер, 2FA, пароль, почта)" % port, file=sys.stderr)
    threading.Thread(target=_pulse_monitor, daemon=True).start()   # §6.3 пульс агента
    httpd = PanelHTTPSServer(("0.0.0.0", port), Handler)
    # На РЕАЛЬНОМ узле (в конфиге прописан внешний server_ip) панель обязана работать по HTTPS:
    # пароль и TOTP не должны идти открытым текстом. При гонке старта (установщик ещё выпускает
    # cert) коротко подождём его появления, и только dev-запуск без server_ip уходит в HTTP.
    # Найдено на приёмке 15.08 (снос №6): cert выпускался после старта -> панель молча на HTTP.
    on_server = requires_tls(APP.cfg)
    if on_server and not (os.path.isfile(CERT) and os.path.isfile(KEY)):
        for _ in range(20):
            time.sleep(0.5)
            if os.path.isfile(CERT) and os.path.isfile(KEY):
                break
    if os.path.isfile(CERT) and os.path.isfile(KEY):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT, KEY)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        httpd.ssl_ctx = ctx     # рукопожатие делает PanelHTTPSServer.get_request (в потоке, под таймаутом)
        scheme = "https"
    elif on_server:
        # cert так и не появился, но это боевой узел — HTTP недопустим, лучше упасть (systemd
        # перезапустит через RestartSec, а установщик к тому времени выпустит cert).
        sys.exit("НЕТ %s на боевом узле (server_ip=%s) — отказываюсь работать без TLS"
                 % (CERT, APP.cfg.get("server_ip")))
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
