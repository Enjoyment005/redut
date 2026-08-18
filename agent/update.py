# -*- coding: utf-8 -*-
"""update.py — самообновление узла с GitHub (план: vpn/UPDATE-PLAN.md).

Как устроено (коротко):
  * версия РАБОТАЮЩЕЙ сборки — файл VERSION рядом с кодом (кладут установщики, Ф0);
  * маяк — файл VERSION на main официального репозитория (одна строка, без API);
  * артефакт — тарболл ТЕГА v<X.Y.Z> (main может уехать между проверкой и скачиванием);
  * транспорт — как у API провайдеров: напрямую, при сетевой ошибке — через
    собственный канал узла (curl --interface tun0), с общей подсказкой в /run;
  * обновление применяет идемпотентный setup.sh нового дерева в режиме UPDATE=1
    (параметры берутся с живого узла) — см. Ф2;
  * состояние (когда проверяли, что видели, чёрный список версий) — update.json
    рядом с БД пула (/var/lib/vpn-panel).

Только stdlib, работает и на Windows (dev-режим тестов): никаких fcntl/сети на
уровне модуля, сеть — системным curl (на узле он есть всегда, install.sh §1).
"""
import json
import os
import re
import subprocess
import time

PANEL_DIR = os.path.dirname(os.path.abspath(__file__))

# Строго X.Y.Z — как в scripts/set_version.py. Тег в GitHub — v<X.Y.Z>,
# префикс «v» здесь не принимаем: в файлах VERSION его не бывает.
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def _version_candidates():
    """Где искать версию РАБОТАЮЩЕЙ сборки (по порядку):
      1) копия рядом с кодом — на узле её кладут setup_panel.py / deploy.py
         (/opt/vpn-panel/VERSION);
      2) корень дерева НАШЕГО репозитория (dev: vpn/VERSION; публичная раскладка:
         agent/../VERSION) — только если рядом действительно лежит репозиторий
         (маркер install/install.sh). Без маркера на узле ../ — это /opt, и чужой
         /opt/VERSION не должен сойти за версию сборки (ревью Ф0)."""
    cands = [os.path.join(PANEL_DIR, "VERSION")]
    parent = os.path.abspath(os.path.join(PANEL_DIR, os.pardir))
    if os.path.isfile(os.path.join(parent, "install", "install.sh")):
        cands.append(os.path.join(parent, "VERSION"))
    return cands


def node_version(paths=None):
    """Версия работающей сборки узла или None, если VERSION никто не положил.

    None — штатный случай для узлов, поставленных до Ф0: панель покажет «?»,
    а автообновление на такой узел не пойдёт (не с чем сравнивать)."""
    for p in (paths or _version_candidates()):
        try:
            # utf-8-sig: человек мог пересохранить файл Блокнотом с BOM — молча
            # сломалось бы сравнение версий. Берём только первую строку.
            with open(p, encoding="utf-8-sig") as f:
                v = f.readline().strip()
        except OSError:
            continue
        if v:
            return v
    return None


def parse_version(s):
    """'1.2.3' -> (1, 2, 3); всё, что не строгий X.Y.Z, -> None."""
    s = (s or "").strip()
    if not SEMVER_RE.match(s):
        return None
    return tuple(int(x) for x in s.split("."))


def is_newer(remote, local):
    """Строго больше по semver — и только так (анти-даунгрейд, план Р3).

    Непарсящаяся ЛЮБАЯ из версий -> False: обновляться «непонятно с чего
    непонятно на что» нельзя, лучше честно показать «версия неизвестна»."""
    r, l = parse_version(remote), parse_version(local)
    if r is None or l is None:
        return False
    return r > l


# ══════════════════════════ Ф1: узнаём о новых версиях ══════════════════════

class UpdateError(Exception):
    """Ошибка обновления. network=True — сетевая недоступность (не «плохой релиз»)."""

    def __init__(self, message, network=False):
        super().__init__(message)
        self.network = network


DEFAULT_REPO = "Enjoyment005/redut"
BRANCH = "main"
USER_AGENT = "redut-update/1.0"
BEACON_URL = "https://raw.githubusercontent.com/%s/%s/VERSION"

# Дефолты блока `update` в /etc/vpn-panel/config.json. Владелец меняет auto из
# панели; окно/репозиторий — по SSH (repo подменяют только для обкатки на тестовом
# форке, план Р9). Блок сохраняется при редеплое, как money/countries. Частоту
# проверок задаёт сама крон-строка (04:41) — отдельного ключа для неё нет намеренно:
# мёртвый конфиг хуже отсутствующего (ревью 17.08).
UPDATE_DEFAULTS = {
    "auto": True,                 # воля владельца: «автоматика сама обновляется»
    "window": "04:00-06:00",      # ночное окно локального времени сервера (обычно UTC)
    "repo": DEFAULT_REPO,
}


def update_cfg(cfg):
    """Блок update из config.json + дефолты (незнакомые ключи игнорируем)."""
    u = dict(UPDATE_DEFAULTS)
    raw = (cfg or {}).get("update")
    if isinstance(raw, dict):
        for k in UPDATE_DEFAULTS:
            if k in raw and raw[k] is not None:
                u[k] = raw[k]
    u["auto"] = bool(u["auto"])
    u["repo"] = str(u["repo"] or DEFAULT_REPO).strip() or DEFAULT_REPO
    return u


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


# ── состояние: /var/lib/vpn-panel/update.json (рядом с БД пула) ─────────────
def state_path(cfg):
    return os.path.join(os.path.dirname(os.path.abspath((cfg or {}).get("db")
                                                        or os.path.join(PANEL_DIR, "state.db"))),
                        "update.json")


def load_state(cfg):
    try:
        with open(state_path(cfg), encoding="utf-8") as f:
            st = json.load(f)
        return st if isinstance(st, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(cfg, st):
    """Атомарно: оборванная запись не должна оставить битый JSON (по образцу set_version).
    Имя tmp — с pid: крон и кнопка панели могут писать одновременно, и общий .tmp
    ронял бы второго на os.replace (ревью Ф1)."""
    path = state_path(cfg)
    tmp = "%s.%d.tmp" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def _seen(st, key, version):
    return version in (st.get(key) or [])


def _mark(st, key, version, keep=20):
    """Отметить версию в списке (не скаляре): маяк может откатиться назад и вернуться —
    об УЖЕ уведомлённой версии второй раз не жужжим (ревью Ф1)."""
    lst = [v for v in (st.get(key) or []) if v != version]
    lst.append(version)
    st[key] = lst[-keep:]


# ── транспорт: curl напрямую -> через канал узла (как providers/base) ────────
def _curl(url, args=(), timeout=20, iface=None):
    """-> (rc, stdout, stderr). rc=-1 — curl не запустился вовсе."""
    cmd = ["curl", "-fsSL", "-m", str(int(timeout)), "-A", USER_AGENT]
    if iface:
        cmd += ["--interface", iface]
    cmd += list(args) + [url]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout + 15)
    except (OSError, subprocess.SubprocessError) as e:
        return -1, "", str(e)
    return p.returncode, p.stdout or "", p.stderr or ""


def fetch_text(url, timeout=20, max_bytes=4096):
    """GET маленького текстового файла тем же правилом транспорта, что у провайдеров:
    предпочтительный -> запасной (tun0 только живой), успех запасного запоминается
    в общей подсказке /run — GitHub и API провайдеров блокируются одинаково."""
    from providers import base as _tb     # лениво: не тянуть транспорт при импорте
    order = ["direct", "tun0"] if _tb.preferred_transport() == "direct" else ["tun0", "direct"]
    last = None
    for i, tr in enumerate(order):
        if tr == "tun0" and not _tb._tun0_alive():
            continue
        rc, out, err = _curl(url, args=("--max-filesize", str(max_bytes)),
                             timeout=timeout, iface=("tun0" if tr == "tun0" else None))
        if rc == 0:
            if i > 0:
                _tb.set_transport(tr)
            return out
        last = "curl rc=%s (%s): %s" % (rc, tr, (err or "нет ответа").strip()[:200])
    raise UpdateError("маяк недоступен — %s" % (last or "канал узла не поднят"), network=True)


# ── проверка: есть ли новая версия ───────────────────────────────────────────
def check(cfg, pool=None, alerter=None, log=None):
    """Сверить версию узла с маяком (VERSION на main). Пишет state; при ПЕРВОМ
    обнаружении новой версии — событие в журнал и одно письмо (не спамим: каждая
    версия уведомляется единожды, notified_version).

    Возвращает dict: local, remote, newer, bad (версия в чёрном списке после
    неудачного применения), error (сетевые/кривой маяк — НЕ исключение: для
    крона и панели «маяк недоступен» это данные, а не авария)."""
    log = log or (lambda m: None)
    u = update_cfg(cfg)
    local = node_version()
    st = load_state(cfg)
    out = {"local": local, "remote": None, "newer": False, "bad": False,
           "error": None, "repo": u["repo"], "auto": u["auto"]}
    try:
        raw = fetch_text(BEACON_URL % (u["repo"], BRANCH))
        remote = (raw or "").strip()
        if not parse_version(remote):
            raise UpdateError("маяк VERSION отдал не X.Y.Z: %r" % remote[:40])
        out["remote"] = remote
    except UpdateError as e:
        out["error"] = str(e)
        st.update(last_check=now_iso(), last_error=str(e))
        save_state(cfg, st)
        log("проверка обновлений: %s" % e)
        return out
    out["newer"] = is_newer(remote, local)
    out["bad"] = remote in (st.get("bad_versions") or [])
    news = out["newer"] and not out["bad"]
    event_new = news and not _seen(st, "notified_versions", remote)
    mail_new = news and not _seen(st, "mailed_versions", remote)
    st.update(last_check=now_iso(), latest_seen=remote, last_error=None)
    if event_new:
        _mark(st, "notified_versions", remote)
    # Письмо помечаем отправленным ТОЛЬКО по факту (send()==True) или когда SMTP не
    # настроен (ждать нечего): иначе разовый сбой почты терял письмо о версии навсегда
    # (ревью Ф1: notified ставился до send, а send по своей философии не бросает).
    if mail_new and alerter is not None:
        if not getattr(alerter, "configured", True):
            _mark(st, "mailed_versions", remote)
        elif alerter.send(
                "Редут: вышла версия %s" % remote,
                "На узле «%s» сейчас Редут %s, в репозитории %s появилась версия %s.\n\n"
                "%s\n\nОбновить вручную: панель, карточка «Обновления» -> «Обновить сейчас», "
                "либо на сервере: vpn-agent self-update --apply."
                % (cfg.get("server") or "?", local or "?", u["repo"], remote,
                   ("Автообновление включено — узел сам обновится в окно %s (по времени сервера)."
                    % u["window"]) if u["auto"] else
                   "Автообновление выключено — узел сам ничего делать не будет.")):
            _mark(st, "mailed_versions", remote)
    save_state(cfg, st)
    log("узел %s, маяк %s (%s)" % (local or "?", remote,
                                   "новее — доступно обновление" if out["newer"] else "не новее"))
    if event_new and pool is not None:
        try:    # журнал вторичен: залоченная БД не должна ронять проверку
            pool.log_event("update-available", actor="agent", result=remote,
                           detail="у узла %s" % (local or "?"))
        except Exception as e:      # noqa: BLE001
            log("событие не записалось: %s" % e)
    return out


# ══════════════════════════ Ф2: применение обновления ═══════════════════════
# Поток (план §4.2): скачать тарболл ТЕГА -> проверить дерево ДО запуска ->
# снимок здоровья -> текущее дерево в .prev -> UPDATE=1 setup.sh нового дерева
# (идемпотентный инсталлятор, параметры с живого узла) -> проверка «не хуже,
# чем было» -> при провале прогнать setup.sh прежнего дерева и внести версию
# в чёрный список. Одна попытка, никаких циклов рестартов (урок chaos-теста:
# серия рестартов sing-box подвешивала вход на узле).

REDUT_SRC = "/opt/redut-src"           # канонические исходники узла
REDUT_PREV = "/opt/redut-src.prev"     # прежнее дерево — цель отката
REDUT_NEW = "/opt/redut-src.new"       # сюда качаем и распаковываем тег
LOCK_PATH = "/run/redut-update.lock"   # гонка «кнопка + крон»
STATUS_PATH = "/run/redut-update.status"   # живой прогресс для карточки панели
TARBALL_URL = "https://codeload.github.com/%s/tar.gz/refs/tags/v%s"
MAX_TARBALL_BYTES = 50 * 1024 * 1024   # защита от «архива-переростка»
SETUP_TIMEOUT = 20 * 60                # полный setup.sh с apt обычно 1-3 мин
VERIFY_WAIT_S = 90                     # даём сервисам встать после установки
UNITS = ("wg-quick@wg0", "sing-box", "vpn-boot-setup", "microsocks", "vpn-panel")


def _run(cmd, timeout=60, env=None):
    """-> (rc, stdout, stderr); rc=-1 — команда не запустилась, rc=-2 — таймаут."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout, env=env)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired as e:
        return -2, (e.stdout or ""), "таймаут %s с" % timeout
    except (OSError, subprocess.SubprocessError) as e:
        return -1, "", str(e)


def status_write(phase, **extra):
    """Живой прогресс в /run (не переживает ребут — и не должен): его читает панель,
    в том числе после собственного рестарта в середине обновления."""
    try:
        tmp = STATUS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(dict({"phase": phase, "ts": now_iso()}, **extra), f, ensure_ascii=False)
        os.replace(tmp, STATUS_PATH)
    except OSError:
        pass


def status_read():
    try:
        with open(STATUS_PATH, encoding="utf-8") as f:
            st = json.load(f)
        return st if isinstance(st, dict) else None
    except (OSError, ValueError):
        return None


def fetch_file(url, dest, timeout=300, max_bytes=MAX_TARBALL_BYTES):
    """Скачать файл тем же правилом транспорта, что fetch_text.
    Обрыв не оставляет полузаписанного dest (качаем в .part, переименовываем)."""
    from providers import base as _tb
    order = ["direct", "tun0"] if _tb.preferred_transport() == "direct" else ["tun0", "direct"]
    last = None
    tmp = dest + ".part"
    for i, tr in enumerate(order):
        if tr == "tun0" and not _tb._tun0_alive():
            continue
        rc, _, err = _curl(url, args=("--max-filesize", str(max_bytes), "-o", tmp),
                           timeout=timeout, iface=("tun0" if tr == "tun0" else None))
        if rc == 0 and os.path.isfile(tmp) and os.path.getsize(tmp) > 0:
            os.replace(tmp, dest)
            if i > 0:
                _tb.set_transport(tr)
            return dest
        try:
            os.unlink(tmp)
        except OSError:
            pass
        last = "curl rc=%s (%s): %s" % (rc, tr, (err or "нет ответа").strip()[:200])
    raise UpdateError("артефакт не скачался — %s" % (last or "канал узла не поднят"), network=True)


def _untar(tgz, dest):
    rc, out, err = _run(["tar", "-xzf", tgz, "-C", dest, "--strip-components=1"], timeout=180)
    if rc != 0:
        raise UpdateError("тарболл не распаковался: %s" % (err or out).strip()[:200])


def _rmtree(path):
    import shutil
    shutil.rmtree(path, ignore_errors=True)


def download_tree(repo, version, dest=None, log=None):
    """Тарболл тега v<version> -> распакованное дерево в dest.

    Проверки ДО какого-либо запуска: структура (setup.sh, install/install.sh)
    и совпадение VERSION внутри с ожидаемой — «VERSION на main подняли, а тег
    указывает не туда» ловится здесь, а не на живом узле."""
    dest = dest or REDUT_NEW
    _rmtree(dest)
    os.makedirs(dest, exist_ok=True)
    tgz = dest + ".tgz"
    try:
        fetch_file(TARBALL_URL % (repo, version), tgz)
        _untar(tgz, dest)
    except UpdateError:
        _rmtree(dest)
        raise
    finally:
        try:
            os.unlink(tgz)
        except OSError:
            pass
    for rel in ("setup.sh", os.path.join("install", "install.sh")):
        if not os.path.isfile(os.path.join(dest, rel)):
            _rmtree(dest)
            raise UpdateError("в архиве тега v%s нет %s — не тот репозиторий?" % (version, rel))
    got = node_version(paths=[os.path.join(dest, "VERSION")])
    if got != version:
        _rmtree(dest)
        raise UpdateError("в тарболле тега v%s лежит VERSION=%s — сборка репозитория кривая"
                          % (version, got))
    return dest


# ── здоровье узла: снимок ДО и проверка ПОСЛЕ («не хуже, чем было») ──────────
def _is_active(unit):
    rc, out, _ = _run(["systemctl", "is-active", unit], timeout=10)
    return (out or "").strip() == "active"


def _wg_peers():
    rc, out, _ = _run(["wg", "show", "wg0", "peers"], timeout=10)
    if rc != 0:
        return None
    return len([ln for ln in (out or "").splitlines() if ln.strip()])


def _panel_ok(port):
    rc, out, _ = _run(["curl", "-sk", "--max-time", "5",
                       "https://127.0.0.1:%d/healthz" % int(port)], timeout=15)
    return rc == 0 and (out or "").strip() == "ok"


def _singbox_ok(cfg):
    binp = (cfg or {}).get("singbox_bin") or "/usr/local/bin/sing-box"
    conf = (cfg or {}).get("singbox_config") or "/etc/sing-box/config.json"
    rc, out, err = _run([binp, "check", "-c", conf], timeout=20)
    return rc == 0, (err or out or "").strip()[:200]


def baseline_health(cfg):
    return {"units": {u: _is_active(u) for u in UNITS},
            "peers": _wg_peers(),
            "panel": _panel_ok((cfg or {}).get("panel_port") or 8443)}


def hard_ok(baseline):
    """Минимум, без которого АВТОМАТИКЕ обновляться нельзя: обновление больного узла
    может добить, а откат «на больное» ничего не докажет. Руками (manual) — можно:
    иногда обновление и есть лечение."""
    return bool(baseline["units"].get("sing-box") and baseline["units"].get("vpn-panel")
                and baseline["panel"])


def _brief_health(b):
    dead = [u for u, ok in (b.get("units") or {}).items() if not ok]
    parts = []
    if dead:
        parts.append("не активны: %s" % ", ".join(dead))
    if not b.get("panel"):
        parts.append("панель не отвечает")
    return "; ".join(parts) or "всё активно"


def _verify_once(cfg, baseline):
    ok, why = _singbox_ok(cfg)
    if not ok:
        return False, "sing-box check не прошёл: %s" % why
    for u in UNITS:
        if baseline["units"].get(u) and not _is_active(u):
            return False, "юнит %s был активен до обновления, а теперь нет" % u
    if (baseline.get("peers") or 0) > 0:
        now = _wg_peers()
        if (now or 0) < baseline["peers"]:
            return False, "wg-пиров стало меньше: было %s, стало %s" % (baseline["peers"], now)
    if baseline.get("panel") and not _panel_ok((cfg or {}).get("panel_port") or 8443):
        return False, "панель не отвечает по HTTPS"
    return True, ""


def verify_health(cfg, baseline, wait_s=VERIFY_WAIT_S, sleep=time.sleep):
    """Жёсткий минимум + «не хуже baseline». Ждём до wait_s: сервисы после
    установки встают не мгновенно (панель — рестарт, wg — syncconf)."""
    deadline = time.monotonic() + wait_s
    while True:
        ok, why = _verify_once(cfg, baseline)
        if ok:
            return True, ""
        if time.monotonic() >= deadline:
            return False, why
        sleep(5)


def _run_setup(tree, log):
    """UPDATE=1 bash setup.sh из дерева tree. Хвост вывода — в лог (journal/cron)."""
    env = dict(os.environ, UPDATE="1")
    rc, out, err = _run(["bash", os.path.join(tree, "setup.sh")], timeout=SETUP_TIMEOUT, env=env)
    text = (out + (("\n" + err) if err.strip() else "")).strip()
    for ln in text.splitlines()[-80:]:
        log("  | %s" % ln)
    return rc, text[-4000:]


def _tree_can_update(tree):
    """Умеет ли дерево режим UPDATE=1. Прогон СТАРОГО setup.sh (сборки до 1.2.0)
    в качестве «отката» переустановил бы узел дефолтами (node1 / 10.8.0.0/24 /
    phone1) — это хуже любого провала, поэтому такое дерево не запускаем
    (ревью 17.08: на узлах, катанных deploy.py, в /opt/redut-src живёт старьё)."""
    try:
        with open(os.path.join(tree, "setup.sh"), encoding="utf-8", errors="replace") as f:
            head = f.read(20000)                # блок 0a живёт в первой сотне строк
    except OSError:
        return False
    return "UPDATE" in head and os.path.isfile(os.path.join(tree, "install", "install.sh"))


def _event(pool, action, result, detail=""):
    if pool is not None:
        pool.log_event(action, actor="agent", result=result, detail=detail)


def apply(cfg, pool=None, alerter=None, log=None, target=None, manual=False, force=False):
    """Скачать и накатить версию (по умолчанию — свежую с маяка) с бэкапом и откатом.

    manual=True — человек (кнопка/CLI): можно ставить версию из чёрного списка
    (сознательный повтор) и не требуется «здоровый» baseline. Автоматика — False.
    force=True (только вместе с manual, 1.6.0) — принудительная переустановка ТОЙ ЖЕ
    версии: скачать выпуск заново и прогнать установщик — лечение узла, у которого
    что-то разъехалось. Анти-даунгрейд (Р3) force НЕ отменяет: версии ниже узла
    не ставятся никогда. Одна попытка; возвращает dict {ok, from, to, rolled_back, why}."""
    log = log or (lambda m: None)
    res = {"ok": False, "from": node_version(), "to": target, "rolled_back": False, "why": ""}
    import apply as apply_mod          # лениво: fcntl только на POSIX
    try:
        with apply_mod.Flock(LOCK_PATH):
            return _apply_locked(cfg, pool, alerter, log, target, manual, res, force)
    except apply_mod.ApplyError:
        res["why"] = "обновление уже идёт (занят %s)" % LOCK_PATH
        log(res["why"])
        return res


def _apply_locked(cfg, pool, alerter, log, target, manual, res, force=False):
    u = update_cfg(cfg)
    local = res["from"]
    force = bool(force and manual)     # у автоматики принудительного режима нет
    if not target:
        r = check(cfg, pool=pool, alerter=None, log=log)
        if r["error"]:
            res["why"] = r["error"]
            status_write("error", why=res["why"])
            return res
        if not r["newer"] and not (force and r["remote"] == local):
            res["why"] = "обновляться не на что (узел %s, маяк %s)" % (local or "?", r["remote"])
            status_write("idle", why=res["why"])
            log(res["why"])
            return res
        target = r["remote"]
    res["to"] = target
    if not is_newer(target, local):
        # force разрешает ровно один «не вверх» случай: переустановку ТЕКУЩЕЙ версии
        # (target == local). Даунгрейд запрещён и с force (анти-даунгрейд Р3).
        if force and target == local:
            log("принудительная переустановка %s: та же версия заново (лечение узла)" % target)
        else:
            res["why"] = ("версия %s не новее узла (%s) — обновляемся только вверх%s"
                          % (target, local or "?",
                             "; принудительно можно переустановить только ТУ ЖЕ версию"
                             if force else ""))
            status_write("error", why=res["why"])
            log(res["why"])
            return res
    st = load_state(cfg)
    if target in (st.get("bad_versions") or []) and not manual:
        res["why"] = ("версия %s в чёрном списке (обновление на неё уже проваливалось) — "
                      "автоматика её не ставит, руками из панели можно" % target)
        status_write("error", why=res["why"])
        log(res["why"])
        return res

    baseline = baseline_health(cfg)
    if not manual and not hard_ok(baseline):
        res["why"] = ("узел нездоров и до обновления (%s) — автоматика не рискует; "
                      "почини или обнови руками" % _brief_health(baseline))
        status_write("error", why=res["why"])
        log(res["why"])
        return res

    log("Обновление Редут %s -> %s (репозиторий %s)" % (local or "?", target, u["repo"]))
    status_write("download", to=target, frm=local)
    try:
        download_tree(u["repo"], target, REDUT_NEW, log=log)
    except UpdateError as e:
        res["why"] = str(e)
        status_write("failed", why=res["why"], to=target)
        _event(pool, "update-fail", target, res["why"])
        log(res["why"])
        # сетевая ошибка = ретрай завтра, письмо не шлём; битое дерево — шлём
        if alerter is not None and not e.network:
            alerter.send("🔴 Редут: обновление %s не скачалось" % target,
                         "Узел «%s»: %s.\nАвтоматика попробует следующую версию; эту можно "
                         "поставить руками, когда починят релиз." % (cfg.get("server") or "?", res["why"]))
        return res

    # Лок агента на установку+проверку+откат: сторож (*/2) и ротация не должны
    # рестартовать sing-box ПАРАЛЛЕЛЬНО инсталлятору — серия рестартов подряд
    # вешала вход на живом узле (chaos-тест node1). rotate/watchdog этот лок уважают.
    import apply as apply_mod
    try:
        with apply_mod.Flock((cfg or {}).get("lock") or "/run/vpn-agent.lock"):
            return _apply_install(cfg, pool, alerter, log, target, manual, res, baseline, force)
    except apply_mod.ApplyError:
        res["why"] = "агент занят (ротация?) — обновление отложено, попробуй через пару минут"
        status_write("failed", why=res["why"], to=target)
        _rmtree(REDUT_NEW)
        log(res["why"])
        return res


def _apply_install(cfg, pool, alerter, log, target, manual, res, baseline, force=False):
    """Установка скачанного дерева + проверка + откат. Вызывается под ДВУМЯ локами
    (redut-update и vpn-agent)."""
    local = res["from"]

    status_write("backup", to=target, frm=local)
    src_ver = node_version(paths=[os.path.join(REDUT_SRC, "VERSION")]) \
        if os.path.isdir(REDUT_SRC) else None
    # При force ветка «след недоустановки» не годится: src_ver == target там ПО
    # ОПРЕДЕЛЕНИЮ (переустанавливаем версию узла), а живое дерево — не «битое»,
    # это лучшая цель отката для сознательной переустановки.
    if src_ver == target and os.path.isdir(REDUT_PREV) and not force:
        # След прошлой недоустановки ТОЙ ЖЕ версии (kill посреди setup.sh): настоящий
        # «до» уже лежит в prev — не затирать его полуустановленным деревом, иначе
        # откат поехал бы на ту же битую версию (ревью 17.08).
        _rmtree(REDUT_SRC + ".failed")
        os.rename(REDUT_SRC, REDUT_SRC + ".failed")
        had_prev = True
        log("нашёл след прошлой недоустановки %s — прежняя сборка в %s сохранена как цель отката"
            % (target, REDUT_PREV))
    else:
        _rmtree(REDUT_PREV)
        had_prev = os.path.isdir(REDUT_SRC)
        if had_prev:
            os.rename(REDUT_SRC, REDUT_PREV)
            try:                    # страховочная копия конфига (восстановление руками)
                import shutil
                if os.path.isfile("/etc/vpn-panel/config.json"):
                    shutil.copy2("/etc/vpn-panel/config.json",
                                 os.path.join(REDUT_PREV, "config.json.before-update"))
            except OSError:
                pass
    os.rename(REDUT_NEW, REDUT_SRC)
    rollback_ok = had_prev and _tree_can_update(REDUT_PREV)
    if had_prev and not rollback_ok:
        log("⚠️ прежнее дерево (%s) не умеет режим UPDATE=1 (сборка до 1.2.0) — "
            "в случае провала автоотката НЕ будет" % REDUT_PREV)

    status_write("install", to=target, frm=local)
    rc, _tail = _run_setup(REDUT_SRC, log)
    status_write("verify", to=target, frm=local)
    if rc == 0:
        ok_v, why_v = verify_health(cfg, baseline)
    else:
        ok_v, why_v = False, "setup.sh завершился с ошибкой (rc=%s)" % rc

    if ok_v:
        res["ok"] = True
        st = load_state(cfg)
        st["last_apply"] = {"ts": now_iso(), "from": local, "to": target,
                            "ok": True, "manual": manual, "force": bool(force)}
        save_state(cfg, st)
        status_write("done", ok=True, to=target, frm=local)
        _event(pool, "update-apply", target,
               "с %s%s" % (local or "?",
                           ", принудительная переустановка" if force and target == local
                           else (", вручную" if manual else "")))
        if alerter is not None:
            alerter.send("Редут обновлён до %s" % target,
                         "Узел «%s» обновился: %s -> %s.\nКлиенты, ключи и канал не тронуты; "
                         "прежняя версия лежит в %s.\nДействий не требуется."
                         % (cfg.get("server") or "?", local or "?", target, REDUT_PREV))
        log("Готово: узел обновлён до %s (прежняя сборка в %s)" % (target, REDUT_PREV))
        return res

    # ── провал -> откат на прежнее дерево ────────────────────────────────────
    log("Проверка после обновления ПРОВАЛЕНА: %s" % why_v)
    status_write("rollback", why=why_v, to=target, frm=local)
    rolled = False
    if rollback_ok:
        _rmtree(REDUT_SRC + ".failed")
        os.rename(REDUT_SRC, REDUT_SRC + ".failed")   # битое дерево — для разбора
        os.rename(REDUT_PREV, REDUT_SRC)
        log("Откатываюсь: прогоняю setup.sh прежней сборки %s" % (local or ""))
        rc2, _t2 = _run_setup(REDUT_SRC, log)
        ok2, why2 = verify_health(cfg, baseline)
        # Истина — здоровье узла, а не rc: старый setup.sh мог упасть на том же
        # инфраструктурном сбое (недоступен apt), не тронув живой узел (ревью 17.08).
        rolled = ok2
        if not rolled:
            log("Откат тоже не прошёл проверку: %s" % (why2 or "setup.sh rc=%s" % rc2))
        elif rc2 != 0:
            log("откат: setup.sh прежней сборки rc=%s, но узел прошёл проверку — похоже "
                "на инфраструктурный сбой (зеркала apt?), сам узел цел" % rc2)
    elif had_prev:
        log("Откат НЕ запускался: прежнее дерево без режима UPDATE=1 переустановило бы "
            "узел дефолтами (node1/10.8.0.0/24) — это хуже провала. Нужен человек.")
    else:
        log("Прежнего дерева нет (%s) — откатывать нечем, нужен человек" % REDUT_PREV)

    st = load_state(cfg)
    # Чёрный список — про «на эту версию не ОБНОВЛЯТЬСЯ»: провал переустановки ТОЙ ЖЕ
    # версии (force) туда не пишем — автоматика на неё и так не пойдёт (не новее),
    # а помечать работающую версию узла «проблемной» — только путать карточку.
    if target != local:
        bad = set(st.get("bad_versions") or [])
        bad.add(target)
        st["bad_versions"] = sorted(bad)
    st["last_apply"] = {"ts": now_iso(), "from": local, "to": target, "ok": False,
                        "rolled_back": rolled, "why": why_v, "manual": manual,
                        "force": bool(force)}
    save_state(cfg, st)
    res.update(rolled_back=rolled, why=why_v)
    status_write("failed", why=why_v, rolled_back=rolled, to=target, frm=local)
    _event(pool, "update-fail", target, "%s; откат %s" % (why_v, "успешен" if rolled else "НЕ УДАЛСЯ"))
    if alerter is not None:
        alerter.send("🔴 Редут: обновление до %s провалилось" % target,
                     "Узел «%s» пробовал обновиться %s -> %s и не прошёл проверку:\n  %s\n\n%s\n"
                     "Версия %s внесена в чёрный список — автоматика её больше не тронет.\n"
                     "Когда выйдет исправленный релиз, узел поставит его сам."
                     % (cfg.get("server") or "?", local or "?", target, why_v,
                        ("Откат прошёл: узел снова на %s, всё работает." % (local or "прежней сборке"))
                        if rolled else
                        "⚠️ ОТКАТ НЕ ПОДТВЕРДИЛСЯ — зайди на узел и посмотри руками (journalctl, systemctl).",
                        target))
    return res


# ══════════════════════════ Ф3: автоматика (крон) ════════════════════════════
JITTER_MAX_S = 25 * 60      # размазать обращения узлов к GitHub (крон у всех 04:41)
COOLDOWN_H = 20             # максимум одна ПОПЫТКА установки в сутки (урок рестарт-шторма)
CRON_HM = 4 * 60 + 41       # минута суточного крона self-update («41 4 * * *»)


def window_covers_cron(window, cron_hm=CRON_HM, jitter_min=JITTER_MAX_S // 60):
    """Накрывает ли окно время крона (с учётом jitter). Слишком узкое окно молча
    выключило бы авто-обновления НАВСЕГДА — карточка панели предупреждает."""
    return any(in_window(window, (cron_hm + m) % 1440) for m in range(int(jitter_min) + 2))


def in_window(window, now_hm=None):
    """Ночное окно "HH:MM-HH:MM" локального времени сервера; поддерживает переход
    через полночь (22:00-02:00). Кривой формат окна НЕ ограничивает (лучше
    обновиться в неурочный час, чем молча никогда) — формат чинится по SSH."""
    m = re.match(r"^(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})$", (window or "").strip())
    if not m:
        return True
    a = int(m.group(1)) * 60 + int(m.group(2))
    b = int(m.group(3)) * 60 + int(m.group(4))
    if now_hm is None:
        lt = time.localtime()
        now_hm = lt.tm_hour * 60 + lt.tm_min
    if a <= b:
        return a <= now_hm < b
    return now_hm >= a or now_hm < b


def _hours_since(ts):
    try:
        return (time.time() - time.mktime(time.strptime(ts, "%Y-%m-%dT%H:%M:%S"))) / 3600.0
    except (TypeError, ValueError):
        return None


def cron_tick(cfg, pool=None, alerter=None, log=None, sleep=time.sleep, jitter_s=None):
    """Режим планировщика (крон 04:41): jitter -> check -> если есть новая, авто
    включено, окно, cooldown и агент не занят ротацией — apply.

    Возвращает {"check": …, "applied": …|None, "skip": причина|None}."""
    log = log or (lambda m: None)
    u = update_cfg(cfg)
    j = jitter_s if jitter_s is not None else __import__("random").uniform(0, JITTER_MAX_S)
    if j and j > 0:
        log("jitter: жду %.0f с (не выстраивать все узлы к GitHub в одну секунду)" % j)
        sleep(j)
    r = check(cfg, pool=pool, alerter=alerter, log=log)
    out = {"check": r, "applied": None, "skip": None}
    if r["error"] or not r["newer"]:
        return out
    if r["bad"]:
        out["skip"] = "версия %s в чёрном списке" % r["remote"]
    elif not u["auto"]:
        out["skip"] = "автообновление выключено (письмо о новинке уже ушло)"
    elif not in_window(u["window"]):
        out["skip"] = "вне окна %s" % u["window"]
    if out["skip"]:
        log("пропуск: %s" % out["skip"])
        return out
    st = load_state(cfg)
    h = _hours_since((st.get("last_apply") or {}).get("ts"))
    if h is not None and h < COOLDOWN_H:
        out["skip"] = "cooldown: прошлая попытка была %.1f ч назад (< %d ч)" % (h, COOLDOWN_H)
        log("пропуск: %s" % out["skip"])
        return out
    # занятость агента (ротация) проверяет сам apply: он берёт /run/vpn-agent.lock
    # на установку+проверку+откат и мягко отказывается, если лок занят.
    out["applied"] = apply(cfg, pool=pool, alerter=alerter, log=log,
                           target=r["remote"], manual=False)
    return out
