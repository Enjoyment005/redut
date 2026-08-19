# -*- coding: utf-8 -*-
"""Показатели сервера для полоски «Сервер» в шапке панели.

Нагрузка процессора, память, swap, диск, аптайм — всё читается из /proc и
стандартной библиотеки: никаких внешних команд (метрики едут в каждый опрос
/api/status раз в 30 с) и никаких зависимостей. На dev-машине без /proc
(Windows) snapshot() возвращает None — панель просто не показывает полоску.

Здесь же — оценка вместимости recommend_clients(): «сколько одновременно
работающих устройств потянет такая конфигурация». Оценка консервативная:
трафик каждого клиента шифруется (WireGuard) и прогоняется через цепочку
sing-box → зарубежный SOCKS5, то есть узким местом становится процессор и
общий прокси-канал, а не память.
"""
import os
import shutil

# ~столько активных устройств вытягивает одно ядро: шифрование WireGuard +
# перекладка трафика sing-box'ом при обычном пользовании (сайты, видео HD)
_CLIENTS_PER_CORE = 10
# память: базовые службы узла (sing-box, панель, dnsmasq, системное) + запас
# на соединения одного активного устройства
_BASE_MB = 256
_MB_PER_CLIENT = 24
# запас на стабильность: рекомендация — 80% расчётного потолка (просьба
# владельца 19.08), чтобы не подводить узел к границе железа вплотную
_SAFETY = 0.8


def _read(path):
    try:
        with open(path, "r", encoding="ascii", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def parse_loadavg(text):
    """Первое число /proc/loadavg — средняя загрузка за минуту."""
    try:
        return float((text or "").split()[0])
    except (IndexError, ValueError):
        return None


def parse_meminfo(text):
    """/proc/meminfo → {ключ: кБ}. Только числовые строки, битые — мимо."""
    out = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        parts = v.split()
        if not parts:
            continue
        try:
            out[k.strip()] = int(parts[0])
        except ValueError:
            continue
    return out


def parse_uptime(text):
    """Первое число /proc/uptime — секунды с загрузки сервера."""
    try:
        return float((text or "").split()[0])
    except (IndexError, ValueError):
        return None


def recommend_clients(cores, mem_total_kb):
    """Оценка «до скольких одновременно работающих устройств» по железу.

    По процессору: _CLIENTS_PER_CORE на ядро (шифрование + прокси-цепочка).
    По памяти: что остаётся после базовых служб, по _MB_PER_CLIENT на устройство.
    Берём худшее из двух и оставляем _SAFETY (80%) — запас на стабильность;
    меньше 2 не отдаём — даже самый маленький VPS тянет телефон и ноутбук.
    Это про АКТИВНЫХ одновременно, не про число профилей.
    """
    try:
        cores = int(cores or 0)
        mem_mb = (int(mem_total_kb or 0)) / 1024.0
    except (TypeError, ValueError):
        return None
    if cores <= 0 or mem_mb <= 0:
        return None
    by_cpu = cores * _CLIENTS_PER_CORE
    by_ram = int((mem_mb - _BASE_MB) // _MB_PER_CLIENT)
    return max(2, int(min(by_cpu, by_ram) * _SAFETY))


def snapshot(proc="/proc", disk_path="/", cores=None, sys_net="/sys/class/net",
             wg_if="wg0"):
    """Всё для полоски «Сервер» одним словарём; None — данных нет (не Linux).

    Параметры путей нужны тестам: на dev-машине подсовывается каталог с
    файлами-фикстурами вместо /proc.
    """
    load_txt = _read(os.path.join(proc, "loadavg"))
    mem_txt = _read(os.path.join(proc, "meminfo"))
    if not load_txt or not mem_txt:
        return None
    if cores is None:
        cores = os.cpu_count() or 1
    out = {"cores": cores}

    load1 = parse_loadavg(load_txt)
    out["load1"] = load1
    out["load_pct"] = (None if load1 is None
                       else min(999, int(round(load1 / max(1, cores) * 100))))

    mem = parse_meminfo(mem_txt)
    total = mem.get("MemTotal") or 0
    # MemAvailable честнее, чем MemFree: ядро само говорит, сколько реально
    # можно раздать без свопа (кэши отдаются). На древних ядрах его нет —
    # тогда free+buffers+cached.
    avail = mem.get("MemAvailable")
    if avail is None:
        avail = (mem.get("MemFree") or 0) + (mem.get("Buffers") or 0) + (mem.get("Cached") or 0)
    if total:
        used = max(0, total - avail)
        out["mem_total_mb"] = int(round(total / 1024.0))
        out["mem_used_mb"] = int(round(used / 1024.0))
        out["mem_pct"] = int(round(100.0 * used / total))
    else:
        out["mem_total_mb"] = out["mem_used_mb"] = out["mem_pct"] = None

    sw_total = mem.get("SwapTotal") or 0
    sw_free = mem.get("SwapFree") or 0
    out["swap_total_mb"] = int(round(sw_total / 1024.0))
    if sw_total:
        sw_used = max(0, sw_total - sw_free)
        out["swap_used_mb"] = int(round(sw_used / 1024.0))
        out["swap_pct"] = int(round(100.0 * sw_used / sw_total))
    else:
        out["swap_used_mb"], out["swap_pct"] = 0, None

    try:
        du = shutil.disk_usage(disk_path)
        out["disk_total_gb"] = round(du.total / 1073741824.0, 1)
        out["disk_free_gb"] = round(du.free / 1073741824.0, 1)
        out["disk_pct"] = int(round(100.0 * du.used / du.total)) if du.total else None
    except OSError:
        out["disk_total_gb"] = out["disk_free_gb"] = out["disk_pct"] = None

    out["uptime_sec"] = parse_uptime(_read(os.path.join(proc, "uptime")))
    out["wg_up"] = os.path.isdir(os.path.join(sys_net, wg_if))
    out["rec_clients"] = recommend_clients(cores, total)
    return out
