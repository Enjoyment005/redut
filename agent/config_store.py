# -*- coding: utf-8 -*-
"""Надёжные точечные изменения runtime-конфига Redut.

Панель и агент — разные процессы. Обычная схема read -> edit -> replace без общей
блокировки теряет параллельное изменение второго процесса. Здесь один writer:
межпроцессный flock на Linux, RLock в dev, уникальный временный файл, fsync и
атомарный os.replace. Служебные значения, подмешанные в cfg в памяти, на диск не
попадают: mutator получает только JSON, реально прочитанный из файла.
"""
import contextlib
import hashlib
import json
import os
import tempfile
import threading
import time

try:
    import fcntl
except ImportError:  # Windows-dev
    fcntl = None
try:
    import msvcrt
except ImportError:  # POSIX
    msvcrt = None


_LOCK = threading.RLock()


def _runtime_lock_path(config_path):
    """Lock живёт вне /etc: read-only config не должен блокировать durable intent."""
    canonical = os.path.normcase(os.path.realpath(config_path)).encode("utf-8", "surrogatepass")
    name = "config-%s.lock" % hashlib.sha256(canonical).hexdigest()[:24]
    configured = str(os.environ.get("VPN_PANEL_LOCK_DIR") or "").strip()
    candidates = []
    if configured:
        candidates.append(configured)
    if os.name == "posix":
        candidates.extend(("/run/lock/redut", "/run/redut-locks"))
    suffix = ("-%s" % os.getuid()) if hasattr(os, "getuid") else ""
    candidates.append(os.path.join(tempfile.gettempdir(), "redut-locks" + suffix))
    last_error = None
    for directory in candidates:
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            return os.path.join(directory, name)
        except OSError as e:
            last_error = e
    raise OSError("не удалось создать runtime-каталог lock: %s" % last_error)


def _path(cfg):
    path = str((cfg or {}).get("_source") or "").strip()
    if not path or not os.path.isfile(path):
        raise OSError("runtime config.json не найден: %s" % (path or "путь не задан"))
    return path


@contextlib.contextmanager
def _file_lock(path):
    lock_path = _runtime_lock_path(path)
    with open(lock_path, "a+b") as lock:
        try:
            os.chmod(lock_path, 0o600)
        except OSError:
            pass
        if fcntl is not None:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        elif msvcrt is not None:
            # msvcrt.locking блокирует диапазон существующего файла. Один байт
            # превращает тот же .lock в настоящий mutex между Windows-процессами.
            lock.seek(0, os.SEEK_END)
            if lock.tell() == 0:
                lock.write(b"\0")
                lock.flush()
            while True:
                try:
                    lock.seek(0)
                    msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.02)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            elif msvcrt is not None:
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


def read(cfg):
    """Прочитать именно дисковый JSON, не возвращая служебные поля cfg."""
    path = _path(cfg)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("runtime config.json должен быть объектом")
    return data


@contextlib.contextmanager
def writer(cfg):
    """Единая межпроцессная критическая секция для intent -> config -> CAS."""
    path = _path(cfg)
    with _LOCK, _file_lock(path):
        yield


def update(cfg, mutator, mode=0o644, _locked=False):
    """Атомарно применить mutator(data) и вернуть новый дисковый объект."""
    path = _path(cfg)
    directory = os.path.dirname(os.path.abspath(path))
    tmp = None
    lock = contextlib.nullcontext() if _locked else writer(cfg)
    with lock:
        data = read(cfg)
        changed = mutator(data)
        if changed is not None:
            data = changed
        if not isinstance(data, dict):
            raise ValueError("mutator config.json вернул не объект")
        fd, tmp = tempfile.mkstemp(prefix=".redut-config-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(tmp, mode)
            except OSError:
                pass
            os.replace(tmp, path)
            tmp = None
            if os.name == "posix":
                dfd = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
    return data


def save_country_strategy(cfg, name, _locked=False):
    """Сохранить countries.strategy, сохранив все соседние настройки."""
    def mutate(data):
        data.setdefault("countries", {})["strategy"] = name
    data = update(cfg, mutate, _locked=_locked)
    cfg.setdefault("countries", {})["strategy"] = name
    return data


def refresh_country_strategy(cfg):
    """Подхватить стратегию, которую другой процесс записал на диск."""
    data = read(cfg)
    name = ((data.get("countries") or {}).get("strategy"))
    countries = cfg.setdefault("countries", {})
    if name is None:
        # Удаление ключа другим процессом тоже изменение: память не должна
        # продолжать жить со старым значением. Вызывающий получит системный default.
        countries.pop("strategy", None)
    else:
        countries["strategy"] = name
    return name
