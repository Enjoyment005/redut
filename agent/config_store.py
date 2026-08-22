# -*- coding: utf-8 -*-
"""Надёжные точечные изменения runtime-конфига Redut.

Панель и агент — разные процессы. Обычная схема read -> edit -> replace без общей
блокировки теряет параллельное изменение второго процесса. Здесь один writer:
межпроцессный flock на Linux, RLock в dev, уникальный временный файл, fsync и
атомарный os.replace. Служебные значения, подмешанные в cfg в памяти, на диск не
попадают: mutator получает только JSON, реально прочитанный из файла.
"""
import contextlib
import json
import os
import tempfile
import threading

try:
    import fcntl
except ImportError:  # Windows-dev
    fcntl = None


_LOCK = threading.RLock()


def _path(cfg):
    path = str((cfg or {}).get("_source") or "").strip()
    if not path or not os.path.isfile(path):
        raise OSError("runtime config.json не найден: %s" % (path or "путь не задан"))
    return path


@contextlib.contextmanager
def _file_lock(path):
    lock_path = path + ".lock"
    with open(lock_path, "a+", encoding="ascii") as lock:
        try:
            os.chmod(lock_path, 0o600)
        except OSError:
            pass
        if fcntl is not None:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def read(cfg):
    """Прочитать именно дисковый JSON, не возвращая служебные поля cfg."""
    path = _path(cfg)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("runtime config.json должен быть объектом")
    return data


def update(cfg, mutator, mode=0o644):
    """Атомарно применить mutator(data) и вернуть новый дисковый объект."""
    path = _path(cfg)
    directory = os.path.dirname(os.path.abspath(path))
    tmp = None
    with _LOCK, _file_lock(path):
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
            try:
                dfd = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            except OSError:
                pass
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
    return data


def save_country_strategy(cfg, name):
    """Сохранить countries.strategy, сохранив все соседние настройки."""
    def mutate(data):
        data.setdefault("countries", {})["strategy"] = name
    data = update(cfg, mutate)
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
