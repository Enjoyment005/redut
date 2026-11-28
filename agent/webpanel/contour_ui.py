"""Request-local panel domain selection; authentication stays node-wide."""
import contextlib
import functools
import json
import os
import threading
import uuid

import contours
from providers import make_providers
from providers.zenxnet import ZenXNet, validate_url
from webpanel import auth

_SUBSCRIPTION_LOCK = threading.Lock()


def subscription_writer(function):
    @functools.wraps(function)
    def serialized(*args, **kwargs):
        with _SUBSCRIPTION_LOCK:
            return function(*args, **kwargs)
    return serialized


class Apps:
    def __init__(self, main, factory):
        self.main = main
        self.factory = factory
        self._second = None
        self._second_identity = None
        self._lock = threading.RLock()

    def selected(self):
        if contours.CURRENT.get() == "1":
            return self.main
        with self._lock:
            if contours.read(self.main.cfg)["secondary"] != "ready":
                raise contours.ContourError("Второй контур пока недоступен; создание или удаление ещё не завершено")
            child = contours.config(self.main.cfg)
            try:
                stat = os.stat(child["db"])
            except OSError:
                raise contours.ContourError("Хранилище второго контура недоступно") from None
            identity = (stat.st_dev, stat.st_ino)
            if self._second is not None and identity != self._second_identity:
                self._second.pool.close()
                self._second = None
            if self._second is None:
                self._second = self.factory(cfg=child, primary=self.main)
                self._second_identity = identity
            self._second.cfg = child
            self._second.providers = contours.allowed_providers(child, make_providers(self.main.secrets), self.main.secrets)
            self._second.secrets = self.main.secrets
            return self._second

    def __getattr__(self, name):
        # The same login, CSRF and account apply to both tabs.
        if name in ("store", "admin", "admin_epoch", "provisioned"):
            return getattr(self.main, name)
        return getattr(self.selected(), name)


def scope_handler(function):
    @functools.wraps(function)
    def scoped(handler, *args, **kwargs):
        app = function.__globals__["APP"]
        headers = getattr(handler, "headers", {})
        selected = headers.get("X-Redut-Contour", "1")
        if not isinstance(selected, str):
            selected = "1"
        if selected not in ("1", "2"):
            return handler._json(400, {"error": "Неизвестный контур"})
        if selected == "2" and not isinstance(app, Apps):
            return handler._json(404, {"error": "Второй контур недоступен"})
        token = contours.CURRENT.set(selected)
        try:
            path = args[0] if args else ""
            # Lifecycle changes wait for in-flight requests in the second tab.
            guard = (app._lock if isinstance(app, Apps)
                     and (selected == "2" or path in ("/api/contours", "/api/contours/delete"))
                     else contextlib.nullcontext())
            with guard:
                if isinstance(app, Apps):
                    app.selected()
                return function(handler, *args, **kwargs)
        except contours.ContourError as error:
            return handler._json(409, {"error": str(error)})
        finally:
            contours.CURRENT.reset(token)
    return scoped


def main_app(app):
    return app.main if isinstance(app, Apps) else app


@subscription_writer
def save_subscription(app, value, check_only=False, target=None):
    """One durable HWID per installation, including unsuccessful retries."""
    target = contours.CURRENT.get() if target is None else str(target)
    if target not in ("1", "2"):
        raise contours.ContourError("Неизвестный контур подписки")
    app = main_app(app)
    url = validate_url(value)
    path = app.secrets_path
    if not path:
        raise contours.ContourError("Секреты панели ещё не настроены")

    def device(data):
        data.setdefault("zenxnet", {}).setdefault("hwid", "redut-" + uuid.uuid4().hex)
        data["zenxnet"]["cache_path"] = os.path.join(os.path.dirname(path), "zenxnet-cache.json")
        return data

    auth.update_secrets_atomic(path, device)
    app.reload_secrets()
    block = app.secrets["zenxnet"]
    provider = ZenXNet(url, block["hwid"], cache_path=block["cache_path"])
    nodes = provider.list()
    if check_only:
        return {"ok": True, "provider": "zenxnet", "nodes": len(nodes),
                "subscription": provider.metadata, "error": ""}

    def save(data):
        if data.get("zenxnet", {}).get("hwid") != block["hwid"]:
            raise contours.ContourError("Идентификатор устройства изменился; повторите проверку")
        memberships = set(contours.provider_contours(app.cfg, data))
        memberships.add(target)
        data["zenxnet"]["api_key"] = url
        data["zenxnet"]["contours"] = sorted(memberships)
        return data

    import apply
    with apply.Flock(app.cfg.get("lock") or "/run/vpn-agent.lock"):
        auth.update_secrets_atomic(path, save)
        app.reload_secrets()
        with app.db_lock:
            if target == "1":
                database, current_host = app.pool, app.current_host()
            elif contours.read(app.cfg)["secondary"] == "ready":
                import pool
                child = contours.config(app.cfg)
                database = pool.Pool(child["db"])
                current_host = apply.current_upstream(apply.load_json(child["singbox_config"]))
            else:
                # Creation consumes the validated durable cache, not C1's pool.
                database, current_host = None, None
            if database is not None:
                try:
                    refreshed = database.refresh({"zenxnet": provider}, actor="user",
                                                 keep_hosts={current_host} if current_host else None)
                    if refreshed["errors"]:
                        raise contours.ContourError("Каталог контура не обновлён; повторите обновление")
                    database.set_setting("subscription:zenxnet", json.dumps(provider.metadata))
                    database.log_event("subscription-set", actor="user", result="ok", detail="zenxnet")
                finally:
                    if database is not app.pool:
                        database.close()
    return {"ok": True, "saved": True, "verified": True, "provider": "zenxnet",
            "masked": "••••••••", "nodes": len(nodes), "subscription": provider.metadata}


def api_get(handler, path, app):
    if path == "/api/contours":
        return handler._json(200, contours.public(main_app(app).cfg))
    return None


def api_post(handler, path, body, app):
    primary = main_app(app)
    if path == "/api/contours":
        if body.get("url"):
            save_subscription(primary, body["url"], target="2")
        elif "2" not in contours.provider_contours(primary.cfg, primary.secrets):
            saved = (primary.secrets.get("zenxnet") or {}).get("api_key")
            if saved:
                save_subscription(primary, saved, target="2")
        return handler._json(200, contours.create(primary.cfg, primary.secrets))
    if path == "/api/contours/assign":
        import apply
        from webpanel import clients
        try:
            with apply.Flock(primary.cfg.get("lock") or "/run/vpn-agent.lock"):
                clients.require_contour_client(primary.cfg, contours.CURRENT.get(), pubkey=body.get("pubkey"))
                recovered = clients.reconcile_client_operation(
                    primary.cfg, _locked=True, dns_pool=primary.saga_pool)
                if recovered.get("recovery_pending"):
                    raise clients.ClientError("Выдача доступа ещё восстанавливается; повторите перенос позже")
                clients.require_contour_client(primary.cfg, contours.CURRENT.get(), pubkey=body.get("pubkey"))
                result = contours.assign(primary.cfg, body.get("pubkey"), str(body.get("contour")), _locked=True)
        except clients.ClientError as error:
            raise contours.ContourError(str(error)) from error
        return handler._json(200, result)
    if path == "/api/contours/delete":
        result = contours.delete(primary.cfg)
        if isinstance(app, Apps):
            with app._lock:
                if app._second is not None:
                    app._second.pool.close()
                    app._second = None
        return handler._json(200, result)
    raise contours.ContourError("Неизвестная операция контура")
