# -*- coding: utf-8 -*-
"""Atomic Mail transport: one durable inbox, REST authentication and JMAP.

Protocol checked against atomic-mail-agentic be3615eb5b09b5b6bd5fdbe37c848fec528749d7.
Only the API key and registration state live in secrets.json. Temporary tokens
stay in memory. This module never reads mail or retries an uncertain submission.
"""
from __future__ import annotations

import base64
import contextlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import http.client
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_SECRETS_PATH = "/etc/vpn-panel/secrets.json"
AUTH_URL = "https://auth.atomicmail.ai"
API_URL = "https://api.atomicmail.ai"
POW_SALT = b"0b980734412c292d6549110276b604ab1dea4883bd460d77d1b984adf8bca083"
POW_TIMEOUT = 150
POW_WORKERS = 2
HTTP_TIMEOUT = 20
MAX_RESPONSE = 1024 * 1024
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"
SUBMISSION = "urn:ietf:params:jmap:submission"
_EMAIL_RE = re.compile(r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$")
_CACHE = {}
_LOCKS = {}
_LOCKS_GUARD = threading.Lock()


class AtomicMailError(Exception):
    """Safe user-facing failure; unknown means the mutation must not be retried."""

    def __init__(self, code, message, *, unknown=False, status=None):
        super().__init__(message)
        self.code = code
        self.unknown = unknown
        self.status = status


def _error(code, *, unknown=False, status=None):
    messages = {
        "network": "Atomic Mail временно недоступен. Повторите проверку позже.",
        "auth": "Atomic Mail отклонил сохранённый доступ. Восстановите ключ из резервной копии.",
        "rate_limit": "Atomic Mail ограничил частоту запросов. Повторите проверку позже.",
        "protocol": "Atomic Mail вернул неожиданный ответ. Почта пока недоступна.",
        "pow": "Не удалось подготовить доступ к Atomic Mail за отведённое время.",
        "storage": "Не удалось прочитать или сохранить доступ к Atomic Mail.",
        "busy": "Подготовка Atomic Mail уже выполняется. Повторите проверку позже.",
        "not_ready": "Atomic Mail ещё не настроен. Запустите подготовку почты.",
        "registration_unknown": "Результат создания ящика Atomic Mail неизвестен. Повторная регистрация остановлена; требуется проверка доступа.",
        "registration_failed": "Atomic Mail отклонил создание ящика. Проверьте состояние почты перед повторной настройкой.",
        "send_rejected": "Atomic Mail не принял письмо к отправке.",
        "send_unknown": "Результат отправки неизвестен. Автоматический повтор остановлен, чтобы не отправить письмо дважды.",
        "invalid_email": "Укажите корректный адрес электронной почты.",
        "send_review": "Нужна проверка неопределённых отправок Atomic Mail. Новые письма временно остановлены.",
    }
    return AtomicMailError(code, messages.get(code, messages["protocol"]), unknown=unknown, status=status)


def _read(path):
    try:
        with open(path, encoding="utf-8") as source:
            data = json.load(source)
        block = data.get("atomicmail", {})
        if not isinstance(data, dict) or not isinstance(block, dict):
            raise ValueError()
        return block
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, TypeError, AttributeError):
        raise _error("storage") from None


def _save(path, block):
    from webpanel.auth import update_secrets_atomic
    try:
        def merge(data):
            data["atomicmail"] = dict(block)
            return data
        update_secrets_atomic(str(path), merge)
    except (OSError, ValueError, TypeError):
        raise _error("storage") from None


@contextlib.contextmanager
def _locked(path):
    key = os.path.abspath(path)
    with _LOCKS_GUARD:
        lock = _LOCKS.setdefault(key, threading.Lock())
    if not lock.acquire(timeout=3):
        raise _error("busy")
    fd = None
    try:
        try:
            fd = os.open(key + ".atomicmail.lock", os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.fchmod(fd, 0o600)
            if os.name == "posix":
                import fcntl
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise _error("busy") from None
        except OSError:
            raise _error("storage") from None
        yield
    finally:
        if fd is not None:
            os.close(fd)
        lock.release()


def status(secrets_path=DEFAULT_SECRETS_PATH):
    """Return saved readiness and address without secrets or network access."""
    try:
        data = _read(secrets_path)
    except AtomicMailError as exc:
        return {"ready": False, "address": "", "status": "error", "error": str(exc)}
    state = data.get("status", "not_configured")
    if state == "provisioning":
        state = "provisioning_unknown"
    error = ""
    if state in ("provisioning_unknown", "registration_failed"):
        error = str(_error("registration_unknown" if state == "provisioning_unknown" else state))
    if not error and data.get("uncertain_sends"):
        error = str(_error("send_unknown"))
    return {"ready": state == "ready" and bool(data.get("api_key")),
            "address": data.get("address", ""), "status": state, "error": error}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http(url, method="POST", *, token=None, body=None, mutation=False):
    headers = {"Accept": "application/json", "User-Agent": "REDUT-AtomicMail/1"}
    if token:
        headers["Authorization"] = "Bearer " + token
    raw = None
    if body is not None:
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=raw, headers=headers, method=method)
    try:
        opener = urllib.request.build_opener(_NoRedirect())
        with opener.open(request, timeout=HTTP_TIMEOUT) as response:
            payload = response.read(MAX_RESPONSE + 1)
            response_headers = dict(response.headers.items())
        if len(payload) > MAX_RESPONSE:
            raise ValueError()
        data = json.loads(payload) if payload.strip() else {}
        if not isinstance(data, dict):
            raise ValueError()
        return data, response_headers
    except urllib.error.HTTPError as exc:
        code = "auth" if exc.code in (401, 403) else "rate_limit" if exc.code == 429 else "network" if exc.code >= 500 else "protocol"
        raise _error(code, unknown=mutation and exc.code >= 500, status=exc.code) from None
    except (urllib.error.URLError, OSError, TimeoutError, http.client.HTTPException):
        raise _error("network", unknown=mutation) from None
    except (ValueError, UnicodeError):
        raise _error("protocol", unknown=mutation) from None


def _bearer(headers):
    raw = next((v for k, v in headers.items() if k.lower() == "authorization"), "")
    match = re.fullmatch(r"\s*Bearer\s+(\S+)\s*", str(raw), re.IGNORECASE)
    if not match:
        raise _error("protocol")
    return match.group(1)


def _claims(token):
    try:
        part = token.split(".")[1]
        result = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        if not isinstance(result, dict):
            raise ValueError()
        return result
    except (ValueError, IndexError, TypeError):
        raise _error("protocol") from None


def _live(token, margin):
    if not token:
        return False
    try:
        expiry = _claims(token).get("exp")
        return isinstance(expiry, (int, float)) and expiry > time.time() + margin
    except AtomicMailError:
        return False


def _pow_local(challenge, difficulty, deadline, workers=1):
    if not isinstance(challenge, str) or not challenge or len(challenge) > 4096 or type(difficulty) is not int or not 0 <= difficulty <= 512:
        raise _error("protocol")
    if type(workers) is not int or not 1 <= workers <= POW_WORKERS:
        raise _error("protocol")
    if not hasattr(hashlib, "scrypt"):
        raise _error("pow")
    target = 1 << (512 - difficulty)
    stop = threading.Event()

    def solve(start):
        nonce = start
        while not stop.is_set() and time.monotonic() < deadline:
            digest = hashlib.scrypt((challenge + ":" + str(nonce)).encode("utf-8"),
                                    salt=POW_SALT, n=16384, r=8, p=1, dklen=64,
                                    maxmem=32 * 1024 * 1024)
            if int.from_bytes(digest, "big") < target:
                stop.set()
                return {"powHex": digest.hex(), "nonce": str(nonce)}
            nonce += workers
        return None

    if workers == 1:
        result = solve(0)
        if result is not None:
            return result
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(solve, start) for start in range(workers)]
            try:
                for future in as_completed(futures):
                    result = future.result()
                    if result is not None:
                        return result
            finally:
                stop.set()
    raise _error("pow")


def _solve_pow(challenge, difficulty, expires):
    timeout = min(POW_TIMEOUT, max(0, expires - time.time() - 2))
    if timeout < 1:
        raise _error("pow")
    try:
        completed = subprocess.run([sys.executable, os.path.abspath(__file__), "--pow"],
                                   input=json.dumps({"challenge": challenge, "difficulty": difficulty,
                                                     "timeout": timeout, "workers": POW_WORKERS}), text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=timeout + 1, check=True)
        result = json.loads(completed.stdout)
        if not isinstance(result, dict) or not re.fullmatch(r"[0-9a-f]{128}", result.get("powHex", "")) or not re.fullmatch(r"[0-9]+", result.get("nonce", "")):
            raise ValueError()
        return result
    except (OSError, ValueError, subprocess.SubprocessError):
        raise _error("pow") from None


def _challenge():
    _, headers = _http(AUTH_URL + "/api/v1/challenge")
    token = _bearer(headers)
    claims = _claims(token)
    expiry = claims.get("exp")
    if not isinstance(expiry, (int, float)):
        raise _error("protocol")
    solution = _solve_pow(claims.get("jti"), claims.get("difficulty"), expiry)
    return token, dict(solution)


class _Client:
    def __init__(self, key, session=None):
        self.key = key
        self.session = session
        self.capability = None

    def bearer(self, force=False):
        if not force and _live(self.capability, 15):
            return self.capability
        for attempt in range(2):
            if not _live(self.session, 60):
                challenge, solution = _challenge()
                solution["apiKey"] = self.key
                _, headers = _http(AUTH_URL + "/api/v1/session", token=challenge, body=solution)
                self.session = _bearer(headers)
            try:
                _, headers = _http(AUTH_URL + "/api/v1/capability", token=self.session)
            except AtomicMailError as exc:
                if exc.status != 401 or attempt:
                    raise
                self.session = None
                continue
            self.capability = _bearer(headers)
            return self.capability
        raise _error("auth")

    def request(self, url, method="GET", *, body=None, mutation=False):
        for attempt in range(2):
            try:
                data, _ = _http(url, method, token=self.bearer(force=attempt == 1), body=body, mutation=mutation)
                return data
            except AtomicMailError as exc:
                if exc.status != 401 or attempt:
                    raise
        raise _error("auth")

    def discover(self):
        data = self.request(API_URL + "/.well-known/jmap")
        api = data.get("apiUrl")
        accounts = data.get("primaryAccounts", {})
        account = accounts.get(MAIL) if isinstance(accounts, dict) else None
        if not isinstance(api, str) or not isinstance(account, str) or not account:
            raise _error("protocol")
        try:
            parsed = urllib.parse.urlsplit(api)
            trusted = parsed.scheme == "https" and parsed.hostname == "api.atomicmail.ai" and parsed.port in (None, 443) and not parsed.username and not parsed.password and not parsed.fragment
        except ValueError:
            trusted = False
        if not trusted:
            raise _error("protocol")
        return api, account

    def methods(self, api, calls, *, mutation=False):
        data = self.request(api, "POST", body={"using": [CORE, MAIL, SUBMISSION], "methodCalls": calls}, mutation=mutation)
        responses = data.get("methodResponses")
        if not isinstance(responses, list):
            raise _error("protocol", unknown=mutation)
        return responses


def _client(path, data, session=None):
    key = data.get("api_key")
    if not isinstance(key, str) or not key:
        raise _error("not_ready")
    cache_key = os.path.abspath(path)
    client = _CACHE.get(cache_key)
    if client is None or client.key != key:
        client = _Client(key, session=session)
        _CACHE[cache_key] = client
    return client


def ensure_ready(secrets_path=DEFAULT_SECRETS_PATH):
    """Provision once, durably save access, then verify authenticated JMAP access."""
    path = str(secrets_path)
    with _locked(path):
        data = _read(path)
        session = None
        if not data.get("api_key"):
            state = data.get("status")
            if state in ("provisioning", "provisioning_unknown"):
                raise _error("registration_unknown", unknown=True)
            if state == "registration_failed":
                raise _error(state)
            if state and state != "prepared":
                raise _error("auth")
            if not data:
                installation_id = secrets.token_hex(16)
                username = "redut-" + secrets.token_hex(6)
                data = {"installation_id": installation_id, "username": username,
                        "address": username + "@atomicmail.ai", "status": "prepared"}
                _save(path, data)
            if not isinstance(data.get("username"), str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{3,19}[a-z0-9]", data["username"]):
                raise _error("storage")
            challenge, solution = _challenge()
            solution["username"] = data["username"]
            data["status"] = "provisioning"
            _save(path, data)
            try:
                response, headers = _http(AUTH_URL + "/api/v1/session", token=challenge, body=solution, mutation=True)
                key = response.get("apiKey")
                if not isinstance(key, str) or not key:
                    raise _error("registration_unknown", unknown=True)
            except AtomicMailError as exc:
                if exc.code == "rate_limit" and exc.status == 429 and not exc.unknown:
                    data["status"] = "prepared"
                    _save(path, data)
                    raise
                data["status"] = "provisioning_unknown" if exc.unknown else "registration_failed"
                _save(path, data)
                raise _error("registration_unknown" if exc.unknown else "registration_failed", unknown=exc.unknown) from None
            data.update(api_key=key, status="configured")
            _save(path, data)
            session = _bearer(headers)
        _client(path, data, session).discover()
        data["status"] = "ready"
        _save(path, data)
        return status(path)


def _result(responses, method, call_id, *, mutation=False):
    for item in responses:
        if isinstance(item, list) and len(item) == 3 and item[2] == call_id:
            if item[0] == "error":
                if mutation and isinstance(item[1], dict) and item[1].get("type") == "serverPartialFail":
                    raise _error("send_unknown", unknown=True)
                raise _error("send_rejected" if mutation else "protocol")
            if item[0] == method and isinstance(item[1], dict):
                return item[1]
    raise _error("protocol", unknown=mutation)


def send(secrets_path, to, subject, body):
    """Send once. Success means accepted by the API, not confirmed delivery."""
    if not isinstance(to, str) or not _EMAIL_RE.fullmatch(to) or len(to) > 254:
        raise _error("invalid_email")
    path = str(secrets_path)
    with _locked(path):
        data = _read(path)
        fingerprint = hashlib.sha256(json.dumps([to, subject, body], ensure_ascii=False,
                                               separators=(",", ":")).encode("utf-8")).hexdigest()
        uncertain = data.get("uncertain_sends", [])
        if not isinstance(uncertain, list):
            raise _error("storage")
        if fingerprint in uncertain:
            raise _error("send_unknown", unknown=True)
        if len(uncertain) >= 32:
            raise _error("send_review")
        client = _client(path, data)
        address = data.get("address")
        if not isinstance(address, str) or not _EMAIL_RE.fullmatch(address):
            raise _error("not_ready")
        api, account = client.discover()
        responses = client.methods(api, [["Mailbox/query", {"accountId": account, "filter": {"role": "sent"}, "limit": 1}, "sent"]])
        ids = _result(responses, "Mailbox/query", "sent").get("ids")
        if ids == []:
            responses = client.methods(api, [["Mailbox/query", {"accountId": account, "filter": {"role": "inbox"}, "limit": 1}, "inbox"]])
            ids = _result(responses, "Mailbox/query", "inbox").get("ids")
        if not isinstance(ids, list) or not ids or not isinstance(ids[0], str):
            raise _error("protocol")
        message = {"mailboxIds": {ids[0]: True}, "from": [{"email": address}],
                   "to": [{"email": to}], "subject": subject,
                   "textBody": [{"partId": "body", "type": "text/plain"}],
                   "bodyValues": {"body": {"value": body}},
                   "keywords": {"$draft": True, "$seen": True}}
        calls = [["Email/set", {"accountId": account, "create": {"message": message}}, "email"],
                 ["EmailSubmission/set", {"accountId": account,
                  "create": {"submission": {"emailId": "#message", "envelope": {
                      "mailFrom": {"email": address}, "rcptTo": [{"email": to}]}}},
                  "onSuccessUpdateEmail": {"#submission": {"keywords/$draft": None, "keywords/$sent": True}}}, "submit"]]
        data["uncertain_sends"] = uncertain + [fingerprint]
        _save(path, data)
        try:
            responses = client.methods(api, calls, mutation=True)
            created = _result(responses, "Email/set", "email", mutation=True)
            submitted = _result(responses, "EmailSubmission/set", "submit", mutation=True)
            if created.get("notCreated") or submitted.get("notCreated"):
                raise _error("send_rejected")
            created_map = created.get("created")
            submitted_map = submitted.get("created")
            if not isinstance(created_map, dict) or not isinstance(submitted_map, dict):
                raise _error("send_unknown", unknown=True)
            for item in (created_map.get("message"), submitted_map.get("submission")):
                if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
                    raise _error("send_unknown", unknown=True)
        except AtomicMailError as exc:
            if exc.unknown:
                raise _error("send_unknown", unknown=True) from None
            try:
                data["uncertain_sends"] = uncertain
                _save(path, data)
            except Exception:
                raise _error("send_unknown", unknown=True) from None
            raise
        except Exception:
            raise _error("send_unknown", unknown=True) from None
        try:
            data["uncertain_sends"] = uncertain
            _save(path, data)
        except Exception:
            raise _error("send_unknown", unknown=True) from None


if __name__ == "__main__" and sys.argv[1:] == ["--pow"]:
    try:
        if os.name == "posix":
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (POW_TIMEOUT * POW_WORKERS + 1,
                                                   POW_TIMEOUT * POW_WORKERS + 2))
            resource.setrlimit(resource.RLIMIT_AS, (384 * 1024 * 1024, 384 * 1024 * 1024))
            os.nice(10)
        task = json.loads(sys.stdin.read(8192))
        timeout = min(POW_TIMEOUT, max(0, float(task["timeout"])))
        result = _pow_local(task["challenge"], task["difficulty"], time.monotonic() + timeout,
                            workers=task.get("workers", 1))
        print(json.dumps(result))
    except Exception:
        sys.exit(1)
