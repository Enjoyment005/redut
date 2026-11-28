# -*- coding: utf-8 -*-
"""Offline protocol and crash-safety tests. Never create inboxes or send mail."""
import base64
import json
import http.client
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import _ctx  # noqa: F401
import atomicmail as am


def jwt(**claims):
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return "header." + payload + ".signature"


class FakeAPI:
    def __init__(self):
        self.calls = []
        self.submissions = 0
        self.reject = False
        self.unknown = False
        self.discovery_error = False
        self.api_url = am.API_URL + "/jmap/api"

    def __call__(self, url, method="POST", **kwargs):
        self.calls.append((url, kwargs))
        if url.endswith("/challenge"):
            return {}, {"Authorization": "Bearer " + jwt(jti="test", difficulty=0, exp=time.time() + 180)}
        if url.endswith("/session"):
            body = kwargs["body"]
            payload = {"apiKey": "your_atomic_api_key_here"} if "username" in body else {}
            return payload, {"Authorization": "Bearer " + jwt(exp=time.time() + 3600)}
        if url.endswith("/capability"):
            return {}, {"Authorization": "Bearer " + jwt(exp=time.time() + 120)}
        if url.endswith("/.well-known/jmap"):
            if self.discovery_error:
                raise am._error("network")
            return {"apiUrl": self.api_url, "primaryAccounts": {am.MAIL: "account"}}, {}
        calls = kwargs["body"]["methodCalls"]
        if calls[0][0] == "Mailbox/query":
            return {"methodResponses": [["Mailbox/query", {"ids": ["sent-box"]}, calls[0][2]]]}, {}
        self.submissions += 1
        if self.unknown:
            raise am._error("network", unknown=True)
        result = {"notCreated": {"submission": {"type": "forbidden"}}} if self.reject else {"created": {"submission": {"id": "s1"}}}
        return {"methodResponses": [["Email/set", {"created": {"message": {"id": "e1"}}}, "email"], ["EmailSubmission/set", result, "submit"]]}, {}


class AtomicMailTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "secrets.json"
        self.path.write_text(json.dumps({"smtp": {"host": "old.example"}, "provider": {"token": "untouched"}}))
        self.api = FakeAPI()
        self.http = mock.patch.object(am, "_http", side_effect=self.api)
        self.pow = mock.patch.object(am, "_solve_pow", return_value={"powHex": "0" * 128, "nonce": "0"})
        self.http.start()
        self.pow.start()
        am._CACHE.clear()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.http.stop)
        self.addCleanup(self.pow.stop)
        self.addCleanup(am._CACHE.clear)

    def saved(self):
        return json.loads(self.path.read_text())

    def ready(self):
        am.ensure_ready(self.path)

    def test_registration_saves_key_before_jmap_and_preserves_other_secrets(self):
        self.api.discovery_error = True
        with self.assertRaises(am.AtomicMailError):
            self.ready()
        data = self.saved()
        self.assertEqual(data["atomicmail"]["api_key"], "your_atomic_api_key_here")
        self.assertEqual(data["atomicmail"]["status"], "configured")
        self.assertEqual(data["smtp"]["host"], "old.example")
        self.assertEqual(data["provider"]["token"], "untouched")
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        self.api.discovery_error = False
        self.ready()
        registrations = [k for u, k in self.api.calls if u.endswith("/session") and "username" in k["body"]]
        self.assertEqual(len(registrations), 1)
        self.assertTrue(am.status(self.path)["ready"])
        self.assertNotIn("api_key", am.status(self.path))

    def test_registration_intent_precedes_request(self):
        original = self.api.__call__
        def api(url, method="POST", **kwargs):
            if url.endswith("/session") and "username" in kwargs["body"]:
                block = self.saved()["atomicmail"]
                self.assertEqual(block["status"], "provisioning")
                self.assertEqual(block["username"], kwargs["body"]["username"])
            return original(url, method, **kwargs)
        am._http.side_effect = api
        self.ready()

    def test_ambiguous_registration_never_registers_again(self):
        original = self.api.__call__
        def api(url, method="POST", **kwargs):
            if url.endswith("/session"):
                raise am._error("network", unknown=True)
            return original(url, method, **kwargs)
        am._http.side_effect = api
        with self.assertRaises(am.AtomicMailError) as error:
            self.ready()
        self.assertTrue(error.exception.unknown)
        self.assertEqual(self.saved()["atomicmail"]["status"], "provisioning_unknown")
        am._http.reset_mock()
        with self.assertRaises(am.AtomicMailError):
            self.ready()
        am._http.assert_not_called()

    def test_registration_429_allows_explicit_retry_with_same_identity(self):
        original = self.api.__call__
        def api(url, method="POST", **kwargs):
            if url.endswith("/session"):
                raise am._error("rate_limit", status=429)
            return original(url, method, **kwargs)
        am._http.side_effect = api
        with self.assertRaises(am.AtomicMailError) as error:
            self.ready()
        self.assertEqual(error.exception.code, "rate_limit")
        self.assertFalse(error.exception.unknown)
        prepared = self.saved()["atomicmail"]
        self.assertEqual(prepared["status"], "prepared")
        self.assertNotIn("api_key", prepared)
        am._http.side_effect = self.api
        self.ready()
        ready = self.saved()["atomicmail"]
        self.assertEqual(ready["username"], prepared["username"])
        self.assertEqual(ready["installation_id"], prepared["installation_id"])
        self.assertTrue(am.status(self.path)["ready"])

    def test_interrupted_registration_without_key_stops(self):
        self.path.write_text(json.dumps({"atomicmail": {"status": "provisioning", "username": "redut-test"}}))
        with self.assertRaises(am.AtomicMailError):
            self.ready()
        am._http.assert_not_called()
        self.assertEqual(am.status(self.path)["status"], "provisioning_unknown")

    def test_storage_failure_prevents_registration(self):
        with mock.patch.object(am, "_save", side_effect=am._error("storage")):
            with self.assertRaises(am.AtomicMailError):
                self.ready()
        am._http.assert_not_called()

    def test_restart_logs_in_with_api_key_not_username(self):
        self.ready()
        address = am.status(self.path)["address"]
        am._CACHE.clear()
        self.api.calls.clear()
        self.ready()
        sessions = [kwargs["body"] for url, kwargs in self.api.calls if url.endswith("/session")]
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["apiKey"], "your_atomic_api_key_here")
        self.assertNotIn("username", sessions[0])
        self.assertEqual(am.status(self.path)["address"], address)

    def test_send_before_setup_does_not_register(self):
        with self.assertRaises(am.AtomicMailError):
            am.send(self.path, "owner@example.com", "subject", "body")
        am._http.assert_not_called()

    def test_send_success_requires_submission_and_clears_guard(self):
        self.ready()
        am.send(self.path, "owner@example.com", "subject", "body")
        self.assertEqual(self.api.submissions, 1)
        self.assertEqual(self.saved()["atomicmail"]["uncertain_sends"], [])
        calls = [k["body"]["methodCalls"] for u, k in self.api.calls if k.get("mutation") and "methodCalls" in k.get("body", {})]
        self.assertEqual(calls[0][1][0], "EmailSubmission/set")
        self.assertEqual(calls[0][1][1]["create"]["submission"]["emailId"], "#message")

    def test_http_200_not_created_is_failure(self):
        self.ready()
        self.api.reject = True
        with self.assertRaises(am.AtomicMailError) as error:
            am.send(self.path, "owner@example.com", "subject", "body")
        self.assertEqual(error.exception.code, "send_rejected")
        self.assertEqual(self.saved()["atomicmail"]["uncertain_sends"], [])

    def test_jmap_partial_failure_keeps_guard_and_stops_retry(self):
        self.ready()
        original = self.api.__call__
        def api(url, method="POST", **kwargs):
            data, headers = original(url, method, **kwargs)
            if kwargs.get("mutation"):
                data["methodResponses"][1] = ["error", {"type": "serverPartialFail"}, "submit"]
            return data, headers
        am._http.side_effect = api
        for _attempt in range(2):
            with self.assertRaises(am.AtomicMailError) as error:
                am.send(self.path, "owner@example.com", "subject", "body")
            self.assertTrue(error.exception.unknown)
        self.assertEqual(self.api.submissions, 1)
        self.assertEqual(len(self.saved()["atomicmail"]["uncertain_sends"]), 1)

    def test_ambiguous_send_is_not_repeated_after_restart(self):
        self.ready()
        self.api.unknown = True
        with self.assertRaises(am.AtomicMailError) as error:
            am.send(self.path, "owner@example.com", "subject", "body")
        self.assertTrue(error.exception.unknown)
        am._CACHE.clear()
        self.api.unknown = False
        with self.assertRaises(am.AtomicMailError) as error:
            am.send(self.path, "owner@example.com", "subject", "body")
        self.assertTrue(error.exception.unknown)
        self.assertEqual(self.api.submissions, 1)
        am.send(self.path, "owner@example.com", "different subject", "body")
        self.assertEqual(self.api.submissions, 2)
        self.assertTrue(am.status(self.path)["error"])
        self.assertNotIn("body", str(self.saved()["atomicmail"]["uncertain_sends"]))

    def test_accepted_send_with_guard_cleanup_failure_is_unknown(self):
        self.ready()
        original = am._save
        def save(path, data):
            if not data.get("uncertain_sends"):
                raise am._error("storage")
            return original(path, data)
        with mock.patch.object(am, "_save", side_effect=save):
            with self.assertRaises(am.AtomicMailError) as error:
                am.send(self.path, "owner@example.com", "subject", "body")
        self.assertEqual(error.exception.code, "send_unknown")
        self.assertTrue(error.exception.unknown)
        self.assertEqual(self.api.submissions, 1)
        self.assertEqual(len(self.saved()["atomicmail"]["uncertain_sends"]), 1)
        with self.assertRaises(am.AtomicMailError) as error:
            am.send(self.path, "owner@example.com", "subject", "body")
        self.assertTrue(error.exception.unknown)
        self.assertEqual(self.api.submissions, 1)

    def test_unexpected_exception_during_submission_is_safe_unknown(self):
        self.ready()
        original = self.api.__call__
        def api(url, method="POST", **kwargs):
            if kwargs.get("mutation"):
                raise RuntimeError("private response body")
            return original(url, method, **kwargs)
        am._http.side_effect = api
        with self.assertRaises(am.AtomicMailError) as error:
            am.send(self.path, "owner@example.com", "subject", "body")
        self.assertTrue(error.exception.unknown)
        self.assertNotIn("private response body", str(error.exception))
        self.assertEqual(len(self.saved()["atomicmail"]["uncertain_sends"]), 1)

    def test_incomplete_http_response_uses_safe_mutation_error(self):
        self.http.stop()
        for mutation in (False, True):
            with self.subTest(mutation=mutation):
                with mock.patch.object(am.urllib.request, "build_opener") as opener:
                    response = opener.return_value.open.return_value.__enter__.return_value
                    response.read.side_effect = http.client.IncompleteRead(b"private response fragment", 100)
                    with self.assertRaises(am.AtomicMailError) as error:
                        am._http(am.API_URL + "/jmap", mutation=mutation)
                self.assertEqual(error.exception.unknown, mutation)
                self.assertNotIn("private response fragment", str(error.exception))

    def test_pending_guard_is_saved_before_submission(self):
        self.ready()
        original = self.api.__call__
        def api(url, method="POST", **kwargs):
            if kwargs.get("mutation"):
                self.assertEqual(len(self.saved()["atomicmail"]["uncertain_sends"]), 1)
            return original(url, method, **kwargs)
        am._http.side_effect = api
        am.send(self.path, "owner@example.com", "subject", "body")

    def test_unknown_send_guard_has_bound(self):
        self.ready()
        data = self.saved()
        data["atomicmail"]["uncertain_sends"] = [str(i) for i in range(32)]
        self.path.write_text(json.dumps(data))
        with self.assertRaises(am.AtomicMailError) as error:
            am.send(self.path, "owner@example.com", "subject", "body")
        self.assertEqual(error.exception.code, "send_review")
        self.assertEqual(self.api.submissions, 0)

    def test_discovery_cannot_redirect_bearer_to_other_host(self):
        for url in ["http://api.atomicmail.ai/jmap", "https://evil.example/jmap", "https://api.atomicmail.ai:444/jmap", "https://user@api.atomicmail.ai/jmap"]:
            with self.subTest(url=url):
                self.api.api_url = url
                with self.assertRaises(am.AtomicMailError):
                    self.ready()

    def test_expired_capability_refresh_avoids_registration(self):
        self.ready()
        client = am._CACHE[os.path.abspath(self.path)]
        client.capability = jwt(exp=1)
        self.api.calls.clear()
        am.send(self.path, "owner@example.com", "subject", "body")
        self.assertTrue(any(u.endswith("/capability") for u, _ in self.api.calls))
        self.assertFalse(any(u.endswith("/session") for u, _ in self.api.calls))

    def test_bad_email_fails_before_network(self):
        with self.assertRaises(am.AtomicMailError):
            am.send(self.path, "owner@example.com\nBcc:bad@example.com", "subject", "body")
        am._http.assert_not_called()

    def test_concurrent_preparation_registers_one_inbox(self):
        gate = threading.Event()
        entered = threading.Event()
        original = self.api.__call__
        results = []
        def api(url, method="POST", **kwargs):
            if url.endswith("/challenge"):
                entered.set()
                gate.wait(2)
            return original(url, method, **kwargs)
        am._http.side_effect = api
        def prepare():
            try:
                results.append(am.ensure_ready(self.path))
            except Exception as exc:
                results.append(exc)
        first = threading.Thread(target=prepare)
        second = threading.Thread(target=prepare)
        first.start()
        self.assertTrue(entered.wait(2))
        second.start()
        gate.set()
        first.join(3)
        second.join(3)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(isinstance(r, dict) and r["ready"] for r in results))
        registrations = [k for u, k in self.api.calls if u.endswith("/session") and "username" in k["body"]]
        self.assertEqual(len(registrations), 1)

    def test_401_capability_refresh_is_bounded(self):
        self.ready()
        client = am._CACHE[os.path.abspath(self.path)]
        client.capability = None
        original = self.api.__call__
        attempts = []
        def api(url, method="POST", **kwargs):
            if url.endswith("/capability"):
                attempts.append(url)
                raise am._error("auth", status=401)
            return original(url, method, **kwargs)
        am._http.side_effect = api
        with self.assertRaises(am.AtomicMailError):
            client.bearer()
        self.assertEqual(len(attempts), 2)

    def test_missing_submission_id_is_not_success(self):
        self.ready()
        original = self.api.__call__
        def api(url, method="POST", **kwargs):
            data, headers = original(url, method, **kwargs)
            if kwargs.get("mutation"):
                data["methodResponses"][1][1] = {"created": {"submission": {}}}
            return data, headers
        am._http.side_effect = api
        with self.assertRaises(am.AtomicMailError) as error:
            am.send(self.path, "owner@example.com", "subject", "body")
        self.assertTrue(error.exception.unknown)
        self.assertEqual(len(self.saved()["atomicmail"]["uncertain_sends"]), 1)

    def test_missing_key_in_ready_state_does_not_create_new_account(self):
        self.path.write_text(json.dumps({"atomicmail": {"status": "ready", "address": "redut-test@atomicmail.ai"}}))
        with self.assertRaises(am.AtomicMailError):
            self.ready()
        am._http.assert_not_called()

    def test_errors_never_echo_upstream_body_or_secrets(self):
        self.http.stop()
        from urllib.error import HTTPError
        import io
        failure = HTTPError(am.AUTH_URL, 403, "your_atomic_api_key_here", {}, io.BytesIO(b'{"apiKey":"hidden-key"}'))
        with mock.patch.object(am.urllib.request, "build_opener") as opener:
            opener.return_value.open.side_effect = failure
            with self.assertRaises(am.AtomicMailError) as error:
                am._http(am.AUTH_URL)
        self.assertNotIn("your_atomic_api_key_here", str(error.exception))
        self.assertNotIn("hidden-key", str(error.exception))


class ProofOfWorkTests(unittest.TestCase):
    def test_matches_official_scrypt_vector(self):
        result = am._pow_local("fixture-alpha", 4, time.monotonic() + 10)
        self.assertEqual(result["nonce"], "4")
        self.assertEqual(result["powHex"], "0e365cf9d7a9a9d515b5362da1ed60b3c287d6b5de7f5f0e55b15bd8a34dd3605695e20f01fb60fbfd64f21dfafe151dcf22ba6b85bbd932fb569f89150c7c50")

    def test_worker_solves_valid_vector_with_resource_limits(self):
        result = am._solve_pow("fixture-alpha", 4, time.time() + 20)
        digest = am.hashlib.scrypt(("fixture-alpha:" + result["nonce"]).encode(),
                                  salt=am.POW_SALT, n=16384, r=8, p=1, dklen=64)
        self.assertEqual(result["powHex"], digest.hex())
        self.assertLess(int.from_bytes(digest, "big"), 1 << (512 - 4))

    def test_parallel_workers_do_not_repeat_nonces(self):
        seen = []
        def fake_scrypt(password, **kwargs):
            nonce = int(password.decode().rsplit(":", 1)[1])
            seen.append(nonce)
            time.sleep(0.002)
            return bytes([0] if nonce == 7 else [255]) * 64
        with mock.patch.object(am.hashlib, "scrypt", side_effect=fake_scrypt):
            result = am._pow_local("test", 1, time.monotonic() + 2, workers=2)
        self.assertEqual(result["nonce"], "7")
        self.assertEqual(len(seen), len(set(seen)))
        self.assertTrue(any(n % 2 for n in seen))
        self.assertTrue(any(n % 2 == 0 for n in seen))

    def test_worker_failure_respects_deadline(self):
        started = time.monotonic()
        with self.assertRaises(am.AtomicMailError) as error:
            am._solve_pow("test-unreachable-difficulty", 512, time.time() + 3.2)
        self.assertEqual(error.exception.code, "pow")
        self.assertLess(time.monotonic() - started, 5)

    def test_pow_budget_caps_at_150_seconds(self):
        response = mock.Mock(stdout=json.dumps({"powHex": "0" * 128, "nonce": "0"}))
        with mock.patch.object(am.subprocess, "run", return_value=response) as run:
            am._solve_pow("test", 1, time.time() + 10000)
        kwargs = run.call_args.kwargs
        task = json.loads(kwargs["input"])
        self.assertEqual(task["timeout"], 150)
        self.assertEqual(task["workers"], 2)
        self.assertEqual(kwargs["timeout"], 151)

    def test_invalid_difficulty_and_expired_deadline_rejected(self):
        for bits in [-1, 513, True, 1.5]:
            with self.assertRaises(am.AtomicMailError):
                am._pow_local("fixture", bits, time.monotonic() + 1)
        with self.assertRaises(am.AtomicMailError):
            am._solve_pow("fixture", 1, time.time() - 1)


if __name__ == "__main__":
    unittest.main()
