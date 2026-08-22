# -*- coding: utf-8 -*-
import datetime
import threading
import time
import unittest
from unittest import mock

import _ctx
from providers import (Capability, ProviderCapabilities, ProviderError,
                       ProviderErrorKind, Proxy6, ProxyLine, ProxyWing)
from providers import base, PROVIDER_CLASSES
from providers import proxy6 as proxy6_mod
from providers.proxy6 import norm_proxy6
from providers.proxyline import norm_proxyline
from providers.proxywing import norm_proxywing


class TestTypedCapabilities(unittest.TestCase):
    def test_every_adapter_uses_one_immutable_capability_type(self):
        adapters = [Proxy6("k"), ProxyLine("k"), ProxyWing("k")]
        for adapter in adapters:
            self.assertIsInstance(adapter.caps, ProviderCapabilities)
            self.assertTrue(adapter.caps["list"])
            self.assertTrue(adapter.caps.get("balance"))
            self.assertFalse(adapter.caps.get("unknown", False))
            with self.assertRaises(TypeError):
                adapter.caps["buy"] = True
        self.assertTrue(adapters[0].caps[Capability.BUY])
        self.assertFalse(adapters[1].caps[Capability.BUY])
        self.assertFalse(adapters[2].caps[Capability.PROLONG])


class TestTypedProviderErrors(unittest.TestCase):
    def test_http_statuses_have_stable_kinds(self):
        expected = {401: ProviderErrorKind.AUTH, 403: ProviderErrorKind.AUTH,
                    404: ProviderErrorKind.NOT_FOUND, 410: ProviderErrorKind.EXPIRED,
                    429: ProviderErrorKind.RATE_LIMIT}
        for status, kind in expected.items():
            error = base._http_error("api", status, '{}', {"Retry-After": "17"})
            self.assertEqual(error.kind, kind)
            self.assertEqual(error.retryable,
                             kind in (ProviderErrorKind.NETWORK,
                                      ProviderErrorKind.RATE_LIMIT))
        self.assertEqual(base._http_error(
            "api", 429, '{}', {"Retry-After": "17"}).retry_after, 17.0)

    def test_retry_after_http_date_is_seconds(self):
        now = datetime.datetime(2026, 8, 22, 12, 0, tzinfo=datetime.timezone.utc)
        self.assertEqual(base._retry_after(
            {"Retry-After": "Sat, 22 Aug 2026 12:02:00 GMT"}, now=now), 120.0)

    def test_nonfinite_retry_after_is_rejected(self):
        for value in ("Infinity", "1e309", "NaN", -1):
            self.assertIsNone(base._retry_after({"Retry-After": value}))
            self.assertIsNone(ProviderError("rate", retry_after=value).retry_after)

    def test_network_compatibility_flags_map_to_kind(self):
        error = ProviderError("down", network=True, unsent=True)
        self.assertEqual(error.kind, ProviderErrorKind.NETWORK)
        self.assertTrue(error.retryable)
        self.assertTrue(error.network and error.unsent)

    def test_proxy6_native_codes_are_classified(self):
        provider = Proxy6("secret")
        with mock.patch.object(proxy6_mod, "http_get_json",
                               return_value={"status": "no", "error_id": 100}):
            with self.assertRaises(ProviderError) as caught:
                provider._api("getproxy")
        self.assertEqual(caught.exception.kind, ProviderErrorKind.AUTH)
        with mock.patch.object(proxy6_mod, "http_get_json",
                               return_value={"status": "no", "error_id": 404}):
            with self.assertRaises(ProviderError) as caught:
                provider._api("getproxy")
        self.assertEqual(caught.exception.kind, ProviderErrorKind.NOT_FOUND)

    def test_proxy6_masking_preserves_unsent(self):
        provider = Proxy6("secret")
        error = ProviderError("secret connect", network=True, unsent=True)
        with mock.patch.object(proxy6_mod, "http_get_json", side_effect=error):
            with self.assertRaises(ProviderError) as caught:
                provider._api("buy", mutating=True)
        self.assertTrue(caught.exception.unsent)
        self.assertNotIn("secret", str(caught.exception))


class _Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class TestProviderCircuitBreaker(unittest.TestCase):
    def setUp(self):
        self.clock = _Clock()
        self.breaker = base.ProviderCircuitBreaker(
            threshold=3, recovery_seconds=30, clock=self.clock)

    def fail(self, error):
        self.breaker.before_call("list")
        self.breaker.failure(error)

    def test_network_threshold_open_and_half_open_recovery(self):
        error = ProviderError("down", network=True, unsent=True)
        for _ in range(3):
            self.fail(error)
        self.assertEqual(self.breaker.snapshot()["state"], "open")
        with self.assertRaises(ProviderError) as blocked:
            self.breaker.before_call("list")
        self.assertEqual(blocked.exception.code, "circuit-open")
        self.assertTrue(blocked.exception.unsent)
        self.clock.now += 30
        self.breaker.before_call("list")
        with self.assertRaises(ProviderError):
            self.breaker.before_call("concurrent")
        self.breaker.success()
        self.assertEqual(self.breaker.snapshot()["state"], "closed")

    def test_provider_throttle_serializes_concurrent_callers(self):
        provider = base.Provider("key")
        provider.min_interval = 0.02
        barrier = threading.Barrier(5)
        stamps = []
        lock = threading.Lock()

        def call():
            barrier.wait()
            provider._throttled(lambda: record())

        def record():
            with lock:
                stamps.append(time.monotonic())

        threads = [threading.Thread(target=call) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(2)
        stamps.sort()
        self.assertEqual(len(stamps), 5)
        self.assertTrue(all(b - a >= 0.015 for a, b in zip(stamps, stamps[1:])),
                        stamps)

    def test_concurrent_queue_rechecks_breaker_after_first_429(self):
        provider = base.Provider("key")
        provider.min_interval = 0.001
        barrier = threading.Barrier(5)
        transport_calls = []
        outcomes = []
        lock = threading.Lock()

        def transport():
            transport_calls.append(time.monotonic())
            raise ProviderError("rate", kind=ProviderErrorKind.RATE_LIMIT,
                                retry_after=60)

        def call():
            barrier.wait()
            try:
                provider._guarded("list", transport)
            except ProviderError as error:
                with lock:
                    outcomes.append(error.code or error.kind.value)

        threads = [threading.Thread(target=call) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(2)
        self.assertEqual(len(transport_calls), 1)
        self.assertEqual(len(outcomes), 5)
        self.assertEqual(outcomes.count("circuit-open"), 4)
        self.assertEqual(provider.breaker.snapshot()["state"], "open")

    def test_rate_limit_opens_immediately_for_retry_after(self):
        self.fail(ProviderError("slow", kind=ProviderErrorKind.RATE_LIMIT,
                                retry_after=17))
        snapshot = self.breaker.snapshot()
        self.assertEqual(snapshot["state"], "open")
        self.assertEqual(snapshot["retry_after"], 17.0)

    def test_auth_does_not_trip_or_hide_next_call(self):
        for _ in range(5):
            self.fail(ProviderError("bad key", kind=ProviderErrorKind.AUTH))
        self.assertEqual(self.breaker.snapshot()["state"], "closed")
        self.breaker.before_call("balance")
        self.breaker.success()


class TestProviderConformance(unittest.TestCase):
    REQUIRED_PROXY_FIELDS = {
        "provider", "ext_id", "ip", "host", "port_http", "port_socks5",
        "user", "password", "country", "ip_version", "kind", "date_end", "descr",
    }

    def test_every_registered_adapter_has_common_contract(self):
        self.assertGreaterEqual(len(PROVIDER_CLASSES), 3)
        for name, cls in PROVIDER_CLASSES.items():
            adapter = cls("fixture-key")
            self.assertEqual(adapter.name, name)
            self.assertIsInstance(adapter.caps, ProviderCapabilities)
            self.assertTrue(adapter.caps[Capability.LIST])
            self.assertTrue(adapter.caps[Capability.BALANCE])
            for capability in adapter.caps.enabled:
                self.assertTrue(callable(getattr(adapter, capability.value, None)),
                                "%s advertises missing %s" % (name, capability.value))

    def test_saved_anonymized_responses_normalize_to_same_shape(self):
        p6 = _ctx.fixture("proxy6_getproxy.json")
        pl = _ctx.fixture("proxyline_proxies.json")
        pw = _ctx.fixture("proxywing_proxies.json")
        normalized = [item for item in
                      (norm_proxy6(raw) for raw in (p6.get("list") or {}).values()) if item]
        normalized += [norm_proxyline(raw) for raw in pl["results"]]
        order = pw["orders"][0]
        normalized += [norm_proxywing(raw, order, "datacenter")
                       for raw in order["proxies"]]
        self.assertGreaterEqual(len(normalized), 4)
        for item in normalized:
            self.assertEqual(set(item), self.REQUIRED_PROXY_FIELDS)
            self.assertTrue(item["provider"] in PROVIDER_CLASSES)
            self.assertTrue(item["ext_id"] and item["host"])


if __name__ == "__main__":
    unittest.main()
