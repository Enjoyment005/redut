"""GeoIP replacement: real cache transactions, no external network in tests."""
import concurrent.futures
import contextlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from _ctx import PANEL_DIR
import geoip
import probe
import apply

IP = "1.2.3.4"
PRIMARY = {"ip": IP, "country_code": "CN", "city_name": "Beijing", "region_name": "Beijing",
           "time_zone": "+08:00", "asn": "64500", "as": "Example Network", "is_proxy": False,
           "latitude": 39.9, "longitude": 116.4}
SECONDARY = {"ip": IP, "success": True, "country_code": "CN", "city": "Beijing",
             "region": "Beijing", "timezone": {"id": "Asia/Shanghai"},
             "connection": {"asn": 64500, "org": "Example Network"},
             "latitude": 39.9, "longitude": 116.4}


class CacheFixture(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cache = Path(tmp.name) / "geoip.sqlite3"
        patch = mock.patch.object(geoip, "CACHE_PATH", str(self.cache))
        patch.start(); self.addCleanup(patch.stop)

    def response(self, source, ip, timeout):
        data = dict(PRIMARY if source == "ip2location" else SECONDARY, ip=ip)
        return geoip.parse(source, data, ip), "ok", 0

    def expire(self):
        with sqlite3.connect(self.cache) as conn:
            conn.execute("UPDATE answer SET expires=0, checked=0")
            conn.execute("UPDATE service SET retry_at=0")


class TestGeoParsers(unittest.TestCase):
    def test_primary_and_secondary_preserve_country_city_and_unknown_flags(self):
        for source, payload in zip(geoip.SOURCES, (PRIMARY, SECONDARY)):
            with self.subTest(source=source):
                data = geoip.parse(source, payload, IP)
                self.assertEqual((data["cc"], data["city"], data["asn"]), ("cn", "Beijing", "AS64500"))
                for field in ("proxy", "hosting", "mobile"):
                    self.assertIsNone(data[field], "free data cannot prove these negative flags")

    def test_wrong_ip_errors_bad_country_and_wrong_types_are_rejected(self):
        for payload in (None, [], {}, dict(PRIMARY, ip="5.6.7.8"), dict(PRIMARY, error={"code": 1}),
                        dict(PRIMARY, country_code="China"), dict(PRIMARY, country_code="ZZ")):
            self.assertIsNone(geoip.parse("ip2location", payload, IP))
        self.assertIsNone(geoip.parse("ipwho.is", dict(SECONDARY, success=False), IP))
        self.assertIsNone(geoip.parse("ipwho.is", dict(SECONDARY, success="true"), IP))

    def test_coordinates_and_asn_are_bounded(self):
        data = geoip.parse("ip2location", dict(PRIMARY, latitude=float("nan"), longitude=181, asn="-1"), IP)
        self.assertIsNone(data["lat"]); self.assertIsNone(data["lon"]); self.assertIsNone(data["asn"])

    def test_ipv6_normalization(self):
        ip = "2606:4700:4700::1111"
        self.assertEqual(geoip.parse("ip2location", dict(PRIMARY, ip=ip), ip)["cc"], "cn")


class TestGeoCache(CacheFixture):
    def test_country_passport_and_consensus_reuse_same_observations(self):
        with mock.patch.object(geoip, "_request", side_effect=self.response) as request:
            self.assertEqual(probe.geo_country(IP), "cn")
            self.assertEqual(probe.ip_intel(IP)["city"], "Beijing")
            self.assertEqual(request.call_count, 1)
            self.assertEqual(probe.geo_country_consensus(IP), {"cc": "cn", "alt": "cn", "agree": True})
            self.assertEqual(geoip.lookup(IP)["status"], "confirmed")
            self.assertEqual(request.call_count, 2)
            stamp = probe.ip_intel(IP)["geo_checked_at"]
            self.assertEqual(probe.ip_intel(IP)["geo_checked_at"], stamp)

    def test_primary_unavailable_uses_reserve_without_false_consensus(self):
        def response(source, ip, timeout):
            return (None, "unavailable", 0) if source == "ip2location" else self.response(source, ip, timeout)
        with mock.patch.object(geoip, "_request", side_effect=response) as request:
            result = geoip.lookup(IP, consensus=True)
            self.assertEqual((result["cc"], result["alt"], result["status"]), ("cn", None, "single-source"))
            self.assertEqual(result["intel"]["src"], "ipwho.is")
            self.assertEqual(probe.geo_country(IP), "cn")
            self.assertEqual(request.call_count, 2)

    def test_disagreement_preserved_including_hard_blocked_secondary(self):
        def response(source, ip, timeout):
            data, status, retry = self.response(source, ip, timeout)
            if source == "ipwho.is": data["cc"] = "ru"
            return data, status, retry
        with mock.patch.object(geoip, "_request", side_effect=response):
            result = geoip.lookup(IP, consensus=True)
        self.assertFalse(result["agree"])
        self.assertEqual(result["status"], "conflict")
        self.assertIn(result["alt"], probe.HARD_BLOCK_CC)

    def test_six_hour_expiry_refetches_both_country_and_city(self):
        with mock.patch.object(geoip, "_request", side_effect=self.response): geoip.lookup(IP)
        self.expire()
        changed = dict(geoip.parse("ip2location", PRIMARY, IP), cc="jp", city="Tokyo")
        with mock.patch.object(geoip, "_request", return_value=(changed, "ok", 0)) as request:
            self.assertEqual(probe.geo_country(IP), "jp")
            self.assertEqual(probe.ip_intel(IP)["city"], "Tokyo")
            self.assertEqual(request.call_count, 1)

    def test_two_failures_have_negative_cache_and_source_cooldown(self):
        with mock.patch.object(geoip, "_request", return_value=(None, "unavailable", 0)) as request:
            for ip in (IP, IP, "5.6.7.8"):
                self.assertIsNone(probe.geo_country(ip))
            self.assertEqual(request.call_count, 2)

    def test_retry_after_applies_to_other_ips_and_force_refresh(self):
        with mock.patch.object(geoip, "_request", return_value=(None, "rate-limited", 3600)) as request:
            geoip.lookup(IP)
            self.expire()  # clear answer age only; restore source rate limit below
            with sqlite3.connect(self.cache) as conn:
                conn.execute("UPDATE service SET retry_at=?", (time.time() + 3600,))
            geoip.lookup("5.6.7.8", consensus=True, refresh=True)
            self.assertEqual(request.call_count, 2)

    def test_daily_budget_is_shared_across_ips_and_reserved_before_network(self):
        with mock.patch.object(geoip, "DAILY_BUDGET", 2), mock.patch.object(geoip, "_request", side_effect=self.response) as request:
            for ip in (IP, "5.6.7.8", "9.8.7.6"):
                geoip.lookup(ip, consensus=True)
            self.assertEqual(request.call_count, 4)
            with sqlite3.connect(self.cache) as conn:
                self.assertEqual(conn.execute("SELECT count(*) FROM request").fetchone()[0], 4)

    def test_concurrent_lookups_coalesce(self):
        with geoip._database(): pass
        def slow(*args): time.sleep(0.1); return self.response(*args)
        with mock.patch.object(geoip, "_request", side_effect=slow) as request:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
                results = list(workers.map(lambda _: probe.ip_intel(IP), range(8)))
            self.assertEqual(request.call_count, 1)
            self.assertTrue(all(r and r["city"] == "Beijing" for r in results))

    def test_answer_committed_while_waiting_for_lock_does_not_refetch(self):
        source = geoip.SOURCES[0]
        clock = [1000.0]
        waiting = threading.Event()

        class ObservedConnection(sqlite3.Connection):
            def execute(self, sql, *args):
                if sql == "BEGIN IMMEDIATE":
                    waiting.set()
                return super().execute(sql, *args)

        @contextlib.contextmanager
        def reader_database():
            conn = sqlite3.connect(self.cache, timeout=5, factory=ObservedConnection)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()

        with geoip._database() as writer:
            writer.execute("BEGIN IMMEDIATE")
            data = geoip.parse(source, PRIMARY, IP)
            # A competing lookup finishes after the reader starts waiting.
            writer.execute("INSERT INTO answer (source,ip,body,checked,expires) VALUES (?,?,?,?,?)",
                           (source, IP, json.dumps(data), 1001.0, 1001.0 + geoip.TTL))
            with mock.patch.object(geoip, "_database", side_effect=reader_database), \
                 mock.patch.object(geoip.time, "time", side_effect=lambda: clock[0]), \
                 mock.patch.object(geoip, "_request", side_effect=self.response) as request:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as workers:
                    result = workers.submit(geoip._source, source, IP, time.monotonic() + 10)
                    try:
                        self.assertTrue(waiting.wait(5), "reader must reach the held write lock")
                        clock[0] = 1001.0
                        writer.commit()
                    finally:
                        writer.rollback()
                    self.assertEqual(result.result(timeout=5)["city"], "Beijing")
                request.assert_not_called()
            self.assertEqual(writer.execute("SELECT count(*) FROM request").fetchone()[0], 0)

    def test_separate_process_reads_persisted_cache_without_http(self):
        with mock.patch.object(geoip, "_request", side_effect=self.response): geoip.lookup(IP)
        code = "import geoip; geoip.CACHE_PATH=%r; geoip._request=lambda *a: (_ for _ in ()).throw(AssertionError('HTTP')); print(geoip.lookup(%r)['cc'])" % (str(self.cache), IP)
        result = subprocess.run([sys.executable, "-c", code], cwd=PANEL_DIR, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "cn")

    def test_refresh_rechecks_blocked_country_instead_of_double_counting_cache(self):
        with mock.patch.object(geoip, "_request", side_effect=self.response) as request:
            geoip.lookup(IP, consensus=True)
            geoip.lookup(IP, consensus=True, refresh=True)
            self.assertEqual(request.call_count, 4)

    def test_private_invalid_ips_and_unwritable_cache_never_make_http_calls(self):
        with mock.patch.object(geoip, "_request") as request:
            for ip in (None, "", "127.0.0.1", "10.0.0.2", "192.0.2.1", "https://example.com"):
                self.assertEqual(geoip.lookup(ip)["status"], "unavailable")
            self.cache.write_text("broken database")
            self.assertIsNone(probe.geo_country(IP))
            request.assert_not_called()

    def test_dead_worker_lease_can_be_retried(self):
        action, _ = geoip._claim("ip2location", IP)
        self.assertEqual(action, "fetch")
        with sqlite3.connect(self.cache) as conn: conn.execute("UPDATE answer SET lease_until=0")
        with mock.patch.object(geoip, "_request", side_effect=self.response):
            self.assertEqual(probe.geo_country(IP), "cn")

    def test_geo_failure_does_not_fail_working_vpn_verification(self):
        with mock.patch.object(geoip, "_request", return_value=(None, "unavailable", 0)), \
             mock.patch.object(apply, "run_cmd", side_effect=[(0, IP), (0, "200")]):
            result = apply.verify_egress()
        self.assertTrue(result["ok"])
        self.assertIsNone(result["exit_cc"])
        self.assertEqual(result["why_kind"], "")

    def test_quota_cooldown_or_failed_recheck_cannot_cancel_known_block(self):
        for failure in ("budget", "rate-limited", "unavailable"):
            with self.subTest(failure=failure):
                self.cache.unlink(missing_ok=True)
                def blocked(source, ip, timeout):
                    data, status, retry = self.response(source, ip, timeout)
                    data["cc"] = "ru"
                    return data, status, retry
                with mock.patch.object(geoip, "_request", side_effect=blocked):
                    geoip.lookup(IP, consensus=True)
                with mock.patch.object(geoip, "DAILY_BUDGET", 1 if failure == "budget" else 950), \
                     mock.patch.object(geoip, "_request", return_value=(None, failure, 3600)), \
                     mock.patch.object(apply, "run_cmd", return_value=(0, IP)):
                    for _ in range(2):
                        result = apply.verify_egress()
                        self.assertFalse(result["ok"])
                        self.assertEqual(result["why_kind"], "blocked-cc")
                        self.assertEqual(probe.geo_country(IP), "ru")

    def test_read_only_snapshot_updates_legacy_country_without_http(self):
        with mock.patch.object(geoip, "_request", side_effect=self.response):
            geoip.lookup(IP, consensus=True)
        with mock.patch.object(geoip, "_request") as request:
            row = {"exit_ip":IP, "exit_cc":"fi", "exit_cc_alt":"fi", "geo_agree":True}
            result = probe.cached_geo_row(row)
            self.assertEqual((result["exit_cc"], result["exit_cc_alt"]), ("cn", "cn"))
            self.assertEqual(row["exit_cc"], "fi", "reading metadata must not mutate pool input")
            request.assert_not_called()

    def test_one_available_source_does_not_hide_historic_block(self):
        with mock.patch.object(geoip, "_request", side_effect=self.response): geoip.lookup(IP)
        for field in ("exit_cc", "exit_cc_alt"):
            result = probe.cached_geo_row({"exit_ip":IP, field:"ru"})
            self.assertEqual(result["exit_cc_alt"], "ru")
            self.assertFalse(result["geo_agree"])


class TestGeoTransport(unittest.TestCase):
    def test_https_direct_bounded_request_and_no_redirects(self):
        raw = b"HTTP/2 200\r\ncontent-type: application/json\r\n\r\n" + json.dumps(PRIMARY).encode()
        with mock.patch.object(geoip.subprocess, "run", return_value=mock.Mock(returncode=0, stdout=raw)) as run:
            data, status, _ = geoip._request("ip2location", IP, 6)
        self.assertEqual(status, "ok"); self.assertEqual(data["cc"], "cn")
        args = run.call_args.args[0]
        self.assertIn("--noproxy", args); self.assertIn("--max-time", args)
        self.assertNotIn("-L", args)
        self.assertTrue(args[-1].startswith("https://"))

    def test_rate_limit_invalid_json_html_redirect_and_mismatched_ip(self):
        cases = [(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 7200\r\n\r\n{}", "rate-limited", 7200),
                 (b"HTTP/1.1 302 Found\r\nLocation: http://other/\r\n\r\n", "unavailable", 0),
                 (b"HTTP/1.1 200 OK\r\n\r\n<html>", "unavailable", 0),
                 (b"HTTP/1.1 200 OK\r\n\r\n{}", "invalid-response", 0)]
        for raw, status, retry in cases:
            with mock.patch.object(geoip.subprocess, "run", return_value=mock.Mock(returncode=0, stdout=raw)):
                self.assertEqual(geoip._request("ip2location", IP, 6), (None, status, retry))


@unittest.skipUnless(shutil.which("node"), "Node.js is required for rendered panel checks")
class TestGeoUI(unittest.TestCase):
    def test_country_city_refresh_attribution_and_contour_isolation(self):
        from webpanel import views
        with tempfile.TemporaryDirectory() as tmp:
            page = Path(tmp) / "dashboard.html"
            page.write_text(views.dashboard_page("test", "synthetic-csrf"))
            result = subprocess.run(["node", str(Path(__file__).with_name("geoip_ui_regression.js")), str(page)],
                                    capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
