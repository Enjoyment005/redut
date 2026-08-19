# -*- coding: utf-8 -*-
"""Паспорт IP для карты выхода (probe.ip_intel + GET /api/ipinfo, 19.08).

Сеть в тестах не трогаем — _http_json подменяется. Проверяем разбор обеих баз
(ip-api.com и фолбэк ipinfo.io), порядок фолбэка, кэш в setting (повторное
открытие дашборда в сеть не ходит), протухание кэша и то, что эндпоинт отвечает
только про ТЕКУЩИЙ egress (общим geoip-сервисом панель не становится).
"""
import json
import unittest
from unittest import mock

from _ctx import PANEL_DIR  # noqa: F401 — панель в sys.path
import probe
import states
from test_panel_api import _AppHarness
import server


IPAPI_OK = {
    "status": "success", "countryCode": "LV", "regionName": "Riga", "city": "Riga",
    "timezone": "Europe/Riga", "isp": "DataClub S.A.", "org": "MivoCloud SRL",
    "as": "AS52048 DataClub S.A.", "asname": "DATACLUB", "reverse": "host.dataclub.eu",
    "mobile": False, "proxy": True, "hosting": True, "lat": 56.95, "lon": 24.1,
}

IPINFO_OK = {
    "ip": "1.2.3.4", "hostname": "srv.example.net", "city": "Helsinki",
    "region": "Uusimaa", "country": "FI", "loc": "60.1699,24.9384",
    "org": "AS24940 Hetzner Online GmbH", "timezone": "Europe/Helsinki",
}

IPAPI_OK_PARSED = probe._intel_from_ipapi(IPAPI_OK)


class TestParsers(unittest.TestCase):
    def test_ipapi_success(self):
        d = probe._intel_from_ipapi(IPAPI_OK)
        self.assertEqual(d["cc"], "lv")
        self.assertEqual(d["asn"], "AS52048")
        self.assertEqual(d["asname"], "DATACLUB")
        self.assertEqual(d["ptr"], "host.dataclub.eu")
        self.assertIs(d["hosting"], True)
        self.assertIs(d["proxy"], True)
        self.assertIs(d["mobile"], False)
        self.assertEqual(d["city"], "Riga")
        self.assertEqual(d["src"], "ip-api")

    def test_ipapi_fail_status_is_none(self):
        self.assertIsNone(probe._intel_from_ipapi({"status": "fail", "message": "private range"}))
        self.assertIsNone(probe._intel_from_ipapi(None))
        self.assertIsNone(probe._intel_from_ipapi("мусор"))

    def test_ipapi_asname_falls_back_to_as_tail(self):
        d = probe._intel_from_ipapi(dict(IPAPI_OK, asname=""))
        self.assertEqual(d["asname"], "DataClub S.A.")

    def test_ipinfo_success(self):
        d = probe._intel_from_ipinfo(IPINFO_OK)
        self.assertEqual(d["cc"], "fi")
        self.assertEqual(d["asn"], "AS24940")
        self.assertEqual(d["asname"], "Hetzner Online GmbH")
        self.assertEqual(d["ptr"], "srv.example.net")
        self.assertEqual((d["lat"], d["lon"]), (60.1699, 24.9384))
        # бесплатный ipinfo не отдаёт эти флаги — None, а не False (фронт различает)
        self.assertIsNone(d["hosting"])
        self.assertEqual(d["src"], "ipinfo")

    def test_ipinfo_empty_is_none(self):
        self.assertIsNone(probe._intel_from_ipinfo({}))
        self.assertIsNone(probe._intel_from_ipinfo(None))


class TestIpIntelFallback(unittest.TestCase):
    def test_primary_wins(self):
        with mock.patch.object(probe, "_http_json", return_value=IPAPI_OK) as m:
            d = probe.ip_intel("1.2.3.4")
        self.assertEqual(d["src"], "ip-api")
        self.assertEqual(m.call_count, 1)

    def test_falls_back_to_ipinfo(self):
        def ask(url, timeout=probe.GEO_TIMEOUT):
            return None if "ip-api" in url else IPINFO_OK
        with mock.patch.object(probe, "_http_json", side_effect=ask):
            d = probe.ip_intel("1.2.3.4")
        self.assertEqual(d["src"], "ipinfo")

    def test_both_silent_is_none(self):
        with mock.patch.object(probe, "_http_json", return_value=None):
            self.assertIsNone(probe.ip_intel("1.2.3.4"))

    def test_empty_ip_is_none_without_network(self):
        with mock.patch.object(probe, "_http_json") as m:
            self.assertIsNone(probe.ip_intel(""))
        m.assert_not_called()


class TestIpinfoEndpoint(_AppHarness):
    def _egress(self, ip):
        self.app.pool.set_egress({"egress_ip": ip, "exit_cc": "lv", "ok": True,
                                  "tg_code": "200", "why": ""})

    def call(self):
        return server.Handler._ipinfo(None)

    def test_no_egress_yet(self):
        r = self.call()
        self.assertFalse(r["ok"])
        self.assertIn("не проверялся", r["why"])

    def test_fetches_and_caches(self):
        self._egress("1.2.3.4")
        with mock.patch.object(server.probe_mod, "ip_intel",
                               return_value=dict(IPAPI_OK_PARSED)) as m:
            r = self.call()
        self.assertTrue(r["ok"])
        self.assertEqual(r["ip"], "1.2.3.4")
        self.assertEqual(r["intel"]["asn"], "AS52048")
        m.assert_called_once_with("1.2.3.4")
        # второй вызов — из кэша, сеть не дёргается
        with mock.patch.object(server.probe_mod, "ip_intel") as m2:
            r2 = self.call()
        self.assertTrue(r2["ok"])
        self.assertEqual(r2["intel"]["asn"], "AS52048")
        m2.assert_not_called()

    def test_failure_is_not_cached(self):
        self._egress("1.2.3.4")
        with mock.patch.object(server.probe_mod, "ip_intel", return_value=None):
            r = self.call()
        self.assertFalse(r["ok"])
        self.assertIsNone(self.app.pool.get_setting("ipintel:1.2.3.4"))

    def test_ip_change_refetches_and_prunes_old_key(self):
        self._egress("1.2.3.4")
        with mock.patch.object(server.probe_mod, "ip_intel",
                               return_value=dict(IPAPI_OK_PARSED)):
            self.call()
        self._egress("5.6.7.8")
        with mock.patch.object(server.probe_mod, "ip_intel",
                               return_value=dict(IPAPI_OK_PARSED, asn="AS1")) as m:
            r = self.call()
        m.assert_called_once_with("5.6.7.8")
        self.assertEqual(r["intel"]["asn"], "AS1")
        # старый ключ подчищен — setting не пухнет от истории адресов
        self.assertIsNone(self.app.pool.get_setting("ipintel:1.2.3.4"))
        self.assertIsNotNone(self.app.pool.get_setting("ipintel:5.6.7.8"))

    def test_stale_cache_refetches(self):
        self._egress("1.2.3.4")
        old = {"at": "2020-01-01 00:00:00", "intel": {"asn": "ASOLD"}}
        self.app.pool.set_setting("ipintel:1.2.3.4", json.dumps(old))
        self.assertGreater(states.age_seconds(old["at"]), probe.INTEL_TTL_S)
        with mock.patch.object(server.probe_mod, "ip_intel",
                               return_value=dict(IPAPI_OK_PARSED)) as m:
            r = self.call()
        m.assert_called_once()
        self.assertEqual(r["intel"]["asn"], "AS52048")


if __name__ == "__main__":
    unittest.main()
