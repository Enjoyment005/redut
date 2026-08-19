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


FULL_OK = dict(IPAPI_OK_PARSED, v=probe.INTEL_VERSION, quality=79,
               dnsbl={"checked": 3, "listed": []})


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
        with mock.patch.object(server.probe_mod, "ip_intel_full",
                               return_value=dict(FULL_OK)) as m:
            r = self.call()
        self.assertTrue(r["ok"])
        self.assertEqual(r["ip"], "1.2.3.4")
        self.assertEqual(r["intel"]["asn"], "AS52048")
        self.assertEqual(m.call_args[0][0], "1.2.3.4")
        # ключи риск-источников идут из secrets.ipintel (в харнессе их нет — {})
        self.assertEqual(m.call_args[1]["keys"], {})
        # второй вызов — из кэша, сеть не дёргается
        with mock.patch.object(server.probe_mod, "ip_intel_full") as m2:
            r2 = self.call()
        self.assertTrue(r2["ok"])
        self.assertEqual(r2["intel"]["asn"], "AS52048")
        m2.assert_not_called()

    def test_failure_is_not_cached(self):
        self._egress("1.2.3.4")
        with mock.patch.object(server.probe_mod, "ip_intel_full", return_value=None):
            r = self.call()
        self.assertFalse(r["ok"])
        self.assertIsNone(self.app.pool.get_setting("ipintel:1.2.3.4"))

    def test_ip_change_refetches_and_prunes_old_key(self):
        self._egress("1.2.3.4")
        with mock.patch.object(server.probe_mod, "ip_intel_full",
                               return_value=dict(FULL_OK)):
            self.call()
        self._egress("5.6.7.8")
        with mock.patch.object(server.probe_mod, "ip_intel_full",
                               return_value=dict(FULL_OK, asn="AS1")) as m:
            r = self.call()
        m.assert_called_once()
        self.assertEqual(m.call_args[0][0], "5.6.7.8")
        self.assertEqual(r["intel"]["asn"], "AS1")
        # старый ключ подчищен — setting не пухнет от истории адресов
        self.assertIsNone(self.app.pool.get_setting("ipintel:1.2.3.4"))
        self.assertIsNotNone(self.app.pool.get_setting("ipintel:5.6.7.8"))

    def test_stale_cache_refetches(self):
        self._egress("1.2.3.4")
        old = {"at": "2020-01-01 00:00:00", "intel": dict(FULL_OK, asn="ASOLD")}
        self.app.pool.set_setting("ipintel:1.2.3.4", json.dumps(old))
        self.assertGreater(states.age_seconds(old["at"]), probe.INTEL_TTL_S)
        with mock.patch.object(server.probe_mod, "ip_intel_full",
                               return_value=dict(FULL_OK)) as m:
            r = self.call()
        m.assert_called_once()
        self.assertEqual(r["intel"]["asn"], "AS52048")

    def test_old_cache_format_refetches(self):
        # свежий по возрасту кэш СТАРОГО формата (без v) — перечитывается:
        # иначе после обновления панели риск-строки не появятся неделю
        self._egress("1.2.3.4")
        self.app.pool.set_setting("ipintel:1.2.3.4", json.dumps(
            {"at": pool_now(), "intel": {"asn": "ASOLD"}}))
        with mock.patch.object(server.probe_mod, "ip_intel_full",
                               return_value=dict(FULL_OK)) as m:
            r = self.call()
        m.assert_called_once()
        self.assertEqual(r["intel"]["asn"], "AS52048")


def pool_now():
    import pool as pool_mod
    return pool_mod.now_iso()


# ── риск-разведка (19.08): парсеры источников, DNSBL, свёртка качества ──
PROXYCHECK_OK = {"status": "ok", "1.2.3.4": {
    "asn": "AS52048", "provider": "DataClub S.A.", "country": "Latvia",
    "isocode": "LV", "proxy": "yes", "type": "VPN", "risk": 13}}

ABUSE_OK = {"data": {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 7,
                     "totalReports": 3, "lastReportedAt": "2026-08-01T00:00:00+00:00"}}

IPQS_OK = {"success": True, "fraud_score": 45, "vpn": True, "tor": False,
           "proxy": True, "connection_type": "Data Center"}


class TestRiskParsers(unittest.TestCase):
    def test_proxycheck_ok(self):
        d = probe._intel_from_proxycheck(PROXYCHECK_OK, "1.2.3.4")
        self.assertIs(d["pc_proxy"], True)
        self.assertEqual(d["pc_type"], "VPN")
        self.assertEqual(d["pc_risk"], 13)
        self.assertEqual(d["_pc_cc"], "lv")

    def test_proxycheck_denied_or_missing_ip(self):
        self.assertIsNone(probe._intel_from_proxycheck(
            {"status": "denied", "message": "limit"}, "1.2.3.4"))
        self.assertIsNone(probe._intel_from_proxycheck({"status": "ok"}, "1.2.3.4"))
        self.assertIsNone(probe._intel_from_proxycheck(None, "1.2.3.4"))

    def test_abuseipdb_ok_and_bad(self):
        d = probe._intel_from_abuseipdb(ABUSE_OK)
        self.assertEqual(d["abuse_score"], 7)
        self.assertEqual(d["abuse_reports"], 3)
        self.assertIsNone(probe._intel_from_abuseipdb({"errors": [{}]}))
        self.assertIsNone(probe._intel_from_abuseipdb(None))

    def test_ipqs_ok_and_bad(self):
        d = probe._intel_from_ipqs(IPQS_OK)
        self.assertEqual(d["ipqs_fraud"], 45)
        self.assertIs(d["ipqs_vpn"], True)
        self.assertIs(d["ipqs_tor"], False)
        self.assertIsNone(probe._intel_from_ipqs({"success": False, "message": "no credits"}))


class TestDnsbl(unittest.TestCase):
    def _resolver(self, listed_zone):
        def r(name):
            if name.endswith(listed_zone):
                return "127.0.0.2"
            raise OSError("NXDOMAIN")
        return r

    def test_listed_and_clean(self):
        d = probe.dnsbl_check("1.2.3.4", resolver=self._resolver("zen.spamhaus.org"))
        self.assertEqual(d["checked"], 3)
        self.assertEqual(d["listed"], ["zen.spamhaus.org"])
        d2 = probe.dnsbl_check("1.2.3.4", resolver=self._resolver("нет-такой-зоны"))
        self.assertEqual(d2["listed"], [])

    def test_reversed_octets(self):
        seen = []
        def r(name):
            seen.append(name)
            raise OSError
        probe.dnsbl_check("1.2.3.4", zones=("zen.spamhaus.org",), resolver=r)
        self.assertEqual(seen, ["4.3.2.1.zen.spamhaus.org"])

    def test_non_ipv4_not_checked(self):
        self.assertEqual(probe.dnsbl_check("2a00::1")["checked"], 0)
        self.assertEqual(probe.dnsbl_check("мусор")["checked"], 0)


class TestQuality(unittest.TestCase):
    def test_unknown_everything_is_100(self):
        self.assertEqual(probe.ip_quality({}), 100)

    def test_typical_datacenter_proxy(self):
        # обычный наш exit: датацентр + светится как прокси + небольшой риск
        d = {"hosting": True, "proxy": True, "pc_proxy": True, "pc_risk": 13,
             "dnsbl": {"checked": 3, "listed": []}}
        self.assertEqual(probe.ip_quality(d), 79)   # 100 − 4.55 − 10 − 6

    def test_tor_is_heavily_penalized(self):
        self.assertLessEqual(probe.ip_quality({"ipqs_tor": True}), 65)

    def test_blacklists_subtract(self):
        clean = probe.ip_quality({"dnsbl": {"checked": 3, "listed": []}})
        dirty = probe.ip_quality({"dnsbl": {"checked": 3, "listed": ["zen.spamhaus.org"]}})
        self.assertEqual(clean - dirty, 14)

    def test_never_below_zero(self):
        d = {"pc_risk": 100, "ipqs_fraud": 100, "abuse_score": 100, "ipqs_tor": True,
             "hosting": True, "proxy": True, "ping_ms": 900,
             "dnsbl": {"checked": 3, "listed": ["a", "b", "c"]}}
        self.assertEqual(probe.ip_quality(d), 0)


class TestIpIntelFull(unittest.TestCase):
    def _http(self, ipapi=IPAPI_OK, pc=PROXYCHECK_OK):
        def ask(url, timeout=probe.GEO_TIMEOUT):
            if "ip-api" in url:
                return ipapi
            if "proxycheck" in url:
                return pc
            if "ipinfo" in url:
                return None
            if "ipqualityscore" in url:
                return IPQS_OK
            return None
        return ask

    def test_merges_all_sources_without_keys(self):
        with mock.patch.object(probe, "_http_json", side_effect=self._http()), \
             mock.patch.object(probe, "_http_json_hdr") as hdr, \
             mock.patch.object(probe, "dnsbl_check",
                               return_value={"checked": 3, "listed": []}):
            d = probe.ip_intel_full("1.2.3.4", ping_ms=142)
        hdr.assert_not_called()                       # AbuseIPDB без ключа не дёргается
        self.assertEqual(d["asn"], "AS52048")         # паспорт ip-api
        self.assertEqual(d["pc_risk"], 13)            # proxycheck
        self.assertNotIn("ipqs_fraud", d)             # IPQS без ключа не дёргается
        self.assertEqual(d["ping_ms"], 142)
        self.assertEqual(d["v"], probe.INTEL_VERSION)
        self.assertIn("quality", d)
        self.assertNotIn("_pc_cc", d)                 # служебные поля не утекают

    def test_keys_enable_abuse_and_ipqs(self):
        with mock.patch.object(probe, "_http_json", side_effect=self._http()), \
             mock.patch.object(probe, "_http_json_hdr", return_value=ABUSE_OK) as hdr, \
             mock.patch.object(probe, "dnsbl_check",
                               return_value={"checked": 3, "listed": []}):
            d = probe.ip_intel_full("1.2.3.4",
                                    keys={"abuseipdb": "K1", "ipqs": "K2"})
        hdr.assert_called_once()
        self.assertEqual(hdr.call_args[0][1]["Key"], "K1")
        self.assertEqual(d["abuse_score"], 7)
        self.assertEqual(d["ipqs_fraud"], 45)

    def test_geo_silent_but_proxycheck_fills_gaps(self):
        with mock.patch.object(probe, "_http_json",
                               side_effect=self._http(ipapi=None)), \
             mock.patch.object(probe, "dnsbl_check",
                               return_value={"checked": 0, "listed": []}):
            d = probe.ip_intel_full("1.2.3.4")
        self.assertEqual(d["cc"], "lv")               # дыры паспорта закрыл proxycheck
        self.assertEqual(d["asn"], "AS52048")
        self.assertEqual(d["org"], "DataClub S.A.")

    def test_everything_silent_is_none(self):
        with mock.patch.object(probe, "_http_json", return_value=None):
            self.assertIsNone(probe.ip_intel_full("1.2.3.4"))


if __name__ == "__main__":
    unittest.main()
