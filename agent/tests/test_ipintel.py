# -*- coding: utf-8 -*-
"""Паспорт IP для карты выхода (probe.ip_intel + GET /api/ipinfo, 19.08).

Сеть в тестах не трогаем. Проверяем кэш риск-разведки в setting,
обновление геолокации независимо от него и то, что эндпоинт отвечает
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


from test_geoip import PRIMARY, SECONDARY
import geoip

IP2LOCATION_OK = dict(PRIMARY, country_code="LV", city_name="Riga", region_name="Riga", asn="52048", **{"as": "DataClub S.A."})
IP2LOCATION_PARSED = geoip.parse("ip2location", IP2LOCATION_OK, "1.2.3.4")


FULL_OK = dict(IP2LOCATION_PARSED, v=probe.INTEL_VERSION, quality=79,
               dnsbl={"checked": 3, "listed": []})


class TestIpinfoEndpoint(_AppHarness):
    def setUp(self):
        super().setUp()
        patches = [mock.patch.object(geoip, "CACHE_PATH", str(__import__('pathlib').Path(self.tmp.name)/'geo.sqlite3')),
                   mock.patch.object(geoip, "_request", return_value=(dict(IP2LOCATION_PARSED), "ok", 0))]
        for patch in patches:
            patch.start(); self.addCleanup(patch.stop)

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


    def test_weekly_risk_cache_never_overrides_fresh_geography(self):
        self._egress("1.2.3.4")
        self.app.pool.set_setting("ipintel:1.2.3.4", json.dumps(
            {"at": pool_now(), "intel": dict(FULL_OK, cc="fi", city="Helsinki", pc_risk=13)}))
        with mock.patch.object(probe, "ip_intel", return_value={"cc":"cn", "city":"Beijing", "src":"ip2location"}), \
             mock.patch.object(probe, "ip_intel_full") as risk:
            result = self.call()
        self.assertEqual((result["intel"]["cc"], result["intel"]["city"]), ("cn", "Beijing"))
        self.assertEqual(result["intel"]["pc_risk"], 13)
        risk.assert_not_called()

    def test_status_map_and_pool_use_same_fresh_country_as_passport(self):
        self._egress("1.2.3.4")
        uid = self.put_proxy("geo-beijing", country="cn", exit_cc="fi", exit_cc_alt="fi")
        self.app.pool.conn.execute("UPDATE proxy SET exit_ip=? WHERE uid=?", ("1.2.3.4", uid))
        self.app.pool.conn.commit()
        data = geoip.parse("ip2location", PRIMARY, "1.2.3.4")
        with mock.patch.object(geoip, "_request", return_value=(data, "ok", 0)):
            self.assertEqual(probe.ip_intel("1.2.3.4")["city"], "Beijing")
        with mock.patch.object(geoip, "_request") as network:
            status = server.Handler._status(None)
            row = self.pool_row(uid)
        self.assertEqual(status["egress_cc"], "cn")
        self.assertIn("cn", status["pool_cc"])
        self.assertNotIn("fi", status["pool_cc"])
        self.assertEqual(row["exit_cc"], "cn")
        self.assertIsNone(row["exit_cc_alt"])
        network.assert_not_called()

    def test_unavailable_geography_clears_old_city_but_preserves_risk(self):
        self._egress("1.2.3.4")
        self.app.pool.set_setting("ipintel:1.2.3.4", json.dumps(
            {"at": pool_now(), "intel": dict(FULL_OK, cc="fi", city="Helsinki", pc_risk=13)}))
        with mock.patch.object(probe, "ip_intel", return_value=None):
            result = self.call()
        self.assertEqual(result["intel"]["geo_status"], "unavailable")
        self.assertNotIn("city", result["intel"])
        self.assertNotIn("cc", result["intel"])
        self.assertEqual(result["intel"]["pc_risk"], 13)


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
    def setUp(self):
        patch = mock.patch.object(probe, "ip_intel", return_value=dict(IP2LOCATION_PARSED))
        self.base = patch.start(); self.addCleanup(patch.stop)

    def _http(self, pc=PROXYCHECK_OK):
        def ask(url, timeout=probe.GEO_TIMEOUT):
            if "proxycheck" in url:
                return pc
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
        self.assertEqual(d["asn"], "AS52048")         # паспорт IP2Location
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

    def test_geo_silent_risk_sources_do_not_invent_a_country(self):
        self.base.return_value = None
        with mock.patch.object(probe, "_http_json",
                               side_effect=self._http()), \
             mock.patch.object(probe, "dnsbl_check",
                               return_value={"checked": 0, "listed": []}):
            d = probe.ip_intel_full("1.2.3.4")
        self.assertNotIn("cc", d)
        self.assertNotIn("city", d)
        self.assertEqual(d["geo_status"], "unavailable")
        self.assertEqual(d["pc_risk"], 13)

    def test_everything_silent_is_none(self):
        self.base.return_value = None
        with mock.patch.object(probe, "_http_json", return_value=None):
            self.assertIsNone(probe.ip_intel_full("1.2.3.4"))


if __name__ == "__main__":
    unittest.main()
