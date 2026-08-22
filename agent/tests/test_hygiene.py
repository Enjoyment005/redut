# -*- coding: utf-8 -*-
"""hygiene.py — статистика белого списка РФ и очистки следов для карточки статуса.
Всё из файлов, без subprocess; нет файла -> блок выключен, карточка строку не покажет."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "webpanel"))
import hygiene  # noqa: E402


class TestWhitelist(unittest.TestCase):
    def test_off_when_no_dnsmasq(self):
        self.assertEqual(hygiene.whitelist_stat(False), {"on": False})

    def test_counts_domains_and_nets(self):
        with tempfile.TemporaryDirectory() as d:
            conf, net = os.path.join(d, "wl.conf"), os.path.join(d, "net.ipset")
            with open(conf, "w", encoding="utf-8") as f:
                f.write("# заголовок\nipset=/pochta.ru/ru_whitelist\nipset=/gosuslugi.ru/ru_whitelist\n")
            with open(net, "w", encoding="utf-8") as f:
                f.write("create ru_whitelist_net hash:net\n"
                        "add ru_whitelist_net 1.2.3.0/24\nadd ru_whitelist_net 5.6.0.0/16\n"
                        "add ru_whitelist_net 7.8.9.0/24\n")
            st = hygiene.whitelist_stat(True, conf=conf, net_file=net)
            self.assertTrue(st["on"])
            self.assertEqual(st["domains"], 2)         # только строки ipset=/
            self.assertEqual(st["nets"], 3)            # только строки add
            self.assertIsNotNone(st["updated_at"])

    def test_missing_files_zero(self):
        st = hygiene.whitelist_stat(True, conf="/no/such/conf", net_file="/no/such/net")
        self.assertEqual((st["on"], st["domains"], st["nets"]), (True, 0, 0))
        self.assertIsNone(st["updated_at"])


class TestCleanup(unittest.TestCase):
    def test_off_when_no_file(self):
        self.assertEqual(hygiene.cleanup_stat("/no/such/cleanup.json"), {"on": False})

    def test_reads_stat(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"last_at": 1000, "freed_24h": 25165824, "runs_24h": 8, "runs": [[1000, 1]]}, f)
            self.assertEqual(hygiene.cleanup_stat(p, now=1500),
                             {"on": True, "last_at": 1000, "freed_24h": 1, "runs_24h": 1,
                              "measured_runs_24h": 0, "complete_24h": False})

    def test_recomputes_sliding_24h_from_all_runs(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.json")
            now = 200000
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"last_at": now - 10, "freed_24h": 999999, "runs_24h": 99,
                           "runs": [
                               [now - 86401, 100],                 # уже выпал
                               [now - 86399, 2],                   # старый формат
                               {"at": now - 3600, "freed": 3, "journal": 3},  # новый формат
                               {"at": now - 10, "freed": 5, "journal": 5},
                           ]}, f)
            self.assertEqual(hygiene.cleanup_stat(p, now=now),
                             {"on": True, "last_at": now - 10,
                              "freed_24h": 10, "runs_24h": 3,
                              "measured_runs_24h": 2, "complete_24h": False})

    def test_complete_when_every_run_has_precise_components(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"last_at": 2000, "runs": [
                    {"at": 1000, "freed": 5, "journal": 5, "files": 0, "tmp": 0},
                    {"at": 2000, "freed": 7, "journal": 6, "files": 1, "tmp": 0},
                ]}, f)
            self.assertEqual(hygiene.cleanup_stat(p, now=2000),
                             {"on": True, "last_at": 2000, "freed_24h": 12,
                              "runs_24h": 2, "measured_runs_24h": 2,
                              "complete_24h": True})

    def test_legacy_aggregate_without_runs_is_supported(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"last_at": 1000, "freed_24h": 25, "runs_24h": 4}, f)
            self.assertEqual(hygiene.cleanup_stat(p, now=2000),
                             {"on": True, "last_at": 1000, "freed_24h": 25, "runs_24h": 4})

    def test_bad_json_off(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.json")
            with open(p, "w", encoding="utf-8") as f:
                f.write("{битый json")
            self.assertEqual(hygiene.cleanup_stat(p), {"on": False})

    def test_non_dict_off(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump([1, 2, 3], f)
            self.assertEqual(hygiene.cleanup_stat(p), {"on": False})


class TestSnapshot(unittest.TestCase):
    def test_off_node(self):
        snap = hygiene.snapshot({"has_dnsmasq": False}, conf="/no", net_file="/no", stat="/no")
        self.assertEqual(snap["whitelist"], {"on": False})
        self.assertEqual(snap["cleanup"], {"on": False})

    def test_none_cfg_safe(self):
        snap = hygiene.snapshot(None, conf="/no", net_file="/no", stat="/no")
        self.assertFalse(snap["whitelist"]["on"])
        self.assertFalse(snap["cleanup"]["on"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
