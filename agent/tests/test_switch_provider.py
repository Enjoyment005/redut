# -*- coding: utf-8 -*-
"""П7-2 (1.6.0): плановое переключение боевого канала с провайдера без ключа.

Живую часть (probe -> apply -> verify -> автооткат) гоняет приёмка на сервере;
здесь фиксируем ЧИСТЫЕ ветки решения, из-за которых уже случались беды:
  * «боевой не у этого провайдера» — ничего не трогаем (ok, switched=False);
  * пауза FROZEN уважается: канал не рвём, событие в журнал, повтор — потом;
  * на dev-машине (не Linux) переключение не запускается вовсе.
"""
import json
import os
import tempfile
import unittest

import _ctx      # noqa: F401  (добавляет panel/ в sys.path)
import pool as pool_mod
import states


class SilentAlerter:
    """Письма в тестах копим, не шлём."""

    def __init__(self):
        self.sent = []

    def __getattr__(self, kind):
        def fake(**kw):
            self.sent.append((kind, kw))
            return True
        return fake


class TestSwitchFromProvider(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.pool = pool_mod.Pool(os.path.join(d, "state.db"), server="test")
        self.sb = os.path.join(d, "singbox.json")
        self.cfg = {"server": "test", "db": os.path.join(d, "state.db"),
                    "singbox_config": self.sb, "lock": os.path.join(d, "agent.lock")}
        self.alerter = SilentAlerter()
        for prov, ext, host in (("proxyline", "9", "10.0.0.9"),
                                ("proxy6", "1", "10.0.0.1")):
            self.pool.upsert_proxy({
                "provider": prov, "ext_id": ext, "ip": host, "host": host,
                "port_http": 8080, "port_socks5": 1080, "user": "u", "password": "p",
                "country": "de", "ip_version": 4, "kind": "dedicated",
                "date_end": None, "descr": ""})

    def tearDown(self):
        self.pool.close()
        self.tmp.cleanup()

    def set_battle(self, host):
        with open(self.sb, "w", encoding="utf-8") as f:
            json.dump({"outbounds": [{"tag": "socks-out", "type": "socks",
                                      "server": host, "server_port": 1080}]}, f)

    def events(self, action):
        return self.pool.conn.execute(
            "SELECT result, detail FROM event WHERE action=?", (action,)).fetchall()

    def test_noop_when_battle_on_other_provider(self):
        self.set_battle("10.0.0.1")          # боевой у proxy6
        r = states.switch_from_provider(self.cfg, {}, self.pool, self.alerter, "proxyline")
        self.assertTrue(r["ok"])
        self.assertFalse(r["switched"])
        self.assertIn("переключать нечего", r["detail"])
        self.assertEqual(self.alerter.sent, [])

    def test_noop_when_no_singbox_config(self):
        # конфига sing-box нет (dev/битый узел) — определить боевого нельзя, не трогаем
        r = states.switch_from_provider(self.cfg, {}, self.pool, self.alerter, "proxyline")
        self.assertTrue(r["ok"])
        self.assertFalse(r["switched"])

    def test_frozen_pause_respected(self):
        self.set_battle("10.0.0.9")          # боевой у proxyline, ключ которого удалён
        self.pool.set_setting("automat_frozen", "1")
        r = states.switch_from_provider(self.cfg, {}, self.pool, self.alerter, "proxyline")
        self.assertFalse(r["ok"])
        self.assertFalse(r["switched"])
        self.assertIn("пауз", r["detail"])
        evs = self.events("provider-switch")
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0][0], "frozen")
        self.assertEqual(self.alerter.sent, [], "на паузе не жужжим письмами")

    @unittest.skipIf(os.name == "posix", "dev-заглушка проверяется только вне Linux")
    def test_dev_machine_does_not_touch_channel(self):
        self.set_battle("10.0.0.9")
        r = states.switch_from_provider(self.cfg, {}, self.pool, self.alerter, "proxyline")
        self.assertFalse(r["ok"])
        self.assertFalse(r["switched"])
        self.assertIn("Linux", r["detail"])
        # пул цел: и боевой proxyline, и кандидат proxy6 на месте
        uids = {x["uid"] for x in self.pool.list(include_gone=True)}
        self.assertEqual(uids, {"proxyline:9", "proxy6:1"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
