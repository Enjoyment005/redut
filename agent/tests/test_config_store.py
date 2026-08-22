# -*- coding: utf-8 -*-
"""Атомарная запись config.json из панели и агента."""
import json
import os
import tempfile
import unittest

import _ctx  # noqa: F401
import config_store


class TestConfigStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "config.json")
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"countries": {"blacklist": ["tr"], "strategy": "balanced"},
                       "money": {"max_buys_per_day": 2}}, f)
        self.cfg = {"_source": self.path, "countries": {"strategy": "balanced"},
                    "_runtime_only": True}

    def tearDown(self):
        self.tmp.cleanup()

    def test_strategy_update_preserves_neighbours_and_runtime_fields_stay_memory_only(self):
        config_store.save_country_strategy(self.cfg, "speed")
        with open(self.path, encoding="utf-8") as f:
            saved = json.load(f)
        self.assertEqual(saved["countries"], {"blacklist": ["tr"], "strategy": "speed"})
        self.assertEqual(saved["money"]["max_buys_per_day"], 2)
        self.assertNotIn("_runtime_only", saved)
        self.assertEqual(self.cfg["countries"]["strategy"], "speed")

    def test_refresh_observes_change_from_another_process(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"countries": {"strategy": "reputation"}}, f)
        self.assertEqual(config_store.refresh_country_strategy(self.cfg), "reputation")
        self.assertEqual(self.cfg["countries"]["strategy"], "reputation")

    def test_refresh_observes_removed_strategy_and_restores_default_semantics(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"countries": {"blacklist": ["tr"]}}, f)
        self.assertIsNone(config_store.refresh_country_strategy(self.cfg))
        self.assertNotIn("strategy", self.cfg["countries"])

    def test_failed_mutator_does_not_damage_original(self):
        with open(self.path, "rb") as f:
            before = f.read()
        with self.assertRaises(RuntimeError):
            config_store.update(self.cfg, lambda data: (_ for _ in ()).throw(RuntimeError("boom")))
        with open(self.path, "rb") as f:
            self.assertEqual(f.read(), before)
        self.assertFalse(any(n.startswith(".redut-config-") for n in os.listdir(self.tmp.name)))


if __name__ == "__main__":
    unittest.main()
