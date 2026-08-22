# -*- coding: utf-8 -*-
import json
import math
import os
import tempfile
import unittest
from unittest import mock

import _ctx  # noqa: F401
import agent
import config_schema
import money
from webpanel import server


class TestConfigSchema(unittest.TestCase):
    def defaults(self):
        return {"db": os.path.abspath("state.db"), "ring": os.path.abspath("cfg"),
                "singbox_config": os.path.abspath("singbox.json"),
                "boot_script": os.path.abspath("boot.sh"),
                "lock": os.path.abspath("agent.lock"), "panel_port": 8443,
                "countries": {"strategy": "speed", "blacklist": []},
                "money": dict(money.DEFAULT_LIMITS)}

    def test_legacy_config_normalizes_to_current_schema(self):
        cfg = config_schema.normalize({"countries": {"strategy": " BALANCED ",
                                                       "blacklist": ["TR", "bad", 1]}},
                                      self.defaults(), source="legacy.json")
        self.assertEqual(cfg["config_schema_version"], config_schema.CURRENT_VERSION)
        self.assertEqual(cfg["countries"], {"strategy": "balanced", "blacklist": ["tr"]})
        self.assertFalse(cfg["_config_meta"]["safe_mode"])
        self.assertEqual(cfg["_source"], "legacy.json")

    def test_future_schema_disables_dangerous_actions(self):
        cfg = config_schema.normalize(
            {"config_schema_version": 999,
             "money": {**money.DEFAULT_LIMITS, "buy_enabled": True,
                        "delete_enabled": True}}, self.defaults())
        self.assertTrue(cfg["_config_meta"]["safe_mode"])
        self.assertFalse(cfg["money"]["buy_enabled"])
        self.assertFalse(cfg["money"]["delete_enabled"])

    def test_invalid_dangerous_fields_fail_closed_without_nan(self):
        raw = {"panel_port": "oops", "db": "relative.db", "subnet": "garbage",
               "wan": "eth0; reboot", "countries": {"strategy": "random"},
               "money": {"buy_enabled": "yes", "delete_enabled": 1,
                         "max_buys_per_day": float("nan"),
                         "max_spend_per_day": -1, "max_price_per_buy": {},
                         "min_balance_reserve": float("inf"), "buy_period_days": 0,
                         "buy_version": 6, "currency": "BTC"}}
        cfg = config_schema.normalize(raw, self.defaults())
        self.assertEqual(cfg["panel_port"], 8443)
        self.assertEqual(cfg["db"], self.defaults()["db"])
        self.assertIsNone(cfg.get("subnet"))
        self.assertIsNone(cfg.get("wan"))
        self.assertEqual(cfg["countries"]["strategy"], "speed")
        self.assertFalse(cfg["money"]["buy_enabled"])
        self.assertFalse(cfg["money"]["delete_enabled"])
        for key in ("max_buys_per_day", "max_spend_per_day", "max_price_per_buy",
                    "min_balance_reserve", "buy_period_days", "buy_version"):
            self.assertTrue(math.isfinite(float(cfg["money"][key])))
        self.assertGreater(len(cfg["_config_meta"]["issues"]), 5)

    def test_corrupt_json_does_not_crash_agent_or_panel_loader(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write("{broken")
            cfg = agent.load_config(path)
            self.assertTrue(cfg["_config_meta"]["safe_mode"])
            self.assertFalse(cfg["money"]["buy_enabled"])
            old = os.environ.get("VPN_PANEL_CONFIG")
            os.environ["VPN_PANEL_CONFIG"] = path
            try:
                panel_cfg = server.load_config()
            finally:
                if old is None:
                    os.environ.pop("VPN_PANEL_CONFIG", None)
                else:
                    os.environ["VPN_PANEL_CONFIG"] = old
            self.assertTrue(panel_cfg["_config_meta"]["safe_mode"])
            self.assertFalse(panel_cfg["money"]["buy_enabled"])

    def test_fuzz_scalar_types_never_raise_or_enable_spending(self):
        bad = [None, [], {}, object(), True, float("nan"), float("inf"), "NaN"]
        for value in bad:
            cfg = config_schema.normalize(
                {"config_schema_version": value,
                 "money": {"buy_enabled": value, "delete_enabled": value,
                           "max_buys_per_day": value, "currency": value}},
                self.defaults())
            self.assertFalse(cfg["money"]["buy_enabled"], repr(value))
            self.assertFalse(cfg["money"]["delete_enabled"], repr(value))

    def test_malformed_money_block_and_reserve_disable_spending(self):
        cfg = config_schema.normalize({"money": []}, self.defaults())
        self.assertFalse(cfg["money"]["buy_enabled"])
        cfg = config_schema.normalize(
            {"money": {**money.DEFAULT_LIMITS, "min_balance_reserve": float("nan")}},
            self.defaults())
        self.assertFalse(cfg["money"]["buy_enabled"])

    def test_runtime_boole_and_numbers_are_strict(self):
        cfg = config_schema.normalize(
            {"has_dnsmasq": "false", "wg_port": "NaN",
             "auto_prolong": {"enabled": "false", "days_before": float("nan"),
                              "period_days": "NaN"},
             "update": {"auto": "false", "window": "04:00-06:00",
                        "repo": "Enjoyment005/redut"}}, self.defaults())
        self.assertFalse(cfg["has_dnsmasq"])
        self.assertNotIn("wg_port", cfg)
        self.assertFalse(cfg["auto_prolong"]["enabled"])
        self.assertEqual(cfg["auto_prolong"]["days_before"], 3)
        self.assertEqual(cfg["auto_prolong"]["period_days"], 30)
        self.assertFalse(cfg["update"]["auto"])

    def test_health_hysteresis_numbers_are_normalized(self):
        cfg = config_schema.normalize(
            {"health": {"fresh_seconds": 100, "stale_seconds": 50,
                        "switch_margin": True, "min_hold_time": float("nan"),
                        "max_latency_regression": -1}}, self.defaults())
        self.assertEqual(cfg["health"]["fresh_seconds"], 100.0)
        self.assertGreater(cfg["health"]["stale_seconds"], 100.0)
        self.assertEqual(cfg["health"]["switch_margin"], 15.0)
        self.assertEqual(cfg["health"]["min_hold_time"], 1800.0)
        self.assertEqual(cfg["health"]["max_latency_regression"], 500.0)
        paths = {item["path"] for item in cfg["_config_meta"]["issues"]}
        self.assertTrue({"health.stale_seconds", "health.switch_margin",
                         "health.min_hold_time",
                         "health.max_latency_regression"}.issubset(paths))

    def test_learning_activation_is_fail_closed_and_minimum_is_30_days(self):
        bad = config_schema.normalize({"learning": {
            "mode": "force", "shadow_min_days": 1, "owner_approved": "yes",
            "canary_servers": "node2"}}, self.defaults())
        self.assertEqual(bad["learning"]["mode"], "shadow")
        self.assertEqual(bad["learning"]["shadow_min_days"], 30)
        self.assertFalse(bad["learning"]["owner_approved"])
        self.assertEqual(bad["learning"]["canary_servers"], [])
        good = config_schema.normalize({"learning": {
            "mode": "canary", "shadow_min_days": 45, "owner_approved": True,
            "canary_servers": ["node2", "node2"]}}, self.defaults())
        self.assertEqual(good["learning"], {
            "mode": "canary", "shadow_min_days": 45,
            "owner_approved": True, "canary_servers": ["node2"],
            "exploration_enabled": False, "exploration_rate": 0.05,
            "exploration_max_per_day": 1,
            "exploration_purchase_budget_per_day": 0.0})

    def test_invalid_exploration_policy_is_disabled(self):
        cfg = config_schema.normalize({"learning": {
            "owner_approved": True, "exploration_enabled": True,
            "exploration_rate": float("nan"), "exploration_max_per_day": -1,
            "exploration_purchase_budget_per_day": -5}}, self.defaults())
        self.assertFalse(cfg["learning"]["exploration_enabled"])
        self.assertEqual(cfg["learning"]["exploration_rate"], 0)
        self.assertEqual(cfg["learning"]["exploration_max_per_day"], 0)
        self.assertEqual(cfg["learning"]["exploration_purchase_budget_per_day"], 0)

    def test_network_numbers_and_nul_path_are_rejected(self):
        raw = {"subnet": 1, "gw": 1, "server_ip": 1, "db": "/\0bad"}
        cfg = config_schema.normalize(raw, self.defaults())
        self.assertIsNone(cfg.get("subnet"))
        self.assertIsNone(cfg.get("gw"))
        self.assertIsNone(cfg.get("server_ip"))
        self.assertEqual(cfg["db"], self.defaults()["db"])
        paths = {item["path"] for item in cfg["_config_meta"]["issues"]}
        self.assertTrue({"subnet", "gw", "server_ip", "db"}.issubset(paths))

    def test_legacy_wg_port_and_update_window_compatibility(self):
        cfg = config_schema.normalize(
            {"update": {"auto": True, "window": "3:15 - 3:45",
                        "repo": "Enjoyment005/redut"}}, self.defaults())
        self.assertNotIn("wg_port", cfg)
        self.assertEqual(cfg["update"]["window"], "03:15-03:45")
        self.assertTrue(cfg["update"]["auto"])
        bad = config_schema.normalize(
            {"update": {"auto": True, "window": "00:00-99:99",
                        "repo": "Enjoyment005/redut"}}, self.defaults())
        self.assertFalse(bad["update"]["auto"])

    def test_all_control_characters_in_paths_are_rejected(self):
        for char in ("\n", "\r", "\t", "\x01", "\0"):
            cfg = config_schema.normalize({"db": os.path.abspath("bad" + char + "db")},
                                          self.defaults())
            self.assertEqual(cfg["db"], self.defaults()["db"], repr(char))

    def test_migration_dry_run_backup_and_idempotency(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            original = {"server": "test", "countries": {"strategy": "speed"}}
            with open(path, "w", encoding="utf-8") as f:
                json.dump(original, f)
            dry = config_schema.migrate_file(path, dry_run=True)
            self.assertEqual(dry["steps"], ["0->1"])
            with open(path, encoding="utf-8") as f:
                self.assertEqual(json.load(f), original)
            done = config_schema.migrate_file(path)
            self.assertTrue(os.path.isfile(done["backup"]))
            with open(done["backup"], encoding="utf-8") as f:
                self.assertEqual(json.load(f), original)
            with open(path, encoding="utf-8") as f:
                migrated = json.load(f)
            self.assertEqual(migrated["config_schema_version"], 1)
            again = config_schema.migrate_file(path)
            self.assertFalse(again["changed"])
            self.assertIsNone(again["backup"])

    def test_future_and_invalid_migrations_never_rewrite_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            for raw in ({"config_schema_version": 999}, ["not", "object"]):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(raw, f)
                with open(path, "rb") as f:
                    before = f.read()
                with self.assertRaises(config_schema.ConfigMigrationError):
                    config_schema.migrate_file(path)
                with open(path, "rb") as f:
                    self.assertEqual(f.read(), before)

    def test_deep_json_loaders_enter_safe_mode_instead_of_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write("[" * 2000 + "0" + "]" * 2000)
            cfg = agent.load_config(path)
            self.assertTrue(cfg["_config_meta"]["safe_mode"])
            self.assertTrue(any(x["action"] == "migration-deferred"
                                for x in cfg["_config_meta"]["issues"]))
            old = os.environ.get("VPN_PANEL_CONFIG")
            os.environ["VPN_PANEL_CONFIG"] = path
            try:
                panel_cfg = server.load_config()
            finally:
                if old is None:
                    os.environ.pop("VPN_PANEL_CONFIG", None)
                else:
                    os.environ["VPN_PANEL_CONFIG"] = old
            self.assertTrue(panel_cfg["_config_meta"]["safe_mode"])

    def test_json_parser_memory_error_enters_safe_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write("{}")
            with mock.patch.object(json, "load", side_effect=MemoryError("parser OOM")):
                cfg = agent.load_config(path)
            self.assertTrue(cfg["_config_meta"]["safe_mode"])
            self.assertTrue(any(x["action"] == "migration-deferred"
                                for x in cfg["_config_meta"]["issues"]))

    def test_diagnostics_reports_sources_and_never_exposes_secrets(self):
        raw = {"server": "node", "panel_port": "oops", "api_key": "TOPSECRET",
               "nested": {"password": "TOPSECRET", "visible": "ok"},
               "money": dict(money.DEFAULT_LIMITS)}
        cfg = config_schema.normalize(raw, self.defaults(), source="config.json")
        out = config_schema.diagnostics(cfg)
        rendered = json.dumps(out, ensure_ascii=False)
        self.assertNotIn("TOPSECRET", rendered)
        self.assertNotIn("api_key", rendered)
        self.assertNotIn("password", rendered)
        self.assertEqual(out["effective"]["nested"]["visible"], "ok")
        self.assertEqual(out["sources"]["server"], "config")
        self.assertEqual(out["sources"]["panel_port"], "safe-default")
        self.assertEqual(out["sources"]["db"], "default")

    def test_diagnostics_is_strict_json_and_marks_safe_mode_overrides(self):
        raw = {"config_schema_version": 999, "mystery": float("nan"),
               "money": {**money.DEFAULT_LIMITS, "buy_enabled": True,
                         "delete_enabled": True},
               "auto_prolong": {"enabled": True, "days_before": 3, "period_days": 30},
               "update": {"auto": True, "window": "04:00-06:00",
                          "repo": "Enjoyment005/redut"}}
        out = config_schema.diagnostics(config_schema.normalize(raw, self.defaults()))
        json.dumps(out, allow_nan=False)
        self.assertIsNone(out["effective"]["mystery"])
        for path in ("money.buy_enabled", "money.delete_enabled",
                     "auto_prolong.enabled", "update.auto"):
            self.assertEqual(out["sources"][path], "safe-default")


if __name__ == "__main__":
    unittest.main()
