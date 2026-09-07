# -*- coding: utf-8 -*-
"""Regression checks for false proxy health and loss of manual intent."""
import contextlib
import http.server
import json
import os
import shutil
import socket
import tempfile
import threading
import unittest
from unittest import mock

import _ctx  # noqa: F401
import pool as pool_mod
import probe
import states


class TestManualConfigFailure(unittest.TestCase):
    def test_unavailable_config_keeps_manual_intent_and_state(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.closing(
                pool_mod.Pool(os.path.join(tmp, "state.db"), server="test")) as pool:
            cfg = {"singbox_config": os.path.join(tmp, "singbox.json"),
                   "_source": os.path.join(tmp, "config.json"),
                   "countries": {"strategy": "reputation"}}
            with open(cfg["_source"], "w", encoding="utf-8") as config:
                json.dump({"countries": {"strategy": "reputation"}}, config)
            states.set_manual_selection(pool, "proxy6:1", "192.0.2.1")
            original = states.selection_revision_state(pool, cfg)
            for error in (OSError("unreadable config"), ValueError("invalid JSON")):
                with self.subTest(error=type(error).__name__), \
                     mock.patch.object(states.apply_mod, "load_json", side_effect=error), \
                     mock.patch.object(states, "net_alive", return_value=(False, None)), \
                     mock.patch.object(states.apply_mod, "verify_egress",
                                       return_value={"ok": False}), \
                     mock.patch.object(states, "singbox_health",
                                       return_value={"ok": True, "active": True, "tun0": True}), \
                     mock.patch.object(states, "release_manual_on_fault",
                                       wraps=states.release_manual_on_fault) as release:
                    result = states._rotate_locked(
                        cfg, {}, pool, mock.Mock(), "watchdog", "auto", lambda *_: None,
                        {}, states.OK)
                self.assertFalse(result["ok"])
                self.assertEqual(result["action"], "config-unavailable")
                self.assertEqual(result["state"], states.OK)
                self.assertEqual(states.selection_revision_state(pool, cfg), original)
                self.assertEqual(states.selection_state(pool, cfg)["mode"], "manual")
                release.assert_not_called()


class TestLocalPathFailure(unittest.TestCase):
    def test_live_egress_and_failed_path_repair_never_reaches_provider(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.closing(
                pool_mod.Pool(os.path.join(tmp, "state.db"), server="test")) as pool:
            cfg = {"singbox_config": os.path.join(tmp, "singbox.json"),
                   "countries": {"strategy": "reputation"}}
            egress = {"ok": True, "egress_ip": "203.0.113.10",
                      "exit_cc": "lv", "tg_code": "204",
                      "why": "", "why_kind": ""}
            with mock.patch.object(states, "reconcile_strategy_override"), \
                 mock.patch.object(states.apply_mod, "load_json", return_value={}), \
                 mock.patch.object(states.apply_mod, "current_upstream",
                                   return_value="192.0.2.50"), \
                 mock.patch.object(states, "net_alive", return_value=(True, "direct")), \
                 mock.patch.object(states.apply_mod, "verify_egress",
                                   return_value=egress), \
                 mock.patch.object(states, "singbox_health",
                                   return_value={"ok": False}), \
                 mock.patch.object(states, "try_self_heal", return_value=False), \
                 mock.patch.object(states, "try_retune") as retune:
                result = states._rotate_locked(
                    cfg, {}, pool, mock.Mock(), "watchdog", "auto",
                    lambda *_args: None, {}, states.OK)
            self.assertFalse(result["ok"])
            self.assertEqual(result["state"], states.DEGRADED)
            self.assertEqual(result["action"], "self-heal-failed")
            retune.assert_not_called()


class TestProbeIPValidation(unittest.TestCase):
    def test_invalid_ipify_responses_cannot_make_a_healthy_matrix(self):
        for response in ("999.999.999.999", ":", "1:2:3", ":::1"):
            with self.subTest(response=response), \
                 mock.patch.object(probe, "fetch_via", return_value=response):
                matrix = probe.probe_matrix("192.0.2.1", [1080], "", "")
                self.assertTrue(all(value is None for value in matrix.values()))

    def test_ipv4_and_ipv6_are_parsed_including_mapped_ipv4(self):
        for value in ("192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1"):
            with self.subTest(value=value):
                self.assertTrue(probe.looks_like_ip(value))
        self.assertTrue(probe.is_ipv4("192.0.2.1"))
        self.assertFalse(probe.is_ipv4("999.999.999.999"))
        self.assertFalse(probe.is_ipv4("2001:db8::1"))


@unittest.skipUnless(shutil.which(probe.CURL), "curl is required for loopback regression")
class TestProbeNoProxyBypass(unittest.TestCase):
    def test_no_proxy_environment_cannot_turn_a_dead_proxy_into_a_success(self):
        # Everything stays on loopback.  The origin would return a valid exit IP
        # if curl mistakenly obeyed NO_PROXY and bypassed the candidate.
        hits = []

        class Origin(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                body = b"192.0.2.99"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        with http.server.HTTPServer(("127.0.0.1", 0), Origin) as origin, \
             socket.socket() as dead_proxy:
            # Reserve a port without listening: connecting to it must fail.
            dead_proxy.bind(("127.0.0.1", 0))
            worker = threading.Thread(target=origin.serve_forever,
                                      kwargs={"poll_interval": 0.01}, daemon=True)
            worker.start()
            try:
                url = "http://127.0.0.1:%s/ip" % origin.server_port
                with mock.patch.dict(os.environ, {"NO_PROXY": "*", "no_proxy": "*"}):
                    for protocol in ("http", "socks"):
                        with self.subTest(protocol=protocol):
                            response = probe.fetch_via(
                                protocol, "127.0.0.1", dead_proxy.getsockname()[1],
                                "", "", url, timeout=1)
                            self.assertEqual(response, "")
                self.assertEqual(hits, [], "probe must never access the origin directly")
            finally:
                origin.shutdown()
                worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
