"""AtomicMail uses the same alert API without SMTP fallback or secret leakage."""
import json
import os
import tempfile
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

import _ctx  # noqa: F401
import alerts


class _AtomicMailError(Exception):
    def __init__(self, message, unknown=False):
        super().__init__(message)
        self.unknown = unknown


class TestAtomicMailAlerts(unittest.TestCase):
    def setUp(self):
        self.sender = {"status": "ready", "api_key": "your_atomic_longterm_secret_here",
                       "address": "redut-test@atomicmail.ai", "to": "owner@example.com"}
        self.smtp = {"host": "smtp.example.com", "user": "node@example.com",
                     "to": "owner@example.com", "password": "your_smtp_password_here"}
        self.logs = []
        self.send = mock.Mock(return_value=None)
        transport = types.SimpleNamespace(send=self.send, AtomicMailError=_AtomicMailError)
        self.patch = mock.patch.dict(sys.modules, {"atomicmail": transport})
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def alerter(self, sender=None, **kwargs):
        block = dict(self.sender if sender is None else sender)
        recipient = block.pop("to", None)
        return alerts.make_alerter(
            {"smtp": self.smtp, "atomicmail": block, "mail": {"to": recipient}},
            {"mail_transport": "atomicmail", "server": "test-node"},
            log=self.logs.append, secrets_path="/test/secrets.json", **kwargs)

    def test_ready_mailbox_uses_atomicmail_and_formatted_alert(self):
        sender = self.alerter()
        self.assertTrue(sender.configured)
        with mock.patch.object(alerts.smtplib, "SMTP") as smtp:
            self.assertTrue(sender.recovered(new_ip="203.0.113.1", egress="203.0.113.2", cc="cn"))
        smtp.assert_not_called()
        args = self.send.call_args.args
        self.assertEqual(args[:2], ("/test/secrets.json", "owner@example.com"))
        self.assertIn("[vpn-agent test-node]", args[2])
        self.assertIn("203.0.113.2", args[3])
        self.assertEqual(sender.last_error, "")

    def test_configuration_needs_ready_key_and_valid_addresses(self):
        for field, value in (("status", "provisioning"), ("api_key", ""),
                             ("address", "invalid"), ("to", ""), ("to", "invalid")):
            with self.subTest(field=field, value=value):
                sender = self.alerter({**self.sender, field: value})
                self.assertFalse(sender.configured)
                self.assertFalse(sender.send("hello", "body"))
        self.send.assert_not_called()

    def test_atomicmail_failure_has_no_smtp_fallback_or_secret_log(self):
        self.send.side_effect = _AtomicMailError("Authorization: " + self.sender["api_key"])
        sender = self.alerter()
        with mock.patch.object(alerts.smtplib, "SMTP") as smtp:
            self.assertFalse(sender.send("hello", "body"))
        smtp.assert_not_called()
        self.assertEqual(self.send.call_count, 1)
        self.assertNotIn(self.sender["api_key"], sender.last_error + str(self.logs))
        self.assertNotIn("Authorization", sender.last_error + str(self.logs))

    def test_unknown_result_is_not_retried_and_other_alerts_remain_available(self):
        # Persistent duplicate suppression belongs to atomicmail.send(), so the
        # facade must not block different alerts after one uncertain result.
        self.send.side_effect = [_AtomicMailError("uncertain", unknown=True), None]
        sender = self.alerter()
        self.assertFalse(sender.send("hello", "body"))
        self.assertEqual(self.send.call_count, 1)
        self.assertIn("повторная отправка остановлена", sender.last_error)
        self.assertTrue(sender.send("another event", "different body"))
        self.assertEqual(self.send.call_count, 2)

    def test_body_and_subject_mask_mailbox_key_without_external_mask(self):
        sender = self.alerter()
        self.assertTrue(sender.send("key " + self.sender["api_key"],
                                    "body " + self.sender["api_key"]))
        self.assertNotIn(self.sender["api_key"], str(self.send.call_args))
        self.assertNotIn(self.sender["api_key"], str(self.logs))

    def test_caller_mask_still_applies(self):
        sender = self.alerter(mask=lambda text: text.replace("provider-secret", "****"))
        self.assertTrue(sender.send("provider-secret", "provider-secret"))
        self.assertNotIn("provider-secret", str(self.send.call_args))

    def test_legacy_config_keeps_smtp_even_if_atomicmail_already_exists(self):
        sender = alerts.make_alerter({"smtp": self.smtp, "atomicmail": self.sender}, {})
        self.assertEqual(sender.transport, "smtp")
        self.assertTrue(sender.configured)
        self.send.assert_not_called()

    def test_atomicmail_recipient_only_comes_from_verified_mail_block(self):
        source = {"atomicmail": dict(self.sender)}
        sender = alerts.make_alerter(source, {"mail_transport": "atomicmail"})
        self.assertFalse(sender.configured)
        source["mail"] = {"to": "confirmed@example.com"}
        sender = alerts.make_alerter(source, {"mail_transport": "atomicmail"})
        self.assertTrue(sender.configured)
        self.assertEqual(sender.atomicmail["to"], "confirmed@example.com")
        self.assertEqual(source["atomicmail"]["to"], "owner@example.com")

    def test_explicit_smtp_keeps_old_constructor_contract(self):
        sender = alerts.Alerter(self.smtp, "node", self.logs.append)
        self.assertEqual(sender.transport, "smtp")
        self.assertTrue(sender.configured)

    def test_invalid_transport_does_not_silently_send_via_smtp(self):
        sender = alerts.make_alerter({"smtp": self.smtp}, {"mail_transport": "typo"},
                                    log=self.logs.append)
        with mock.patch.object(alerts.smtplib, "SMTP") as smtp:
            self.assertFalse(sender.configured)
            self.assertFalse(sender.send("hello", "body"))
        smtp.assert_not_called()

    def contour_sender(self, cfg):
        return alerts.make_alerter(
            {"smtp": self.smtp, "atomicmail": self.sender,
             "mail": {"to": "owner@example.com"}}, cfg,
            log=self.logs.append, secrets_path="/test/secrets.json")

    def test_both_contours_use_current_main_transport_and_recipient(self):
        with tempfile.TemporaryDirectory() as temp:
            main_path = Path(temp) / "config.json"
            for current, stale in (("atomicmail", "smtp"), ("smtp", "atomicmail")):
                with self.subTest(current=current):
                    main = {"mail_transport": current}
                    main_path.write_text(json.dumps(main))
                    second = {"contour_id": "2", "main_config": str(main_path),
                              "mail_transport": stale}
                    self.send.reset_mock()
                    with mock.patch.object(alerts.smtplib, "SMTP") as smtp:
                        for cfg in (main, second):
                            sender = self.contour_sender(cfg)
                            self.assertEqual(sender.transport, current)
                            self.assertTrue(sender.send("contour alert", "body"))
                    if current == "atomicmail":
                        smtp.assert_not_called()
                        self.assertEqual(self.send.call_count, 2)
                        self.assertTrue(all(call.args[1] == "owner@example.com"
                                            for call in self.send.call_args_list))
                    else:
                        self.send.assert_not_called()
                        self.assertEqual(smtp.call_count, 2)
                    self.assertEqual(second["mail_transport"], stale)

    def test_child_follows_implicit_legacy_smtp_of_main_config(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.json"
            path.write_text("{}")
            sender = self.contour_sender({"contour_id": "2", "main_config": str(path),
                                          "mail_transport": "atomicmail"})
            self.assertEqual(sender.transport, "smtp")
            self.assertTrue(sender.configured)

    def test_unreadable_main_config_never_uses_stale_child_smtp(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.json"
            for content in (None, "bad JSON", "[]", '{"mail_transport":"invalid"}'):
                with self.subTest(content=content):
                    if content is not None:
                        path.write_text(content)
                    sender = self.contour_sender({"contour_id": "2", "main_config": str(path),
                                                  "mail_transport": "smtp"})
                    with mock.patch.object(alerts.smtplib, "SMTP") as smtp:
                        self.assertFalse(sender.configured)
                        self.assertFalse(sender.send("contour alert", "body"))
                    smtp.assert_not_called()
                    self.send.assert_not_called()

    def test_child_without_main_config_path_does_not_fall_back(self):
        sender = self.contour_sender({"contour_id": "2", "mail_transport": "smtp"})
        self.assertFalse(sender.configured)

    def test_explicit_secret_path_overrides_environment(self):
        with mock.patch.dict(os.environ, {"VPN_PANEL_SECRETS": "/env/secrets.json"}):
            self.assertEqual(self.alerter().secrets_path, "/test/secrets.json")

    def test_environment_path_is_respected(self):
        with mock.patch.dict(os.environ, {"VPN_PANEL_SECRETS": "/env/secrets.json"}):
            sender = alerts.make_alerter({"atomicmail": self.sender}, {"mail_transport": "atomicmail"})
        self.assertEqual(sender.secrets_path, "/env/secrets.json")

    def test_local_secret_path_matches_agent_fallback(self):
        local = os.path.join(os.path.dirname(alerts.__file__), ".secrets.local.json")
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(alerts.os.path, "isfile", side_effect=lambda path: path == local):
            sender = alerts.make_alerter({"atomicmail": self.sender}, {"mail_transport": "atomicmail"})
        self.assertEqual(sender.secrets_path, local)


if __name__ == "__main__":
    unittest.main()
