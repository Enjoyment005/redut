# -*- coding: utf-8 -*-
"""alerts.py: форматирование писем, маскировка секретов, тихий фолбэк без SMTP."""
import unittest

import _ctx  # noqa: F401
import alerts


class TestNoSMTP(unittest.TestCase):
    """SMTP не настроен -> typed-методы возвращают False, ничего не бросают (§20)."""

    def test_not_configured(self):
        a = alerts.Alerter(smtp={}, server="test", log=lambda m: None)
        self.assertFalse(a.configured)
        self.assertFalse(a.rotated(old_ip="1.1.1.1", new_ip="2.2.2.2", uid="proxy6:1",
                                   egress="2.2.2.2", cc="de", tg_code="200"))
        self.assertFalse(a.emergency(reason="нет денег"))
        self.assertFalse(a.no_heartbeat(hours=30))

    def test_partial_config_not_enough(self):
        a = alerts.Alerter(smtp={"host": "h"}, server="test", log=lambda m: None)  # нет from/to
        self.assertFalse(a.configured)


class _Capture(alerts.Alerter):
    """Перехватывает письмо вместо реальной отправки, применяя ту же mask."""
    def __init__(self, **kw):
        super().__init__(**kw)
        self.sent = []

    def _send(self, subject, body):
        # повторяем префикс темы из настоящего _send, чтобы тест был правдив
        subj = "[vpn-agent %s] %s" % (self.server, subject)
        self.sent.append((subj, self.mask(body)))
        return True


def _mk(mask=None):
    return _Capture(smtp={"host": "h", "from": "f@x", "to": "t@x"}, server="node1", mask=mask)


class TestFormatting(unittest.TestCase):
    def test_configured_true(self):
        self.assertTrue(_mk().configured)

    def test_rotated_has_ips_and_uid(self):
        a = _mk()
        a.rotated(old_ip="1.1.1.1", new_ip="2.2.2.2", uid="proxy6:40",
                  egress="2.2.2.2", cc="lv", tg_code="200", candidates_tried=3)
        subj, body = a.sent[0]
        self.assertIn("1.1.1.1", subj)
        self.assertIn("2.2.2.2", body)
        self.assertIn("proxy6:40", body)
        self.assertIn("node1", subj)          # метка сервера в теме

    def test_retuned_shows_modes(self):
        a = _mk()
        a.retuned(host="5.5.5.5", old_mode="SOCKS5 :1080", new_mode="HTTP :8080", uid="proxy6:7")
        subj, body = a.sent[0]
        self.assertIn("RETUNE", subj)
        self.assertIn("5.5.5.5", body)

    def test_bought_shows_price_and_balance(self):
        a = _mk()
        a.bought(uid="proxy6:5", price=42.5, currency="RUB", balance_after=900,
                 country="fi", period=7, egress="9.9.9.9", cc="fi")
        subj, body = a.sent[0]
        self.assertIn("42.5", subj)
        self.assertIn("900", body)
        self.assertIn("fi", body)

    def test_emergency_and_recovered(self):
        a = _mk()
        a.emergency(reason="денег не хватило")
        a.recovered(new_ip="3.3.3.3", egress="3.3.3.3", cc="de")
        self.assertIn("АВАРИЙНЫЙ", a.sent[0][0].upper())
        self.assertIn("3.3.3.3", a.sent[1][1])

    def test_no_heartbeat_body(self):
        a = _mk()
        a.no_heartbeat(hours=30.0, last_ts="2026-08-13 06:00:00")
        subj, body = a.sent[0]
        self.assertIn("30", subj)
        self.assertIn("2026-08-13 06:00:00", body)

    def test_mask_applied_to_body(self):
        a = _mk(mask=lambda s: s.replace("SECRETKEY", "****"))
        a.frozen_net(detail="ключ SECRETKEY утёк в текст ошибки")
        subj, body = a.sent[0]
        self.assertNotIn("SECRETKEY", body)
        self.assertIn("****", body)


if __name__ == "__main__":
    unittest.main()
