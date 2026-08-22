# -*- coding: utf-8 -*-
"""alerts.py: форматирование писем, маскировка секретов, тихий фолбэк без SMTP."""
import unittest
from unittest import mock

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
    return _Capture(smtp={"host": "h", "from": "f@x.co", "to": "t@x.co"}, server="node1", mask=mask)


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

    def test_rotated_cold_start_names_first_channel(self):
        # холодный старт: прежнего канала не было — тема и тело говорят это словами, а не пустотой
        a = _mk()
        a.rotated(old_ip="", new_ip="2.2.2.2", uid="proxyline:1", egress="2.2.2.2", cc="mx", tg_code="200")
        subj, body = a.sent[0]
        self.assertIn("Первый канал: 2.2.2.2", subj)
        self.assertNotIn(":  ->", subj)
        self.assertIn("канала не было", body)

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

    def test_proxy_vanished_names_uid_and_paid_days(self):
        a = _mk()
        self.assertTrue(a.proxy_vanished(items=[
            {"uid": "proxyline:28172036", "host": "155.212.127.143", "country": "lt",
             "date_end": "2026-08-26 12:00:00", "days_left": 4.0}]))
        subj, body = a.sent[-1]
        self.assertIn("оплаченный прокси", subj)
        self.assertIn("proxyline:28172036", body)
        self.assertIn("4.0", body)
        self.assertIn("2026-08-26", body)

    def test_proxy_vanished_without_items_is_silent(self):
        a = _mk()
        self.assertFalse(a.proxy_vanished(items=[]))
        self.assertEqual(a.sent, [])

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


class _FakeSMTP:
    """Заглушка SMTP: перехватывает send_message, ни одного сетевого вызова."""
    last = None

    def __init__(self, host, port, timeout=None):
        self.host, self.port = host, port
        self.sent = []
        _FakeSMTP.last = self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def ehlo(self):
        pass

    def starttls(self, context=None):
        pass

    def login(self, user, password):
        self.login_user = user

    def send_message(self, msg):
        self.sent.append(msg)


class TestEnvelopeFrom(unittest.TestCase):
    """Фикс приёмки node2 (17.08): display-name в «from» -> фолбэк на user (реальный ящик).

    Иначе SMTP отвечает 501 Invalid MAIL FROM и все алерты молча пропадают.
    """

    def test_valid_email_helper(self):
        self.assertTrue(alerts._valid_email("user@example.com"))
        self.assertTrue(alerts._valid_email("  a@b.co  "))       # пробелы обрезаются
        self.assertFalse(alerts._valid_email("От ВПНА"))          # отображаемое имя, не адрес
        self.assertFalse(alerts._valid_email("no-at-sign"))
        self.assertFalse(alerts._valid_email("a@b"))              # нет точки в домене
        self.assertFalse(alerts._valid_email(""))
        self.assertFalse(alerts._valid_email(None))

    @staticmethod
    def _envelope_from(msg):
        # ровно то, что smtplib.send_message извлечёт как MAIL FROM из заголовка From
        import email.utils
        return email.utils.getaddresses([msg["From"]])[0][1]

    def test_display_name_from_falls_back_to_user(self):
        smtp = {"host": "h", "port": 587, "user": "box@example.com", "password": "x",
                "from": "От ВПНА", "to": "to@example.com"}
        a = alerts.Alerter(smtp=smtp, server="test", log=lambda m: None)
        self.assertTrue(a.configured)                             # «from» непустой -> configured
        with mock.patch.object(alerts.smtplib, "SMTP", _FakeSMTP):
            self.assertTrue(a._send("тест", "тело"))
        msg = _FakeSMTP.last.sent[0]
        self.assertEqual(self._envelope_from(msg), "box@example.com")  # envelope — реальный ящик
        self.assertIn("box@example.com", msg["From"])                 # ярлык сохранён как display-name

    def test_valid_from_used_as_is(self):
        smtp = {"host": "h", "port": 587, "user": "box@example.com",
                "from": "real@example.com", "to": "to@example.com"}
        a = alerts.Alerter(smtp=smtp, server="test", log=lambda m: None)
        with mock.patch.object(alerts.smtplib, "SMTP", _FakeSMTP):
            self.assertTrue(a._send("тест", "тело"))
        self.assertEqual(_FakeSMTP.last.sent[0]["From"], "real@example.com")

    def test_empty_from_with_valid_user_is_configured(self):
        # Мастер сохраняет почту без «from» (поля больше нет) — алерты обязаны работать:
        # отправитель берётся из логина. До 1.3.2 такой узел молча сидел без писем (node2 18.08).
        smtp = {"host": "h", "port": 587, "user": "box@example.com", "password": "x",
                "from": "", "to": "to@example.com"}
        a = alerts.Alerter(smtp=smtp, server="test", log=lambda m: None)
        self.assertTrue(a.configured)
        with mock.patch.object(alerts.smtplib, "SMTP", _FakeSMTP):
            self.assertTrue(a._send("тест", "тело"))
        msg = _FakeSMTP.last.sent[0]
        self.assertEqual(self._envelope_from(msg), "box@example.com")
        self.assertEqual(msg["From"], "box@example.com")          # без ярлыка — голый адрес

    def test_no_from_key_at_all_is_configured(self):
        smtp = {"host": "h", "user": "box@example.com", "to": "to@example.com"}
        self.assertTrue(alerts.Alerter(smtp=smtp, server="test", log=lambda m: None).configured)

    def test_invalid_from_and_no_user_logs_and_returns_false(self):
        logs = []
        smtp = {"host": "h", "from": "От ВПНА", "to": "to@example.com"}  # user отсутствует
        a = alerts.Alerter(smtp=smtp, server="test", log=logs.append)
        # слать нечем: ни валидного «from», ни логина -> честно «не настроено»
        self.assertFalse(a.configured)
        with mock.patch.object(alerts.smtplib, "SMTP", _FakeSMTP):
            self.assertFalse(a._send("тест", "тело"))            # не шлём и НЕ бросаем
        self.assertTrue(any("не настроен" in m.lower() for m in logs))


if __name__ == "__main__":
    unittest.main()
