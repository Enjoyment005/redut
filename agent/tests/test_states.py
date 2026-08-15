# -*- coding: utf-8 -*-
"""Машина состояний §8: лестница диагностики (порядок!), лимиты, cooldown, пульс.

Тесты без сервера: проверяем ЧИСТЫЕ решения (decide/cooldown/age) и работу с БД
(кандидаты с cooldown, счётчик замен, резерв N+1, heartbeat-check с дедупом).
"""
import datetime
import os
import tempfile
import unittest

import _ctx  # noqa: F401  (кладёт panel/ в sys.path)
import pool as pool_mod
import states


def mk_norm(ext_id, host, country="de"):
    return {"provider": "proxy6", "ext_id": str(ext_id), "ip": host, "host": host,
            "port_http": 8080, "port_socks5": 1080, "user": "u", "password": "p",
            "country": country, "ip_version": 4, "kind": "dedicated",
            "date_end": "", "descr": ""}


class TestDecideLadder(unittest.TestCase):
    """Порядок §8 критичен: шаг 1 (сеть) раньше всего — иначе сожжём пул."""

    def test_frozen_net_wins_over_everything(self):
        # сеть мертва -> frozen_net ВСЕГДА, что бы ни было с egress/sing-box
        self.assertEqual(states.decide(False, True, True), "frozen_net")
        self.assertEqual(states.decide(False, False, False), "frozen_net")
        self.assertEqual(states.decide(False, True, False), "frozen_net")

    def test_ok_when_egress_alive(self):
        self.assertEqual(states.decide(True, True, True), "ok")
        self.assertEqual(states.decide(True, True, False), "ok")  # egress жив — чинить нечего

    def test_self_heal_when_singbox_broken(self):
        self.assertEqual(states.decide(True, False, False), "self_heal")

    def test_proxy_fault_is_last(self):
        self.assertEqual(states.decide(True, False, True), "proxy_fault")


class TestCooldown(unittest.TestCase):
    def test_exponential_10_30_120(self):
        self.assertEqual(states.cooldown_seconds(1), 600)     # 10 мин
        self.assertEqual(states.cooldown_seconds(2), 1800)    # 30 мин
        self.assertEqual(states.cooldown_seconds(3), 7200)    # 2 ч
        self.assertEqual(states.cooldown_seconds(9), 7200)
        self.assertEqual(states.cooldown_seconds(0), 7200)


class TestAge(unittest.TestCase):
    def test_age_seconds(self):
        now = datetime.datetime(2026, 8, 14, 12, 0, 0)
        self.assertAlmostEqual(states.age_seconds("2026-08-14 11:00:00", now), 3600, delta=1)
        self.assertAlmostEqual(states.age_seconds("2026-08-14T11:00:00", now), 3600, delta=1)
        self.assertIsNone(states.age_seconds("", now))
        self.assertIsNone(states.age_seconds(None, now))


class TestPoolAutomat(unittest.TestCase):
    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.pool = pool_mod.Pool(self.db, server="test")

    def tearDown(self):
        self.pool.close()
        os.unlink(self.db)

    def _add(self, ext_id, host, role="auto", probe_ok=1, score=80.0, cooldown=None):
        uid = self.pool.upsert_proxy(mk_norm(ext_id, host), role=role)
        self.pool.conn.execute(
            "UPDATE proxy SET probe_ok=?, score=?, cooldown_until=? WHERE uid=?",
            (probe_ok, score, cooldown, uid))
        self.pool.conn.commit()
        return uid

    def test_rotation_candidates_excludes_cooldown_and_current(self):
        self._add(1, "1.1.1.1")
        future = (datetime.datetime.now() + datetime.timedelta(hours=1)
                  ).replace(microsecond=0).isoformat(sep=" ")
        self._add(2, "2.2.2.2", cooldown=future)     # на cooldown — не кандидат
        self._add(3, "3.3.3.3")                       # текущий — исключим по host
        hosts = {c["host"] for c in self.pool.rotation_candidates(exclude_host="3.3.3.3")}
        self.assertIn("1.1.1.1", hosts)
        self.assertNotIn("2.2.2.2", hosts)
        self.assertNotIn("3.3.3.3", hosts)

    def test_expired_cooldown_is_candidate_again(self):
        past = (datetime.datetime.now() - datetime.timedelta(hours=1)
                ).replace(microsecond=0).isoformat(sep=" ")
        uid = self._add(1, "1.1.1.1", cooldown=past)
        self.assertIn(uid, {c["uid"] for c in self.pool.rotation_candidates()})

    def test_set_clear_cooldown(self):
        uid = self._add(1, "1.1.1.1")
        self.pool.set_cooldown(uid, 600)
        self.assertNotIn(uid, {c["uid"] for c in self.pool.rotation_candidates()})
        self.pool.clear_cooldown(uid)
        self.assertIn(uid, {c["uid"] for c in self.pool.rotation_candidates()})

    def test_bump_fail_increments(self):
        uid = self._add(1, "1.1.1.1")
        self.assertEqual(self.pool.bump_fail(uid), 1)
        self.assertEqual(self.pool.bump_fail(uid), 2)

    def test_reserve_count_only_verified_non_current(self):
        self._add(1, "1.1.1.1", probe_ok=1, score=80.0)
        self._add(2, "2.2.2.2", probe_ok=0, score=None)   # не проверен -> не резерв
        self._add(3, "3.3.3.3", probe_ok=1, score=70.0)   # текущий
        self.assertEqual(self.pool.reserve_count(current_host="3.3.3.3"), 1)

    def test_off_and_chrome_not_candidates(self):
        self._add(1, "1.1.1.1", role="off")
        self._add(2, "2.2.2.2", role="chrome")
        self._add(3, "3.3.3.3", role="auto")
        hosts = {c["host"] for c in self.pool.rotation_candidates()}
        self.assertEqual(hosts, {"3.3.3.3"})

    def test_rotations_last_hour_counts_auto_replacements(self):
        self.pool.log_event("rotate", actor="auto", result="ok")
        self.pool.log_event("replenish", actor="auto", result="ok")
        self.pool.log_event("rotate", actor="user", result="ok")    # ручной — не в лимит
        self.pool.log_event("retune", actor="auto", result="ok")    # RETUNE — не «замена»
        self.pool.log_event("rotate", actor="auto", result="fail")  # неуспех — не считаем
        self.assertEqual(self.pool.rotations_last_hour(), 2)

    def test_settings_roundtrip(self):
        self.pool.set_setting("automat_state", states.EMERGENCY)
        self.assertEqual(self.pool.get_setting("automat_state"), states.EMERGENCY)
        self.assertEqual(self.pool.get_setting("nope", "def"), "def")

    def test_heartbeat(self):
        self.assertIsNone(self.pool.last_heartbeat())
        self.pool.heartbeat()
        self.assertIsNotNone(self.pool.last_heartbeat())


class _FakeAlerter:
    def __init__(self):
        self.calls = []

    def no_heartbeat(self, **kw):
        self.calls.append(kw)
        return True


class TestHeartbeatCheck(unittest.TestCase):
    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.pool = pool_mod.Pool(self.db, server="test")

    def tearDown(self):
        self.pool.close()
        os.unlink(self.db)

    def test_fresh_pulse_no_alert(self):
        self.pool.heartbeat()
        a = _FakeAlerter()
        r = states.heartbeat_check(self.pool, a)
        self.assertFalse(r["stale"])
        self.assertEqual(a.calls, [])

    def test_stale_alerts_once_then_dedup(self):
        old = (datetime.datetime.now() - datetime.timedelta(hours=30)
               ).replace(microsecond=0).isoformat(sep=" ")
        self.pool.set_setting("agent_heartbeat", old)
        a = _FakeAlerter()
        r1 = states.heartbeat_check(self.pool, a)
        self.assertTrue(r1["stale"])
        self.assertEqual(len(a.calls), 1)           # письмо один раз
        states.heartbeat_check(self.pool, a)
        self.assertEqual(len(a.calls), 1)           # повтор про тот же пульс — молчим


if __name__ == "__main__":
    unittest.main()
