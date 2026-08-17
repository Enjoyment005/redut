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


class TestRankCandidates(unittest.TestCase):
    """Порядок выбора канала (снос №5): trusted-страна вперёд, чёрный список выброшен,
    сырой кандидат хорошей страны обгоняет пробованный кандидат плохой страны."""

    def _row(self, host, country, exit_cc=None, probe_ok=0, score=None, role="auto"):
        return {"uid": "proxy6:%s" % host, "host": host, "country": country,
                "exit_cc": exit_cc, "probe_ok": probe_ok, "score": score, "role": role}

    def test_blacklist_dropped(self):
        rows = [self._row("r", "ru"), self._row("u", "ua"), self._row("b", "by"),
                self._row("d", "de")]
        out = states.rank_candidates(rows)
        self.assertEqual([r["host"] for r in out], ["d"])

    def test_trusted_before_low_trust_even_if_unprobed(self):
        # Латвия сырая (score=None) должна идти ПЕРЕД Нигерией, уже пробованной (score=60) —
        # ровно баг сноса №5 (первый канал ушёл в ng при живой lv в пуле)
        rows = [self._row("ng", "ng", exit_cc="ng", probe_ok=1, score=60.0),
                self._row("lv", "lv")]
        out = [r["host"] for r in states.rank_candidates(rows)]
        self.assertEqual(out[0], "lv")
        self.assertEqual(out, ["lv", "ng"])

    def test_probed_trusted_before_raw_trusted(self):
        rows = [self._row("lv_raw", "lv"),
                self._row("de_ok", "de", exit_cc="de", probe_ok=1, score=150.0)]
        out = [r["host"] for r in states.rank_candidates(rows)]
        self.assertEqual(out, ["de_ok", "lv_raw"])   # при равной стране — выше по реальному score

    def test_exit_cc_overrides_declared_country(self):
        # продан как lv, но geoip видит ng -> ранжируем по фактической стране
        rows = [self._row("x", "lv", exit_cc="ng", probe_ok=1, score=60.0),
                self._row("y", "fi")]
        out = [r["host"] for r in states.rank_candidates(rows)]
        self.assertEqual(out[0], "y")


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

    def test_off_not_candidate(self):
        self._add(1, "1.1.1.1", role="off")
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

    def test_selectable_includes_unprobed_excludes_blacklist(self):
        # «Из чего выбрать»: сырые (непробованные) кандидаты тоже считаются, ru — нет
        self._addc(1, "1.1.1.1", "lv", probe_ok=0, score=None)   # сырой trusted — годен
        self._addc(2, "2.2.2.2", "ru", probe_ok=1, score=90.0)   # чёрный список — не годен
        self._addc(3, "3.3.3.3", "de", probe_ok=1, score=140.0)  # текущий
        sel = states.selectable_candidates(self.pool, {"role": None}, "3.3.3.3")
        hosts = [r["host"] for r in sel]
        self.assertEqual(hosts, ["1.1.1.1"])

    def test_selectable_orders_trusted_first(self):
        self._addc(1, "ng", "ng", probe_ok=1, score=60.0)
        self._addc(2, "lv", "lv", probe_ok=0, score=None)
        self._addc(3, "mx", "mx", probe_ok=0, score=None)
        sel = [r["host"] for r in states.selectable_candidates(self.pool, {"role": None}, None)]
        self.assertEqual(sel[0], "lv")           # trusted сырой — первым, раньше пробованной ng
        # ng и mx обе low-trust; среди равной страны пробованный рабочий (ng) выше сырого (mx)
        self.assertEqual(sel, ["lv", "ng", "mx"])

    def _addc(self, ext_id, host, country, probe_ok=0, score=None, role="auto"):
        uid = self.pool.upsert_proxy(mk_norm(ext_id, host, country=country), role=role)
        self.pool.conn.execute("UPDATE proxy SET probe_ok=?, score=?, exit_cc=? WHERE uid=?",
                               (probe_ok, score, country, uid))
        self.pool.conn.commit()
        return uid


class TestBuyOnlyWhenPoolEmpty(unittest.TestCase):
    """Жёсткое правило владельца (снос №5): автоматика покупает ТОЛЬКО когда выбрать из
    пула нечего. Есть пригодные кандидаты (даже непробованные) -> покупки нет."""

    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.pool = pool_mod.Pool(self.db, server="test")
        self._orig_load = states.apply_mod.load_json
        states.apply_mod.load_json = lambda p: {"outbounds": [{"tag": "socks-out", "server": "9.9.9.9"}]}
        self.cfg = {"role": None, "singbox_config": "x",
                    "money": {"buy_enabled": True, "buy_period_days": 7, "buy_version": 4}}

    def tearDown(self):
        states.apply_mod.load_json = self._orig_load
        self.pool.close()
        os.unlink(self.db)

    def _addc(self, ext_id, host, country, probe_ok=0, score=None, role="auto"):
        uid = self.pool.upsert_proxy(mk_norm(ext_id, host, country=country), role=role)
        self.pool.conn.execute("UPDATE proxy SET probe_ok=?, score=?, exit_cc=? WHERE uid=?",
                               (probe_ok, score, country, uid))
        self.pool.conn.commit()
        return uid

    class _Prov:
        caps = {"buy": True}

        def __init__(self):
            self.bought = False

        def getcount(self, *a, **k):
            self.bought = True           # дошли до рынка — значит собирались купить
            return 0

    def test_replenish_refuses_when_unprobed_candidates_exist(self):
        self._addc(1, "1.1.1.1", "lv", probe_ok=0, score=None)   # сырой годный — есть из чего выбрать
        prov = self._Prov()
        r = states.try_replenish(self.cfg, {"proxy6": prov}, self.pool,
                                 _NullAlerter(), lambda *a: None, "auto")
        self.assertFalse(r["ok"])
        self.assertIn("непровер", r["reason"])
        self.assertFalse(prov.bought, "покупка не должна была даже дойти до рынка")

    def test_ensure_reserve_refuses_when_pool_has_candidates(self):
        self._addc(1, "1.1.1.1", "lv", probe_ok=0, score=None)
        self._addc(2, "2.2.2.2", "fi", probe_ok=0, score=None)
        prov = self._Prov()
        r = states.ensure_reserve(self.cfg, {"proxy6": prov}, self.pool,
                                  _NullAlerter(), lambda *a: None, "auto")
        self.assertFalse(r["bought"])
        self.assertGreaterEqual(r["have"], 1)
        self.assertFalse(prov.bought)

    def test_replenish_proceeds_when_only_blacklist_left(self):
        # в пуле только ru (чёрный список) -> выбирать нечего -> покупка допустима (дойдёт до рынка)
        self._addc(1, "1.1.1.1", "ru", probe_ok=1, score=90.0)
        prov = self._Prov()
        states.try_replenish(self.cfg, {"proxy6": prov}, self.pool,
                             _NullAlerter(), lambda *a: None, "auto")
        self.assertTrue(prov.bought, "пул из одного ru = выбирать нечего -> покупка идёт на рынок")


class _NullAlerter:
    def __getattr__(self, _):
        return lambda *a, **k: None


class TestEmergencyRestoreRoutes(unittest.TestCase):
    """EMERGENCY в базе, а прямой выход сбит (нет флага после ребута / middleman снова в tun0
    после переустановки) — чиним сразу, не дожидаясь 15-минутного окна (приёмка 15.08)."""

    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.pool = pool_mod.Pool(self.db, server="test")
        fd, self.flag = tempfile.mkstemp(suffix=".flag")
        os.close(fd)
        os.unlink(self.flag)                       # по умолчанию флага НЕТ
        self._orig = (states.EMERGENCY_FLAG, states.emergency_on, states._middleman_default)
        states.EMERGENCY_FLAG = self.flag
        self.on_calls = []
        states.emergency_on = lambda cfg, log=print: self.on_calls.append(cfg) or True
        self.route = "default via 198.51.100.1 dev ens3"      # по умолчанию — уже прямой
        states._middleman_default = lambda: self.route

    def tearDown(self):
        states.EMERGENCY_FLAG, states.emergency_on, states._middleman_default = self._orig
        self.pool.close()
        os.unlink(self.db)
        if os.path.exists(self.flag):
            os.unlink(self.flag)

    def _events(self):
        return self.pool.conn.execute(
            "SELECT result, detail FROM event WHERE action='emergency'").fetchall()

    def _set_flag(self):
        with open(self.flag, "w") as f:
            f.write("2026-08-15 12:00:00\n")

    def test_no_flag_restores_routes_and_logs(self):
        self.assertTrue(states.restore_emergency_routes({"gw": "1.1.1.1"}, self.pool, log=lambda *a: None))
        self.assertEqual(len(self.on_calls), 1, "emergency_on вызван ровно один раз")
        ev = self._events()
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0][0], "restore")
        self.assertIn("перезагрузки", ev[0][1])

    def test_flag_present_route_reset_restores(self):
        self._set_flag()
        self.route = "default dev tun0 scope link"           # boot-скрипт вернул tun0
        self.assertTrue(states.restore_emergency_routes({}, self.pool, log=lambda *a: None))
        self.assertEqual(len(self.on_calls), 1)
        self.assertIn("сброса маршрута", self._events()[0][1])

    def test_flag_present_route_direct_noop(self):
        self._set_flag()
        self.assertFalse(states.restore_emergency_routes({}, self.pool, log=lambda *a: None))
        self.assertEqual(self.on_calls, [])
        self.assertEqual(self._events(), [])

    def test_emergency_on_failed_no_event(self):
        states.emergency_on = lambda cfg, log=print: False    # не posix / не смогли
        self.assertFalse(states.restore_emergency_routes({}, self.pool, log=lambda *a: None))
        self.assertEqual(self._events(), [])


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
