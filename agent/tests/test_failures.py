# -*- coding: utf-8 -*-
"""Пакет F (П8): меньше ложных аварий, честные статусы, самовосстановление.

Полная лестница гоняется chaos-тестами на приёмке (§9); здесь — чистые решения
и компонентные ветки: backoff, фоновый fail_count, check-подсказка, why_kind
verify, дедуп алертов, «прокси жив — успокойся», TG≠канал, ручная авария.
"""
import datetime
import os
import tempfile
import unittest

import _ctx      # noqa: F401
import apply as apply_mod
import pool as pool_mod
import probe
import states


class _NullAlerter:
    def __getattr__(self, _):
        return lambda *a, **k: None


class _SpyAlerter:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def call(**kw):
            self.calls.append((name, kw))
            return True
        return call


class TestEmergencyBackoff(unittest.TestCase):
    def test_ladder_2_5_10_15_30(self):
        self.assertEqual(states.emergency_retry_delay(0), 120)
        self.assertEqual(states.emergency_retry_delay(1), 300)
        self.assertEqual(states.emergency_retry_delay(2), 600)
        self.assertEqual(states.emergency_retry_delay(3), 900)
        self.assertEqual(states.emergency_retry_delay(4), 1800)

    def test_cap_30_min(self):
        self.assertEqual(states.emergency_retry_delay(50), 1800)

    def test_garbage_is_first_step(self):
        self.assertEqual(states.emergency_retry_delay(None), 120)
        self.assertEqual(states.emergency_retry_delay("мусор"), 120)
        self.assertEqual(states.emergency_retry_delay(-3), 120)


class _DbBase(unittest.TestCase):
    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.pool = pool_mod.Pool(self.db, server="test")
        self.uid = self.pool.upsert_proxy({
            "provider": "proxy6", "ext_id": "1", "ip": "1.1.1.1", "host": "1.1.1.1",
            "port_http": 8080, "port_socks5": 1080, "user": "u", "password": "p",
            "country": "fi", "ip_version": 4, "kind": "dedicated",
            "date_end": None, "descr": ""})

    def tearDown(self):
        self.pool.close()
        os.unlink(self.db)


class TestBackgroundFailCount(_DbBase):
    """F5: одиночный фоновый (крон) провал не инкрементит fail_count."""

    def test_single_background_blip_not_counted(self):
        self.pool.record_probe(self.uid, {"ok": True, "socks_ok": True})
        self.pool.record_probe(self.uid, {"ok": False}, background=True)
        self.assertEqual(self.pool.get(self.uid)["fail_count"], 0, "первый чих — не считаем")

    def test_second_consecutive_background_fail_counted(self):
        self.pool.record_probe(self.uid, {"ok": False}, background=True)   # probe_ok был None
        self.assertEqual(self.pool.get(self.uid)["fail_count"], 0)
        self.pool.record_probe(self.uid, {"ok": False}, background=True)   # 2-й подряд
        self.assertEqual(self.pool.get(self.uid)["fail_count"], 1)
        self.pool.record_probe(self.uid, {"ok": False}, background=True)   # 3-й подряд
        self.assertEqual(self.pool.get(self.uid)["fail_count"], 2)

    def test_foreground_fail_always_counted(self):
        self.pool.record_probe(self.uid, {"ok": True, "socks_ok": True})
        self.pool.record_probe(self.uid, {"ok": False})
        self.assertEqual(self.pool.get(self.uid)["fail_count"], 1,
                         "ротация/ручная проба считает провал сразу")

    def test_success_resets_and_clears_cooldown(self):
        # F5: успешная проба снимает активный cooldown, а не только обнуляет счётчик
        self.pool.record_probe(self.uid, {"ok": False})
        self.pool.set_cooldown(self.uid, 7200)
        self.assertIsNotNone(self.pool.get(self.uid)["cooldown_until"])
        self.pool.record_probe(self.uid, {"ok": True, "socks_ok": True})
        row = self.pool.get(self.uid)
        self.assertEqual(row["fail_count"], 0)
        self.assertIsNone(row["cooldown_until"], "живой прокси не досиживает cooldown")

    def test_failed_probe_keeps_cooldown(self):
        self.pool.set_cooldown(self.uid, 7200)
        self.pool.record_probe(self.uid, {"ok": False})
        self.assertIsNotNone(self.pool.get(self.uid)["cooldown_until"])


class TestProviderCheckIsHint(unittest.TestCase):
    """F4: check?ids= false — подсказка; живая матрица побеждает мёртвый check."""

    def px(self):
        return {"host": "1.1.1.1", "port_socks5": 1080, "port_http": 8080,
                "user": "u", "password": "p"}

    def run_probe(self, matrix_alive, check_alive):
        orig_run, orig_geo = probe._run_curl, probe.geo_country_consensus
        try:
            def fake_curl(args, timeout=probe.CURL_TIMEOUT):
                if probe.IPIFY_URL in args:
                    return (0, "5.5.5.5") if matrix_alive else (0, "")
                if "%{http_code}" in args:
                    return (0, "204")
                return (0, "0.1")
            probe._run_curl = fake_curl
            probe.geo_country_consensus = lambda ip: {"cc": "fi", "alt": "fi", "agree": True}
            return probe.probe(self.px(), provider_check=lambda: check_alive)
        finally:
            probe._run_curl, probe.geo_country_consensus = orig_run, orig_geo

    def test_dead_check_alive_matrix_passes(self):
        res = self.run_probe(matrix_alive=True, check_alive=False)
        self.assertTrue(res["ok"], "API провайдера соврал — живой прокси не теряем")
        self.assertIsNone(res["disqualified"])
        self.assertEqual(res["provider_check"], False)

    def test_dead_check_dead_matrix_disqualified_with_mark(self):
        res = self.run_probe(matrix_alive=False, check_alive=False)
        self.assertFalse(res["ok"])
        self.assertEqual(res["disqualified"], "provider-check-dead+no-combo")

    def test_alive_check_dead_matrix_plain_no_combo(self):
        res = self.run_probe(matrix_alive=False, check_alive=True)
        self.assertEqual(res["disqualified"], "no-combo")


class TestVerifyWhyKind(unittest.TestCase):
    """F1: verify_egress различает «канал мёртв», «блок страны» и «мёртв только TG»."""

    def fake_verify(self, ip_out, geo_first, geo_consensus, tg_code):
        orig = (apply_mod.run_cmd, probe.geo_country, probe.geo_country_consensus)

        def fake_run(args, timeout=40):
            if probe.IPIFY_URL in args:
                return (0, ip_out)
            if probe.TG_URL in args:
                return (0, tg_code)
            return (0, "")
        try:
            apply_mod.run_cmd = fake_run
            probe.geo_country = lambda ip: geo_first
            probe.geo_country_consensus = lambda ip: geo_consensus
            return apply_mod.verify_egress()
        finally:
            apply_mod.run_cmd, probe.geo_country, probe.geo_country_consensus = orig

    def test_no_ip(self):
        v = self.fake_verify("", "fi", None, "204")
        self.assertFalse(v["ok"])
        self.assertEqual(v["why_kind"], "no-ip")

    def test_tg_only_dead(self):
        v = self.fake_verify("5.5.5.5", "fi", {"cc": "fi", "alt": "fi", "agree": True}, "000")
        self.assertFalse(v["ok"])
        self.assertEqual(v["why_kind"], "tg")
        self.assertEqual(v["egress_ip"], "5.5.5.5", "ipify жив — канал не мёртв")

    def test_blocked_confirmed_by_recheck(self):
        v = self.fake_verify("5.5.5.5", "ru", {"cc": "ru", "alt": "de", "agree": False}, "204")
        self.assertFalse(v["ok"])
        self.assertEqual(v["why_kind"], "blocked-cc", "любая база на повторе подтверждает блок")

    def test_blocked_refuted_by_recheck_passes(self):
        # первый вердикт «ru» оказался ложняком одной базы: повтор обеих даёт de/de
        v = self.fake_verify("5.5.5.5", "ru", {"cc": "de", "alt": "de", "agree": True}, "204")
        self.assertTrue(v["ok"])
        self.assertEqual(v["exit_cc"], "de")

    def test_all_alive_ok(self):
        v = self.fake_verify("5.5.5.5", "fi", {"cc": "fi", "alt": "fi", "agree": True}, "204")
        self.assertTrue(v["ok"])
        self.assertEqual(v["why_kind"], "")


class TestAlertDedup(_DbBase):
    """F7: no_funds/pool_empty/no_market — не чаще раза в 6 ч на причину."""

    def test_first_sends_second_muted(self):
        a = _SpyAlerter()
        self.assertTrue(states._alert_once(self.pool, a, "no_funds", detail="пусто"))
        self.assertFalse(states._alert_once(self.pool, a, "no_funds", detail="пусто"))
        self.assertEqual(len(a.calls), 1)

    def test_kinds_independent(self):
        a = _SpyAlerter()
        states._alert_once(self.pool, a, "no_funds", detail="x")
        states._alert_once(self.pool, a, "no_market", detail="y")
        self.assertEqual([c[0] for c in a.calls], ["no_funds", "no_market"])

    def test_resends_after_period(self):
        a = _SpyAlerter()
        states._alert_once(self.pool, a, "no_funds", detail="x")
        old = (datetime.datetime.now() - datetime.timedelta(hours=7)
               ).replace(microsecond=0).isoformat(sep=" ")
        self.pool.set_setting("alert_last:no_funds", old)
        self.assertTrue(states._alert_once(self.pool, a, "no_funds", detail="x"))
        self.assertEqual(len(a.calls), 2)


class TestManualEmergencySticks(_DbBase):
    """F7: ручная авария помечается manual; ручное снятие пишет verify в журнал."""

    def test_manual_flag_set_and_cleared(self):
        states.set_emergency({}, self.pool, _NullAlerter(), on=True, log=lambda *a: None)
        self.assertEqual(self.pool.get_setting("emergency_manual"), "1")
        self.assertEqual(self.pool.get_setting("automat_state"), states.EMERGENCY)
        states.set_emergency({}, self.pool, _NullAlerter(), on=False, log=lambda *a: None)
        self.assertIsNone(self.pool.get_setting("emergency_manual"))
        self.assertEqual(self.pool.get_setting("automat_state"), states.OK)

    def test_manual_off_logged(self):
        states.set_emergency({}, self.pool, _NullAlerter(), on=True, log=lambda *a: None)
        states.set_emergency({}, self.pool, _NullAlerter(), on=False, log=lambda *a: None)
        ev = self.pool.conn.execute(
            "SELECT detail FROM event WHERE action='emergency' AND result='off-manual'").fetchone()
        self.assertIsNotNone(ev)
        self.assertIn("выключен вручную", ev["detail"])

    def test_auto_enter_resets_backoff_counter(self):
        states._enter_emergency({}, self.pool, _NullAlerter(), "тест", lambda *a: None,
                                "auto", states.OK)
        self.assertEqual(self.pool.get_setting("emergency_retry_n"), "0")
        self.assertIsNone(self.pool.get_setting("emergency_manual"),
                          "авто-вход не помечается ручным")


class TestLeaveDirect(_DbBase):
    """Единый выход из прямого выхода: EMERGENCY шлёт recovered, ROTATING — тихий."""

    def setUp(self):
        super().setUp()
        self._orig = (states.emergency_off, states.apply_mod.load_json,
                      states.apply_mod.current_upstream)
        self.off_calls = []
        states.emergency_off = lambda cfg, log=print: self.off_calls.append(1) or True
        states.apply_mod.load_json = lambda p: {}
        states.apply_mod.current_upstream = lambda sb: "1.1.1.1"

    def tearDown(self):
        (states.emergency_off, states.apply_mod.load_json,
         states.apply_mod.current_upstream) = self._orig
        super().tearDown()

    def test_emergency_leave_sends_recovered(self):
        a = _SpyAlerter()
        self.pool.set_setting("emergency_retry_n", "3")
        states._leave_direct({"singbox_config": "x"}, self.pool, a,
                             {"egress_ip": "5.5.5.5", "exit_cc": "fi"},
                             lambda *a_: None, "auto", states.EMERGENCY)
        self.assertEqual(len(self.off_calls), 1)
        self.assertEqual([c[0] for c in a.calls], ["recovered"])
        self.assertIsNone(self.pool.get_setting("emergency_retry_n"), "backoff сброшен")

    def test_rotating_leave_quiet(self):
        a = _SpyAlerter()
        self.pool.set_setting("rotating_since", "2026-08-17 10:00:00")
        states._leave_direct({"singbox_config": "x"}, self.pool, a,
                             {"egress_ip": "5.5.5.5"}, lambda *a_: None, "auto", states.ROTATING)
        self.assertEqual(a.calls, [], "ROTATING входил без письма — выходит тоже тихо")
        self.assertIsNone(self.pool.get_setting("rotating_since"))
        ev = self.pool.conn.execute(
            "SELECT result FROM event WHERE action='rotating'").fetchone()
        self.assertEqual(ev["result"], "off")


class TestCalmRetune(_DbBase):
    """F2: прокси жив + конфиг оптимален = успех цикла (рестарт), не ротация."""

    def setUp(self):
        super().setUp()
        self._orig = (states.apply_mod.load_json, states.apply_mod.current_upstream,
                      states.probe_mod.probe, states.apply_mod.restart_singbox,
                      states.apply_mod.wait_tun0, states.apply_mod.verify_egress)
        states.apply_mod.load_json = lambda p: {
            "outbounds": [
                {"tag": "socks-out", "type": "socks", "server": "1.1.1.1", "server_port": 1080,
                 "username": "u", "password": "p", "version": "5"},
                {"tag": "http-tg", "type": "http", "server": "1.1.1.1", "server_port": 8080,
                 "username": "u", "password": "p"}]}
        states.apply_mod.current_upstream = lambda sb: "1.1.1.1"
        states.probe_mod.probe = lambda row, provider_check=None, latency_runs=3: {
            "ok": True, "disqualified": None, "socks_ok": True, "http_ok": True,
            "socks_port": 1080, "http_port": 8080, "exit_ip": "5.5.5.5", "exit_cc": "fi",
            "exit_cc_alt": "fi", "geo_agree": True, "tg_ok": True, "latency_ms": 100}
        self.restarts = []
        states.apply_mod.restart_singbox = lambda: self.restarts.append(1) or True
        states.apply_mod.wait_tun0 = lambda timeout=30: True
        self.verify_after = {"ok": True, "egress_ip": "5.5.5.5", "exit_cc": "fi",
                             "tg_code": "204", "why": "", "why_kind": ""}
        states.apply_mod.verify_egress = lambda: self.verify_after

    def tearDown(self):
        (states.apply_mod.load_json, states.apply_mod.current_upstream,
         states.probe_mod.probe, states.apply_mod.restart_singbox,
         states.apply_mod.wait_tun0, states.apply_mod.verify_egress) = self._orig
        super().tearDown()

    def run_retune(self):
        return states.try_retune({"singbox_config": "x"}, {}, self.pool,
                                 _NullAlerter(), lambda *a: None, "auto")

    def test_calm_success_no_rotation(self):
        r = self.run_retune()
        self.assertTrue(r["ok"])
        self.assertTrue(r.get("calm"))
        self.assertEqual(len(self.restarts), 1, "рестарт sing-box был")
        ev = self.pool.conn.execute(
            "SELECT result FROM event WHERE action='retune'").fetchone()
        self.assertEqual(ev["result"], "calm")

    def test_calm_failed_flagged_for_escalation(self):
        self.verify_after = {"ok": False, "egress_ip": None, "exit_cc": None,
                             "tg_code": None, "why": "egress через tun0 пуст",
                             "why_kind": "no-ip"}
        r = self.run_retune()
        self.assertFalse(r["ok"])
        self.assertTrue(r.get("calm_failed"),
                        "признак для предохранителя F2 (3 подряд -> ROTATING)")


class TestFrozenKeepsState(_DbBase):
    """Ревью 1.3.0 (1.1): пауза/FROZEN_NET не затирают EMERGENCY/ROTATING —
    иначе прямой WAN-выход с флагом осиротеет навсегда."""

    def setUp(self):
        super().setUp()
        self._orig_restore = states.restore_emergency_routes
        self.restores = []
        states.restore_emergency_routes = (
            lambda cfg, pool, log=print, actor="auto": self.restores.append(1) or False)

    def tearDown(self):
        states.restore_emergency_routes = self._orig_restore
        super().tearDown()

    def run_rotate(self):
        return states.rotate({}, {}, self.pool, _NullAlerter(), log=lambda *a: None)

    def test_pause_does_not_bury_emergency(self):
        self.pool.set_setting("automat_frozen", "1")
        self.pool.set_setting("automat_state", states.EMERGENCY)
        r = self.run_rotate()
        self.assertEqual(r["state"], states.EMERGENCY, "состояние отдаётся честно")
        self.assertEqual(self.pool.get_setting("automat_state"), states.EMERGENCY,
                         "EMERGENCY переживает паузу — прямой выход не осиротеет")
        self.assertEqual(len(self.restores), 1,
                         "прямой выход поддерживается и на паузе (ребут не даст чёрную дыру)")

    def test_pause_does_not_bury_rotating(self):
        self.pool.set_setting("automat_frozen", "1")
        self.pool.set_setting("automat_state", states.ROTATING)
        self.run_rotate()
        self.assertEqual(self.pool.get_setting("automat_state"), states.ROTATING)

    def test_pause_plain_ok_stays_ok(self):
        self.pool.set_setting("automat_frozen", "1")
        r = self.run_rotate()
        self.assertEqual(r["state"], states.OK)
        self.assertEqual(self.restores, [], "без прямого выхода восстанавливать нечего")


class TestSyncDegraded(_DbBase):
    """Ревью 1.3.0 (1.2): DEGRADED от автоматики + снятие залипших чипов —
    лёгкая синхронизация из pool-refresh/egress-mark, без полного rotate."""

    def tg_verify(self):
        return {"ok": False, "egress_ip": "5.5.5.5", "exit_cc": "fi", "tg_code": "000",
                "why": "Telegram-проба через tun0 не прошла (код 000)", "why_kind": "tg"}

    def ok_verify(self):
        return {"ok": True, "egress_ip": "5.5.5.5", "exit_cc": "fi", "tg_code": "204",
                "why": "", "why_kind": ""}

    def test_full_verify_sets_degraded_and_alerts_once(self):
        a = _SpyAlerter()
        for _ in range(4):
            st = states.sync_degraded_state(self.pool, self.tg_verify(), alerter=a)
        self.assertEqual(st, states.DEGRADED)
        self.assertEqual(self.pool.get_setting("automat_state"), states.DEGRADED)
        self.assertEqual([c[0] for c in a.calls], ["tg_degraded"], "письмо один раз, после 3 подряд")

    def test_ok_verify_clears_stuck_degraded(self):
        self.pool.set_setting("automat_state", states.DEGRADED)
        self.pool.set_setting("tg_fail_streak", "5")
        st = states.sync_degraded_state(self.pool, self.ok_verify())
        self.assertEqual(st, states.OK)
        self.assertEqual(self.pool.get_setting("automat_state"), states.OK)
        self.assertIsNone(self.pool.get_setting("tg_fail_streak"))

    def test_light_mark_clears_suspect_but_not_degraded(self):
        self.pool.set_setting("automat_state", states.SUSPECT)
        states.sync_degraded_state(self.pool, self.ok_verify(), light=True)
        self.assertEqual(self.pool.get_setting("automat_state"), states.OK)
        # DEGRADED light-меткой НЕ снимается: она TG не меряет — снимет полный verify
        self.pool.set_setting("automat_state", states.DEGRADED)
        states.sync_degraded_state(self.pool, self.ok_verify(), light=True)
        self.assertEqual(self.pool.get_setting("automat_state"), states.DEGRADED)
        # и light-провал состояний не ставит
        self.pool.set_setting("automat_state", states.OK)
        states.sync_degraded_state(self.pool, {"ok": False, "why_kind": ""}, light=True)
        self.assertEqual(self.pool.get_setting("automat_state"), states.OK)

    def test_never_touches_emergency_or_rotating(self):
        for st0 in (states.EMERGENCY, states.ROTATING, states.FROZEN_NET):
            self.pool.set_setting("automat_state", st0)
            states.sync_degraded_state(self.pool, self.tg_verify())
            self.assertEqual(self.pool.get_setting("automat_state"), st0)
            states.sync_degraded_state(self.pool, self.ok_verify())
            self.assertEqual(self.pool.get_setting("automat_state"), st0,
                             "EMERGENCY/ROTATING правит только rotate")


class TestTgDegraded(_DbBase):
    """F1: ipify жив + TG мёртв -> DEGRADED; письмо после 3 подряд, один раз."""

    def setUp(self):
        super().setUp()
        self._orig_retune = states.try_retune
        states.try_retune = lambda *a, **k: {"ok": False, "why": "нет"}
        self.egress = {"ok": False, "egress_ip": "5.5.5.5", "exit_cc": "fi",
                       "tg_code": "000", "why": "Telegram-проба через tun0 не прошла (код 000)",
                       "why_kind": "tg"}

    def tearDown(self):
        states.try_retune = self._orig_retune
        super().tearDown()

    def run_tg(self, state_before=states.OK, alerter=None):
        result = {"state": None, "action": None, "detail": "", "ok": False}
        return states._tg_degraded({"singbox_config": "x"}, {}, self.pool,
                                   alerter or _NullAlerter(), result, self.egress,
                                   lambda *a: None, "auto", state_before)

    def test_degraded_not_rotating(self):
        r = self.run_tg()
        self.assertEqual(r["state"], states.DEGRADED)
        self.assertEqual(self.pool.get_setting("automat_state"), states.DEGRADED)
        self.assertEqual(self.pool.get_setting("tg_fail_streak"), "1")

    def test_alert_on_third_streak_only_once(self):
        a = _SpyAlerter()
        self.run_tg(alerter=a)
        self.run_tg(alerter=a)
        self.assertEqual(a.calls, [], "до 3 подряд — молчим")
        self.run_tg(alerter=a)
        self.assertEqual([c[0] for c in a.calls], ["tg_degraded"])
        self.run_tg(alerter=a)
        self.assertEqual(len(a.calls), 1, "письмо один раз на стрик")
        ev = self.pool.conn.execute(
            "SELECT COUNT(*) FROM event WHERE action='degraded'").fetchone()[0]
        self.assertEqual(ev, 1)

    def test_retune_win_resets_streak(self):
        self.run_tg()
        states.try_retune = lambda *a, **k: {"ok": True, "verify": self.egress,
                                             "detail": "RETUNE ок"}
        r = self.run_tg()
        self.assertEqual(r["state"], states.OK)
        self.assertIsNone(self.pool.get_setting("tg_fail_streak"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
