# -*- coding: utf-8 -*-
"""Система обновлений (vpn/UPDATE-PLAN.md): версия узла, маяк, check.

Версия — это то, с чем сверяется автообновление и что видит человек в панели,
поэтому фиксируем: чтение VERSION терпит отсутствие/пустоту/BOM, парсер принимает
ТОЛЬКО строгий X.Y.Z, «новее» значит строго больше (анти-даунгрейд), проверка
маяка уведомляет о каждой версии ровно один раз и не считает сетевую ошибку
аварией, а UPDATE-режим setup.sh выводит параметры из живого config.json.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import _ctx      # noqa: F401  (добавляет panel/ в sys.path)
import update

PANEL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# приватная раскладка: install/setup.sh; публичная: setup.sh в корне репозитория —
# тесты должны гоняться и у публичных пользователей (ревью 17.08)
_SETUP_CANDS = (os.path.join(PANEL_DIR, os.pardir, "install", "setup.sh"),
                os.path.join(PANEL_DIR, os.pardir, "setup.sh"))
SETUP_SH = next((p for p in _SETUP_CANDS if os.path.isfile(p)), _SETUP_CANDS[0])
PROFILES_PY = os.path.join(PANEL_DIR, os.pardir, "install", "profiles.py")


class FakePool:
    def __init__(self):
        self.events = []

    def log_event(self, action, **kw):
        self.events.append((action, kw))


class FakeAlerter:
    def __init__(self, configured=True, ok=True):
        self.sent = []
        self.configured = configured
        self.ok = ok

    def send(self, subject, body):
        self.sent.append((subject, body))
        return self.ok


class TestNodeVersion(unittest.TestCase):
    def _tmp(self, content):
        fd, path = tempfile.mkstemp(suffix=".version")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return path

    def test_reads_and_strips(self):
        p = self._tmp("1.2.3\n")
        self.assertEqual(update.node_version(paths=[p]), "1.2.3")

    def test_missing_file_is_none(self):
        self.assertIsNone(update.node_version(paths=[os.path.join(tempfile.gettempdir(),
                                                                  "нет-такого-file.version")]))

    def test_empty_file_falls_through_to_next(self):
        empty, real = self._tmp("   \n"), self._tmp("1.0.7\n")
        self.assertEqual(update.node_version(paths=[empty, real]), "1.0.7")

    def test_all_bad_is_none(self):
        self.assertIsNone(update.node_version(paths=[self._tmp("")]))

    def test_bom_and_extra_lines_tolerated(self):
        # Блокнот мог пересохранить с BOM, человек — дописать строку: версия всё
        # равно должна читаться (иначе сравнение версий молча умирает, ревью Ф0).
        p = self._tmp("\ufeff1.2.3\n# приписка\n")
        self.assertEqual(update.node_version(paths=[p]), "1.2.3")

    def test_default_paths_find_dev_version(self):
        # На dev-машине рядом с panel/ лежит vpn/VERSION — версия должна читаться
        # без каких-либо аргументов (это же путь и для /opt/vpn-panel/VERSION на узле).
        v = update.node_version()
        self.assertIsNotNone(v)
        self.assertIsNotNone(update.parse_version(v), "vpn/VERSION должен быть строгим X.Y.Z")


class TestSemver(unittest.TestCase):
    def test_parse_ok(self):
        self.assertEqual(update.parse_version("1.2.3"), (1, 2, 3))
        self.assertEqual(update.parse_version(" 10.0.99 \n"), (10, 0, 99))

    def test_parse_rejects_non_semver(self):
        for bad in ("", None, "1.2", "1.2.3.4", "v1.2.3", "1.2.3-rc1", "абв", "1..3"):
            self.assertIsNone(update.parse_version(bad), bad)

    def test_newer_is_strictly_greater(self):
        self.assertTrue(update.is_newer("1.2.1", "1.2.0"))
        self.assertTrue(update.is_newer("1.10.0", "1.9.9"))     # числами, не строками
        self.assertFalse(update.is_newer("1.2.0", "1.2.0"))     # равная — не обновление
        self.assertFalse(update.is_newer("1.1.9", "1.2.0"))     # даунгрейд — никогда

    def test_newer_with_unparsable_is_false(self):
        # Непонятная версия с ЛЮБОЙ стороны = не обновляемся (лучше «?» в панели,
        # чем прыжок «непонятно с чего непонятно на что»).
        self.assertFalse(update.is_newer("боевая", "1.0.0"))
        self.assertFalse(update.is_newer("1.0.1", None))
        self.assertFalse(update.is_newer(None, None))


class TestUpdateCfg(unittest.TestCase):
    def test_defaults(self):
        u = update.update_cfg({})
        self.assertTrue(u["auto"])
        self.assertEqual(u["window"], "04:00-06:00")
        self.assertEqual(u["repo"], update.DEFAULT_REPO)

    def test_owner_overrides_and_sanitize(self):
        u = update.update_cfg({"update": {"auto": 0, "window": "02:00-03:00",
                                          "repo": "  my/fork  "}})
        self.assertFalse(u["auto"])
        self.assertEqual(u["window"], "02:00-03:00")
        self.assertEqual(u["repo"], "my/fork")

    def test_garbage_block_ignored(self):
        for raw in (None, "строка", 42, []):
            u = update.update_cfg({"update": raw})
            self.assertTrue(u["auto"], raw)
        u = update.update_cfg({"update": {"repo": "", "неведомый_ключ": 1}})
        self.assertEqual(u["repo"], update.DEFAULT_REPO)
        self.assertNotIn("неведомый_ключ", u)


class TestStateAndCheck(unittest.TestCase):
    """check(): состояние, событие и письмо — ровно один раз на версию."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="upd-test-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.cfg = {"server": "test", "db": os.path.join(self.dir, "state.db")}
        self._orig_fetch = update.fetch_text
        self._orig_node = update.node_version
        update.node_version = lambda paths=None: "1.2.0"
        self.addCleanup(self._restore)
        self.pool, self.alerter = FakePool(), FakeAlerter()

    def _restore(self):
        update.fetch_text = self._orig_fetch
        update.node_version = self._orig_node

    def _beacon(self, value):
        if isinstance(value, Exception):
            def f(url, **kw):
                raise value
        else:
            def f(url, **kw):
                return value
        update.fetch_text = f

    def test_state_roundtrip_and_missing(self):
        self.assertEqual(update.load_state(self.cfg), {})
        update.save_state(self.cfg, {"a": 1})
        self.assertEqual(update.load_state(self.cfg), {"a": 1})
        with open(update.state_path(self.cfg), "w", encoding="utf-8") as f:
            f.write("{битый json")
        self.assertEqual(update.load_state(self.cfg), {})   # битый файл = пустое состояние

    def test_check_asks_the_api_source_first(self):
        asked = []
        def f(url, **kw):
            asked.append(url)
            return "1.3.0"
        update.fetch_text = f
        update.check(self.cfg, pool=self.pool, alerter=self.alerter)
        self.assertTrue(asked[0].startswith("https://api.github.com/repos/"), asked)

    def test_newer_notifies_once(self):
        self._beacon("1.3.0\n")
        r1 = update.check(self.cfg, pool=self.pool, alerter=self.alerter)
        self.assertTrue(r1["newer"])
        self.assertEqual(len(self.alerter.sent), 1)
        self.assertIn("1.3.0", self.alerter.sent[0][0])
        self.assertEqual(self.pool.events[0][0], "update-available")
        r2 = update.check(self.cfg, pool=self.pool, alerter=self.alerter)
        self.assertTrue(r2["newer"])
        self.assertEqual(len(self.alerter.sent), 1)         # повторного письма нет
        self.assertEqual(len(self.pool.events), 1)
        st = update.load_state(self.cfg)
        self.assertEqual(st["latest_seen"], "1.3.0")
        self.assertIn("1.3.0", st["notified_versions"])
        self.assertIn("1.3.0", st["mailed_versions"])

    def test_smtp_failure_retries_mail_next_check(self):
        # Разовый сбой почты не должен терять письмо о версии НАВСЕГДА (ревью Ф1):
        # отметка «отправлено» ставится только по факту send()==True.
        self._beacon("1.3.0")
        self.alerter.ok = False
        update.check(self.cfg, pool=self.pool, alerter=self.alerter)
        self.assertEqual(len(self.alerter.sent), 1)          # попытка была
        self.assertNotIn("1.3.0", update.load_state(self.cfg).get("mailed_versions") or [])
        self.alerter.ok = True
        update.check(self.cfg, pool=self.pool, alerter=self.alerter)
        self.assertEqual(len(self.alerter.sent), 2)          # почта ожила — письмо дошло
        self.assertIn("1.3.0", update.load_state(self.cfg)["mailed_versions"])
        update.check(self.cfg, pool=self.pool, alerter=self.alerter)
        self.assertEqual(len(self.alerter.sent), 2)          # и больше не шлём
        self.assertEqual(len(self.pool.events), 1)           # событие журнала — одно

    def test_unconfigured_smtp_does_not_retry_forever(self):
        self._beacon("1.3.0")
        quiet = FakeAlerter(configured=False)
        update.check(self.cfg, pool=self.pool, alerter=quiet)
        self.assertEqual(quiet.sent, [])                     # send даже не дёргали
        self.assertIn("1.3.0", update.load_state(self.cfg)["mailed_versions"])

    def test_beacon_flip_does_not_respam(self):
        # Маяк подняли до 1.4.0, откатили на 1.3.0 и вернули: об уже уведомлённых
        # версиях второй раз не жужжим (список, не скаляр — ревью Ф1).
        self._beacon("1.3.0")
        update.check(self.cfg, pool=self.pool, alerter=self.alerter)
        self._beacon("1.4.0")
        update.check(self.cfg, pool=self.pool, alerter=self.alerter)
        self.assertEqual(len(self.alerter.sent), 2)
        self._beacon("1.3.0")
        update.check(self.cfg, pool=self.pool, alerter=self.alerter)
        self._beacon("1.4.0")
        update.check(self.cfg, pool=self.pool, alerter=self.alerter)
        self.assertEqual(len(self.alerter.sent), 2)          # повторов нет
        self.assertEqual(len(self.pool.events), 2)

    def test_same_version_is_quiet(self):
        self._beacon("1.2.0")
        r = update.check(self.cfg, pool=self.pool, alerter=self.alerter)
        self.assertFalse(r["newer"])
        self.assertEqual(self.alerter.sent, [])
        self.assertEqual(self.pool.events, [])

    def test_network_error_is_data_not_crash(self):
        self._beacon(update.UpdateError("маяк недоступен — curl rc=6", network=True))
        r = update.check(self.cfg, pool=self.pool, alerter=self.alerter)
        self.assertIn("недоступен", r["error"])
        self.assertFalse(r["newer"])
        st = update.load_state(self.cfg)
        self.assertIn("last_check", st)
        self.assertIn("недоступен", st["last_error"])
        # после ошибки маяк ожил — last_error должен очиститься
        self._beacon("1.2.0")
        update.check(self.cfg)
        self.assertIsNone(update.load_state(self.cfg)["last_error"])

    def test_garbage_beacon_is_error(self):
        self._beacon("<html>расчехлился прокси-портал</html>")
        r = update.check(self.cfg, pool=self.pool, alerter=self.alerter)
        self.assertIsNotNone(r["error"])
        self.assertFalse(r["newer"])
        self.assertEqual(self.alerter.sent, [])

    def test_bad_version_no_letter(self):
        update.save_state(self.cfg, {"bad_versions": ["1.3.0"]})
        self._beacon("1.3.0")
        r = update.check(self.cfg, pool=self.pool, alerter=self.alerter)
        self.assertTrue(r["newer"])
        self.assertTrue(r["bad"])
        self.assertEqual(self.alerter.sent, [])             # на проблемную не зовём
        self.assertEqual(self.pool.events, [])

    def test_downgrade_beacon_is_not_newer(self):
        self._beacon("1.0.0")
        r = update.check(self.cfg, pool=self.pool, alerter=self.alerter)
        self.assertFalse(r["newer"])
        self.assertEqual(self.alerter.sent, [])


class TestFetchTransport(unittest.TestCase):
    """fetch_text: напрямую -> через tun0, подсказка транспорта общая с провайдерами."""

    def setUp(self):
        from providers import base
        self.base = base
        self._orig = (update._curl, base._tun0_alive, base.TRANSPORT_HINT)
        fd, self.hint = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(self.hint)
        base.TRANSPORT_HINT = self.hint
        base.reset_transport_for_tests()
        self.calls = []
        base._tun0_alive = lambda: True
        self.addCleanup(self._restore)

    def _restore(self):
        update._curl, self.base._tun0_alive, self.base.TRANSPORT_HINT = self._orig
        self.base.reset_transport_for_tests()
        if os.path.exists(self.hint):
            os.unlink(self.hint)

    def _curl_fake(self, results):
        def f(url, args=(), timeout=20, iface=None):
            tr = "tun0" if iface == "tun0" else "direct"
            self.calls.append(tr)
            return results.get(tr, (7, "", "connect refused"))
        update._curl = f

    def test_direct_ok(self):
        self._curl_fake({"direct": (0, "1.2.3\n", "")})
        self.assertEqual(update.fetch_text("http://x"), "1.2.3\n")
        self.assertEqual(self.calls, ["direct"])

    def test_beacon_prefers_api_over_cached_raw(self):
        """Грабля 15.08 и 22.08: raw.githubusercontent держит VERSION 5 минут
        (Fastly, max-age=300, копия на каждом узле CDN), и сразу после публикации
        узел видит СТАРУЮ версию. Cache-buster в query там не работает — проверено
        22.08: ответ приходит с X-Cache: HIT. Поэтому спрашиваем Contents API
        (max-age=60), а raw остаётся запасным."""
        seen = []
        def f(url, args=(), timeout=20, iface=None):
            seen.append((url, list(args)))
            return 0, "9.9.9", ""
        update._curl = f
        self.assertEqual(update.fetch_beacon("owner/repo"), "9.9.9")
        url, args = seen[0]
        self.assertEqual(url, "https://api.github.com/repos/owner/repo/contents/VERSION?ref=main")
        self.assertIn("Accept: application/vnd.github.raw", args)
        self.assertIn("Cache-Control: no-cache", args)
        self.assertIn("Pragma: no-cache", args)
        self.assertEqual(len(seen), 1, "запасной источник дёргать незачем — API ответил")

    def test_beacon_falls_back_to_raw_when_api_fails(self):
        answers = {"api.github.com": (22, "", "rate limit"),
                   "raw.githubusercontent.com": (0, "9.9.9", "")}
        seen = []
        def f(url, args=(), timeout=20, iface=None):
            host = url.split("/")[2]
            seen.append(host)
            return answers[host]
        update._curl = f
        self.assertEqual(update.fetch_beacon("owner/repo"), "9.9.9")
        # API пробуется обоими транспортами (direct -> tun0), и лишь потом raw
        self.assertEqual(seen[0], "api.github.com")
        self.assertEqual(seen[-1], "raw.githubusercontent.com")
        self.assertEqual(seen.count("raw.githubusercontent.com"), 1)

    def test_beacon_json_instead_of_version_is_not_fatal(self):
        """API без нужного Accept отдаёт JSON — это отказ источника, а не проверки."""
        def f(url, args=(), timeout=20, iface=None):
            if url.startswith("https://api."):
                return 0, '{"name":"VERSION","encoding":"base64"}', ""
            return 0, "9.9.9", ""
        update._curl = f
        self.assertEqual(update.fetch_beacon("owner/repo"), "9.9.9")

    def test_beacon_all_sources_dead_is_one_error(self):
        def f(url, args=(), timeout=20, iface=None):
            return 7, "", "connect refused"
        update._curl = f
        with self.assertRaises(update.UpdateError) as cm:
            update.fetch_beacon("owner/repo")
        self.assertTrue(cm.exception.network)
        self.assertIn("маяк недоступен", str(cm.exception))

    def test_fallback_to_tun0_and_hint_saved(self):
        self._curl_fake({"direct": (7, "", "refused"), "tun0": (0, "1.2.3", "")})
        self.assertEqual(update.fetch_text("http://x"), "1.2.3")
        self.assertEqual(self.calls, ["direct", "tun0"])
        self.assertEqual(self.base.preferred_transport(), "tun0")   # запомнили

    def test_tun0_dead_no_fallback(self):
        self.base._tun0_alive = lambda: False
        self._curl_fake({"direct": (6, "", "dns fail")})
        with self.assertRaises(update.UpdateError) as cm:
            update.fetch_text("http://x")
        self.assertTrue(cm.exception.network)
        self.assertEqual(self.calls, ["direct"])


class TestApplyOrchestration(unittest.TestCase):
    """apply(): бэкап -> UPDATE=1 setup.sh -> verify -> commit/rollback.

    Системные шаги (скачивание, запуск инсталлятора, здоровье) замоканы; проверяем
    ОРКЕСТРАЦИЮ: какие деревья куда переехали, какой setup.sh гонялся, что попало
    в состояние/журнал/письма. Это самая рискованная часть плана (Ф2 §4.2)."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="upd-apply-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.cfg = {"server": "test", "db": os.path.join(self.dir, "state.db")}
        self._paths = {}
        for name, sub in (("REDUT_SRC", "src"), ("REDUT_PREV", "prev"), ("REDUT_NEW", "new"),
                          ("LOCK_PATH", "lock"), ("STATUS_PATH", "status.json")):
            self._paths[name] = getattr(update, name)
            setattr(update, name, os.path.join(self.dir, sub))
        self._origs = (update.download_tree, update._run_setup, update.baseline_health,
                       update.verify_health, update.node_version)
        update.baseline_health = lambda cfg: {"units": {"sing-box": True, "vpn-panel": True},
                                              "peers": 2, "panel": True}
        self.setup_runs, self.setup_rc, self.verify_q = [], [], []
        update.download_tree = self._fake_download
        update._run_setup = self._fake_setup
        update.verify_health = lambda cfg, baseline, **kw: self.verify_q.pop(0)
        # node_version БЕЗ путей — версия узла (мок); С путями — честное чтение
        # (оркестрация читает VERSION деревьев: защита от полуустановки, ревью 17.08)
        real_nv = self._origs[4]
        update.node_version = lambda paths=None: ("1.2.0" if paths is None
                                                  else real_nv(paths=paths))
        # старое дерево узла
        self._mktree(update.REDUT_SRC, "1.2.0")
        self.pool, self.alerter = FakePool(), FakeAlerter()
        self.addCleanup(self._restore)

    def _restore(self):
        (update.download_tree, update._run_setup, update.baseline_health,
         update.verify_health, update.node_version) = self._origs
        for name, val in self._paths.items():
            setattr(update, name, val)

    @staticmethod
    def _mktree(path, version):
        os.makedirs(os.path.join(path, "install"), exist_ok=True)
        with open(os.path.join(path, "VERSION"), "w", encoding="utf-8") as f:
            f.write(version + "\n")
        with open(os.path.join(path, "setup.sh"), "w", encoding="utf-8") as f:
            f.write('#!/bin/bash\nUPDATE="${UPDATE:-0}"\n')   # дерево «умеет UPDATE»
        with open(os.path.join(path, "install", "install.sh"), "w", encoding="utf-8") as f:
            f.write("#!/bin/bash\n")

    def _fake_download(self, repo, version, dest=None, log=None):
        dest = dest or update.REDUT_NEW
        self._mktree(dest, version)
        return dest

    def _fake_setup(self, tree, log):
        with open(os.path.join(tree, "VERSION"), encoding="utf-8") as f:
            self.setup_runs.append(f.read().strip())
        return (self.setup_rc.pop(0) if self.setup_rc else 0), ""

    def _tree_ver(self, path):
        with open(os.path.join(path, "VERSION"), encoding="utf-8") as f:
            return f.read().strip()

    def test_success_path(self):
        self.verify_q[:] = [(True, "")]
        r = update.apply(self.cfg, pool=self.pool, alerter=self.alerter, target="1.3.0", manual=True)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.setup_runs, ["1.3.0"])          # гонялся setup.sh нового дерева
        self.assertEqual(self._tree_ver(update.REDUT_SRC), "1.3.0")
        self.assertEqual(self._tree_ver(update.REDUT_PREV), "1.2.0")   # прежнее — цель отката
        st = update.load_state(self.cfg)
        self.assertTrue(st["last_apply"]["ok"])
        self.assertEqual(st["last_apply"]["to"], "1.3.0")
        self.assertEqual([e[0] for e in self.pool.events], ["update-apply"])
        self.assertEqual(len(self.alerter.sent), 1)
        self.assertIn("обновлён", self.alerter.sent[0][0])
        self.assertEqual((update.status_read() or {}).get("phase"), "done")

    def test_verify_fail_rolls_back(self):
        self.verify_q[:] = [(False, "панель не отвечает по HTTPS"), (True, "")]
        r = update.apply(self.cfg, pool=self.pool, alerter=self.alerter, target="1.3.0", manual=True)
        self.assertFalse(r["ok"])
        self.assertTrue(r["rolled_back"], r)
        self.assertEqual(self.setup_runs, ["1.3.0", "1.2.0"])  # установка, затем откат
        self.assertEqual(self._tree_ver(update.REDUT_SRC), "1.2.0")   # узел снова на старом
        self.assertEqual(self._tree_ver(update.REDUT_SRC + ".failed"), "1.3.0")  # битое — для разбора
        st = update.load_state(self.cfg)
        self.assertIn("1.3.0", st["bad_versions"])
        self.assertFalse(st["last_apply"]["ok"])
        self.assertTrue(st["last_apply"]["rolled_back"])
        self.assertEqual([e[0] for e in self.pool.events], ["update-fail"])
        self.assertEqual(len(self.alerter.sent), 1)
        self.assertIn("🔴", self.alerter.sent[0][0])
        self.assertEqual((update.status_read() or {}).get("phase"), "failed")

    def test_setup_rc_nonzero_rolls_back(self):
        self.setup_rc[:] = [1, 0]
        self.verify_q[:] = [(True, "")]                        # verify — только для отката
        r = update.apply(self.cfg, pool=self.pool, alerter=self.alerter, target="1.3.0", manual=True)
        self.assertFalse(r["ok"])
        self.assertTrue(r["rolled_back"])
        self.assertIn("setup.sh", r["why"])
        self.assertEqual(self.setup_runs, ["1.3.0", "1.2.0"])

    def test_rollback_failure_is_reported(self):
        self.verify_q[:] = [(False, "sing-box check не прошёл: kaput"), (False, "всё ещё плохо")]
        r = update.apply(self.cfg, pool=self.pool, alerter=self.alerter, target="1.3.0", manual=True)
        self.assertFalse(r["ok"])
        self.assertFalse(r["rolled_back"])
        self.assertIn("ОТКАТ НЕ ПОДТВЕРДИЛСЯ", self.alerter.sent[0][1])

    def test_not_newer_refused_before_download(self):
        r = update.apply(self.cfg, pool=self.pool, alerter=self.alerter, target="1.2.0", manual=True)
        self.assertFalse(r["ok"])
        self.assertIn("не новее", r["why"])
        self.assertEqual(self.setup_runs, [])
        self.assertFalse(os.path.isdir(update.REDUT_PREV))     # ничего не двигали

    def test_bad_version_blocks_auto_but_not_manual(self):
        update.save_state(self.cfg, {"bad_versions": ["1.3.0"]})
        r = update.apply(self.cfg, pool=self.pool, alerter=self.alerter, target="1.3.0", manual=False)
        self.assertFalse(r["ok"])
        self.assertIn("чёрном списке", r["why"])
        self.verify_q[:] = [(True, "")]
        r2 = update.apply(self.cfg, pool=self.pool, alerter=self.alerter, target="1.3.0", manual=True)
        self.assertTrue(r2["ok"], r2)                          # руками — можно

    def test_auto_requires_healthy_baseline(self):
        update.baseline_health = lambda cfg: {"units": {"sing-box": False, "vpn-panel": True},
                                              "peers": 0, "panel": True}
        r = update.apply(self.cfg, pool=self.pool, alerter=self.alerter, target="1.3.0", manual=False)
        self.assertFalse(r["ok"])
        self.assertIn("нездоров", r["why"])
        self.assertEqual(self.setup_runs, [])

    def test_download_network_error_no_letter(self):
        def boom(repo, version, dest=None, log=None):
            raise update.UpdateError("артефакт не скачался — curl rc=7", network=True)
        update.download_tree = boom
        r = update.apply(self.cfg, pool=self.pool, alerter=self.alerter, target="1.3.0", manual=True)
        self.assertFalse(r["ok"])
        self.assertEqual(self.alerter.sent, [])                # сеть = ретрай завтра, не спамим
        self.assertEqual(self._tree_ver(update.REDUT_SRC), "1.2.0")   # дерево узла не тронуто

    def test_download_broken_tree_sends_letter(self):
        def boom(repo, version, dest=None, log=None):
            raise update.UpdateError("в тарболле тега v1.3.0 лежит VERSION=1.2.9")
        update.download_tree = boom
        update.apply(self.cfg, pool=self.pool, alerter=self.alerter, target="1.3.0", manual=True)
        self.assertEqual(len(self.alerter.sent), 1)
        self.assertIn("не скачалось", self.alerter.sent[0][0])

    def test_lock_busy_backs_off(self):
        import apply as apply_mod
        orig = apply_mod.Flock

        class Busy:
            def __init__(self, path):
                pass

            def __enter__(self):
                raise apply_mod.ApplyError("занято")

            def __exit__(self, *a):
                pass
        apply_mod.Flock = Busy
        try:
            r = update.apply(self.cfg, pool=self.pool, target="1.3.0", manual=True)
        finally:
            apply_mod.Flock = orig
        self.assertFalse(r["ok"])
        self.assertIn("уже идёт", r["why"])
        self.assertEqual(self.setup_runs, [])

    def test_agent_lock_busy_after_download_defers_install(self):
        """A manual apply/rotate owning vpn-agent.lock wins over update mutation."""
        import apply as apply_mod
        original = apply_mod.Flock
        calls = []

        class FirstLockOnly:
            def __init__(self, path):
                self.path = path

            def __enter__(self):
                calls.append(self.path)
                if len(calls) == 2:
                    raise apply_mod.ApplyError("vpn-agent.lock занят ручным apply")
                return self

            def __exit__(self, *args):
                return False

        apply_mod.Flock = FirstLockOnly
        try:
            result = update.apply(
                self.cfg, pool=self.pool, target="1.3.0", manual=True)
        finally:
            apply_mod.Flock = original
        self.assertFalse(result["ok"])
        self.assertIn("агент занят", result["why"])
        self.assertEqual(self.setup_runs, [])
        self.assertEqual(calls, [update.LOCK_PATH, "/run/vpn-agent.lock"])
        self.assertFalse(os.path.exists(update.REDUT_NEW))

    def test_rollback_refused_for_pre_update_tree(self):
        # На узле лежит дерево сборки до 1.2.0 (setup.sh без UPDATE — так на узлах,
        # катанных deploy.py): его прогон в качестве «отката» переустановил бы узел
        # дефолтами node1/10.8.0.0/24 — хуже провала. Откат не запускается (ревью 17.08).
        with open(os.path.join(update.REDUT_SRC, "setup.sh"), "w", encoding="utf-8") as f:
            f.write("#!/bin/bash\nNAME=node1\n")           # старый setup.sh: UPDATE не знает
        self.verify_q[:] = [(False, "панель не отвечает по HTTPS")]
        r = update.apply(self.cfg, pool=self.pool, alerter=self.alerter,
                         target="1.3.0", manual=True)
        self.assertFalse(r["ok"])
        self.assertFalse(r["rolled_back"])
        self.assertEqual(self.setup_runs, ["1.3.0"])       # старый setup.sh НЕ гонялся
        self.assertIn("1.3.0", update.load_state(self.cfg)["bad_versions"])
        self.assertIn("ОТКАТ НЕ ПОДТВЕРДИЛСЯ", self.alerter.sent[0][1])

    def test_leftover_failed_install_does_not_poison_prev(self):
        # kill -9 посреди прошлой установки 1.3.0: src=полуустановленный 1.3.0,
        # prev=настоящий 1.2.0. Повторный прогон НЕ должен затереть prev «той же
        # версией» — иначе откат поехал бы на битое дерево (ревью 17.08).
        self._mktree(update.REDUT_PREV, "1.2.0")
        shutil.rmtree(update.REDUT_SRC, ignore_errors=True)
        self._mktree(update.REDUT_SRC, "1.3.0")            # след недоустановки
        self.verify_q[:] = [(False, "опять плохо"), (True, "")]
        r = update.apply(self.cfg, pool=self.pool, alerter=self.alerter,
                         target="1.3.0", manual=True)
        self.assertFalse(r["ok"])
        self.assertTrue(r["rolled_back"], r)
        self.assertEqual(self._tree_ver(update.REDUT_SRC), "1.2.0")   # откат на НАСТОЯЩИЙ «до»
        self.assertEqual(self.setup_runs, ["1.3.0", "1.2.0"])

    def test_rollback_trusts_health_not_rc(self):
        # Инфраструктурный сбой (легли зеркала apt): и новая установка, и откат
        # падают rc!=0, но узел цел и проходит проверку — это УСПЕШНЫЙ откат,
        # а не «ОТКАТ НЕ ПОДТВЕРДИЛСЯ» (ревью 17.08).
        self.setup_rc[:] = [1, 1]
        self.verify_q[:] = [(True, "")]                    # verify — только для отката
        r = update.apply(self.cfg, pool=self.pool, alerter=self.alerter,
                         target="1.3.0", manual=True)
        self.assertFalse(r["ok"])
        self.assertTrue(r["rolled_back"])
        self.assertIn("Откат прошёл", self.alerter.sent[0][1])

    # ── принудительная переустановка (1.6.0): та же версия заново, лечение узла ──
    def test_force_reinstall_same_version(self):
        self.verify_q[:] = [(True, "")]
        r = update.apply(self.cfg, pool=self.pool, alerter=self.alerter,
                         target="1.2.0", manual=True, force=True)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.setup_runs, ["1.2.0"])
        self.assertEqual(self._tree_ver(update.REDUT_SRC), "1.2.0")
        # цель отката — ЖИВОЕ дерево, что работало до переустановки
        self.assertEqual(self._tree_ver(update.REDUT_PREV), "1.2.0")
        st = update.load_state(self.cfg)
        self.assertTrue(st["last_apply"]["ok"])
        self.assertTrue(st["last_apply"]["force"])

    def test_force_downgrade_still_refused(self):
        # анти-даунгрейд (Р3) force не отменяет: вниз — никогда
        r = update.apply(self.cfg, pool=self.pool, alerter=self.alerter,
                         target="1.1.0", manual=True, force=True)
        self.assertFalse(r["ok"])
        self.assertIn("не новее", r["why"])
        self.assertEqual(self.setup_runs, [])

    def test_force_needs_manual(self):
        # у автоматики принудительного режима нет: force без manual — обычный отказ
        r = update.apply(self.cfg, pool=self.pool, alerter=self.alerter,
                         target="1.2.0", manual=False, force=True)
        self.assertFalse(r["ok"])
        self.assertIn("не новее", r["why"])
        self.assertEqual(self.setup_runs, [])

    def test_force_reinstall_ignores_leftover_prev(self):
        # В prev лежит прошлая версия (1.1.0). Ветка «след недоустановки» здесь
        # сработать не должна: src_ver == target при force — норма, а не признак
        # битого дерева; откат обязан целиться в живое 1.2.0, не в 1.1.0 (даунгрейд).
        self._mktree(update.REDUT_PREV, "1.1.0")
        self.verify_q[:] = [(True, "")]
        r = update.apply(self.cfg, pool=self.pool, alerter=self.alerter,
                         target="1.2.0", manual=True, force=True)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self._tree_ver(update.REDUT_PREV), "1.2.0")

    def test_force_failed_reinstall_rolls_back_without_blacklist(self):
        # Провал переустановки ТОЙ ЖЕ версии: откат на прежнее живое дерево, а в
        # чёрный список версию узла не пишем (список — про «не обновляться НА»).
        self.verify_q[:] = [(False, "панель не отвечает"), (True, "")]
        r = update.apply(self.cfg, pool=self.pool, alerter=self.alerter,
                         target="1.2.0", manual=True, force=True)
        self.assertFalse(r["ok"])
        self.assertTrue(r["rolled_back"], r)
        self.assertEqual(self.setup_runs, ["1.2.0", "1.2.0"])
        self.assertNotIn("1.2.0", update.load_state(self.cfg).get("bad_versions") or [])

    def test_force_apply_from_beacon_same_version(self):
        # target не задан: без force маяк «не новее» = отказ, с force — переустановка
        orig = update.check
        update.check = lambda cfg, **kw: {"local": "1.2.0", "remote": "1.2.0",
                                          "newer": False, "bad": False, "error": None}
        try:
            r0 = update.apply(self.cfg, pool=self.pool, alerter=self.alerter, manual=True)
            self.assertFalse(r0["ok"])
            self.assertIn("не на что", r0["why"])
            self.verify_q[:] = [(True, "")]
            r = update.apply(self.cfg, pool=self.pool, alerter=self.alerter,
                             manual=True, force=True)
            self.assertTrue(r["ok"], r)
            self.assertEqual(r["to"], "1.2.0")
        finally:
            update.check = orig


class TestWindowAndCron(unittest.TestCase):
    def test_in_window_plain(self):
        self.assertTrue(update.in_window("04:00-06:00", now_hm=4 * 60))
        self.assertTrue(update.in_window("04:00-06:00", now_hm=5 * 60 + 59))
        self.assertFalse(update.in_window("04:00-06:00", now_hm=6 * 60))
        self.assertFalse(update.in_window("04:00-06:00", now_hm=3 * 60 + 59))

    def test_in_window_wraps_midnight(self):
        self.assertTrue(update.in_window("22:00-02:00", now_hm=23 * 60))
        self.assertTrue(update.in_window("22:00-02:00", now_hm=1 * 60))
        self.assertFalse(update.in_window("22:00-02:00", now_hm=12 * 60))

    def test_garbage_window_does_not_block(self):
        for w in ("", None, "ночь", "4-6", "99:99"):
            self.assertTrue(update.in_window(w, now_hm=12 * 60), w)

    def test_window_covers_cron(self):
        # Крон 04:41 + jitter ≤25 мин: окно обязано пересекаться с [04:41..05:07],
        # иначе авто молча не сработает никогда — карточка предупреждает (ревью 17.08).
        self.assertTrue(update.window_covers_cron("04:00-06:00"))
        self.assertTrue(update.window_covers_cron("05:00-06:00"))   # jitter дотянет
        self.assertFalse(update.window_covers_cron("04:00-04:30"))
        self.assertFalse(update.window_covers_cron("12:00-14:00"))
        self.assertTrue(update.window_covers_cron("мусор"))         # кривое окно не ограничивает


class TestCronTick(unittest.TestCase):
    """Крон: check всегда; apply только при авто+окно+cooldown+свободный агент."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="upd-cron-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.cfg = {"server": "t", "db": os.path.join(self.dir, "state.db"),
                    "lock": os.path.join(self.dir, "agent.lock"),
                    "update": {"auto": True, "window": "00:00-24:00"}}
        self._origs = (update.check, update.apply)
        self.applied = []
        update.check = lambda cfg, **kw: {"local": "1.2.0", "remote": "1.3.0", "newer": True,
                                          "bad": False, "error": None}
        update.apply = lambda cfg, **kw: self.applied.append(kw.get("target")) or {
            "ok": True, "from": "1.2.0", "to": kw.get("target"), "rolled_back": False, "why": ""}
        self.addCleanup(self._restore)

    def _restore(self):
        update.check, update.apply = self._origs

    def test_happy_path_applies(self):
        r = update.cron_tick(self.cfg, jitter_s=0)
        self.assertIsNone(r["skip"])
        self.assertEqual(self.applied, ["1.3.0"])
        self.assertTrue(r["applied"]["ok"])

    def test_auto_off_skips(self):
        self.cfg["update"]["auto"] = False
        r = update.cron_tick(self.cfg, jitter_s=0)
        self.assertIn("выключено", r["skip"])
        self.assertEqual(self.applied, [])

    def test_outside_window_skips(self):
        lt = __import__("time").localtime()
        start = (lt.tm_hour * 60 + lt.tm_min + 120) % 1440
        end = (start + 60) % 1440
        self.cfg["update"]["window"] = "%02d:%02d-%02d:%02d" % (start // 60, start % 60,
                                                                end // 60, end % 60)
        r = update.cron_tick(self.cfg, jitter_s=0)
        self.assertIn("вне окна", r["skip"])
        self.assertEqual(self.applied, [])

    def test_cooldown_skips(self):
        update.save_state(self.cfg, {"last_apply": {"ts": update.now_iso(), "ok": False}})
        r = update.cron_tick(self.cfg, jitter_s=0)
        self.assertIn("cooldown", r["skip"])
        self.assertEqual(self.applied, [])

    def test_bad_version_skips(self):
        update.check = lambda cfg, **kw: {"local": "1.2.0", "remote": "1.3.0", "newer": True,
                                          "bad": True, "error": None}
        r = update.cron_tick(self.cfg, jitter_s=0)
        self.assertIn("чёрном списке", r["skip"])
        self.assertEqual(self.applied, [])

    def test_no_news_no_action(self):
        update.check = lambda cfg, **kw: {"local": "1.2.0", "remote": "1.2.0", "newer": False,
                                          "bad": False, "error": None}
        r = update.cron_tick(self.cfg, jitter_s=0)
        self.assertIsNone(r["applied"])
        self.assertEqual(self.applied, [])

    def test_jitter_sleeps_before_check(self):
        order = []
        update.check = lambda cfg, **kw: order.append("check") or {
            "local": "1.2.0", "remote": "1.2.0", "newer": False, "bad": False, "error": None}
        update.cron_tick(self.cfg, sleep=lambda s: order.append("sleep"), jitter_s=7)
        self.assertEqual(order, ["sleep", "check"])


@unittest.skipUnless(os.path.isfile(SETUP_SH), "нет install/setup.sh (публичная раскладка)")
class TestSetupShUpdateMode(unittest.TestCase):
    """UPDATE=1 в setup.sh: параметры узла выводятся из живого config.json.

    Питон-блок, который это делает, зашит в setup.sh хередоком — извлекаем его из
    скрипта и гоняем как есть: тестируется ровно тот код, что пойдёт на сервер.
    Это защита от главной грабли повторной установки: NAME=node1 переименовал бы
    узел (роль = привязка прокси в пуле), CLIENTS=phone1 дописал бы клиента.
    """

    @classmethod
    def setUpClass(cls):
        with open(SETUP_SH, encoding="utf-8") as f:
            text = f.read()
        m = re.search(r"upd_vars=\"\$\(python3 - \"\$CFG_LIVE\" <<'PY'\n(.*?)\nPY\n", text, re.S)
        assert m, "в setup.sh не найден питон-блок UPDATE-режима"
        cls.snippet = m.group(1)

    def _run(self, cfg):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            if isinstance(cfg, str):
                f.write(cfg)                      # нарочно битый JSON
            else:
                json.dump(cfg, f, ensure_ascii=False)
        self.addCleanup(os.unlink, path)
        # PYTHONIOENCODING: на Windows дочерний python пишет русский stderr в cp1251,
        # и декодер utf-8 родителя падал (на сервере всё utf-8, это чисто тестовая грабля).
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        p = subprocess.run([sys.executable, "-", path], input=self.snippet, env=env,
                           capture_output=True, text=True, encoding="utf-8")
        return p.returncode, p.stdout, p.stderr

    def test_full_config(self):
        rc, out, _ = self._run({"server": "node2", "subnet": "10.10.10.0/24",
                                "panel_port": 9443, "wg_port": 51821, "has_dnsmasq": True})
        self.assertEqual(rc, 0)
        self.assertIn("NAME=node2", out)
        self.assertIn("SUBNET=10.10.10.0/24", out)
        self.assertIn("PANEL_PORT=9443", out)
        self.assertIn("UPD_WG_PORT=51821", out)
        self.assertIn("UPD_DNSMASQ=1", out)

    def test_defaults_when_optional_missing(self):
        rc, out, _ = self._run({"server": "node1", "subnet": "10.8.0.0/24"})
        self.assertEqual(rc, 0)
        self.assertIn("PANEL_PORT=8443", out)
        self.assertIn("UPD_WG_PORT=''", out)      # пусто -> §3 оставит порт профиля
        self.assertIn("UPD_DNSMASQ=0", out)

    def test_missing_required_key_fails_with_reason(self):
        rc, _, err = self._run({"subnet": "10.8.0.0/24"})
        self.assertNotEqual(rc, 0)
        self.assertIn("server", err)

    def test_broken_json_fails(self):
        rc, _, err = self._run("{это не json")
        self.assertNotEqual(rc, 0)
        self.assertIn("JSON", err)

    def test_values_are_shell_quoted(self):
        # Имя с пробелом инсталлятор не пропустит (§0), но eval не должен
        # развалиться раньше этой проверки — значения обязаны быть закавычены.
        rc, out, _ = self._run({"server": "evil name; rm -rf /", "subnet": "10.8.0.0/24"})
        self.assertEqual(rc, 0)
        self.assertIn("NAME='evil name; rm -rf /'", out)

    def test_bad_panel_port_fails_early(self):
        rc, _, err = self._run({"server": "n", "subnet": "10.8.0.0/24", "panel_port": "abc"})
        self.assertNotEqual(rc, 0)
        self.assertIn("panel_port", err)

    def test_auto_update_detect_and_cron_path_present(self):
        # Голый повторный прогон на установленном узле обязан сам включать UPDATE=1
        # (иначе дефолты переименуют узел), а PATH — расширяться для крона (ревью 17.08).
        with open(SETUP_SH, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("_UPDATE_SET", text)
        self.assertIn("включаю режим обновления", text)
        self.assertIn('export PATH="/usr/local/sbin:', text)


@unittest.skipUnless(os.path.isfile(PROFILES_PY), "рядом нет install/profiles.py")
class TestEffectiveWgIp(unittest.TestCase):
    """wg_ip профиля осмыслен только в родной подсети (ревью Ф2: обновление узла
    чужим профилем прописывало wg0 адрес не из подсети узла — клиенты теряли DNS)."""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, os.path.join(PANEL_DIR, os.pardir, "install"))
        import profiles
        cls.profiles = profiles

    def test_foreign_subnet_recalculates(self):
        prof = {"subnet": "10.8.0.0/24", "wg_ip": "10.8.0.1"}
        self.assertEqual(self.profiles.effective_wg_ip(prof, "10.10.10.0/24"), "10.10.10.1")

    def test_native_subnet_keeps_profile_ip(self):
        prof = {"subnet": "10.8.0.0/24", "wg_ip": "10.8.0.7"}
        self.assertEqual(self.profiles.effective_wg_ip(prof, "10.8.0.0/24"), "10.8.0.7")

    def test_no_profile_ip_derives_first(self):
        self.assertEqual(self.profiles.effective_wg_ip({}, "10.9.0.0/24"), "10.9.0.1")

    def test_setup_sh_uses_helper_and_neutralizes_foreign_secrets(self):
        # Хередок §3 не запустить без `ip route` — фиксируем текстом, что он
        # использует effective_wg_ip и в UPDATE=1 обнуляет чужие секреты профиля
        # (upstream и пароль SOCKS5). Живьём это гоняет приёмка на node1.
        with open(SETUP_SH, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("profiles.effective_wg_ip(", text)
        self.assertIn('os.environ.get("UPDATE") == "1"', text)
        self.assertIn('"host": "", "socks": 0', text)


if __name__ == "__main__":
    unittest.main()
