# -*- coding: utf-8 -*-
"""Пересборка config.json от эталона vadim/README.md §5.3 (§7.3, §9.3)."""
import copy
import unittest

import _ctx
import apply as apply_mod

NEW = dict(host="91.198.74.10", user="u", password="p")


def outbound_by_tag(cfg, tag):
    return next(o for o in cfg["outbounds"] if o.get("tag") == tag)


class TestChooseOutbounds(unittest.TestCase):
    def test_both_alive(self):
        s, h, quic = apply_mod.choose_outbounds(NEW["host"], "u", "p", 62955, 62954)
        self.assertEqual((s["type"], s["server_port"]), ("socks", 62955))
        self.assertEqual(s["version"], "5")
        self.assertEqual((h["type"], h["server_port"]), ("http", 62954))
        self.assertNotIn("version", h, "у http-outbound поля version нет вовсе")
        self.assertFalse(quic)

    def test_socks_dead_fallback_by_type(self):
        # правильный фолбэк — менять ТИП, а не порт (§7.1: баг set_upstream.py:81)
        s, h, quic = apply_mod.choose_outbounds(NEW["host"], "u", "p", None, 62954)
        self.assertEqual((s["type"], s["server_port"]), ("http", 62954))
        self.assertNotIn("version", s, 'при socks->http не должно остаться "version":"5"')
        self.assertEqual(s["tag"], "socks-out", "тег НЕ переименовывается")
        self.assertTrue(quic, "HTTP-режим основного -> нужен reject UDP443")

    def test_http_dead_fallback_by_type(self):
        s, h, quic = apply_mod.choose_outbounds(NEW["host"], "u", "p", 62955, None)
        self.assertEqual((h["type"], h["server_port"]), ("socks", 62955))
        self.assertEqual(h["version"], "5")
        self.assertEqual(h["tag"], "http-tg")
        self.assertFalse(quic)

    def test_nothing_alive(self):
        with self.assertRaises(apply_mod.ApplyError):
            apply_mod.choose_outbounds(NEW["host"], "u", "p", None, None)


class TestPatchConfig(unittest.TestCase):
    def setUp(self):
        self.ref = _ctx.fixture("singbox_config_reference.json")

    def patch(self, socks_port, http_port):
        s, h, quic = apply_mod.choose_outbounds(NEW["host"], NEW["user"], NEW["password"],
                                                socks_port, http_port)
        return apply_mod.patch_config(self.ref, s, h, quic)

    def test_reference_not_mutated(self):
        before = copy.deepcopy(self.ref)
        self.patch(62955, 62954)
        self.assertEqual(self.ref, before, "patch_config не должен мутировать вход")

    def test_normal_socks_mode(self):
        c = self.patch(62955, 62954)
        s = outbound_by_tag(c, "socks-out")
        h = outbound_by_tag(c, "http-tg")
        self.assertEqual((s["type"], s["server"], s["server_port"]), ("socks", NEW["host"], 62955))
        self.assertEqual((h["type"], h["server_port"]), ("http", 62954))
        self.assertEqual(c["route"]["final"], "socks-out", "final прописан явно (§7.1)")
        self.assertFalse(any(apply_mod.is_quic_reject(r) for r in c["route"]["rules"]))
        # структура нетронута: dns-out на месте, telegram-правила целы, dns.detour цел
        self.assertEqual(outbound_by_tag(c, "dns-out"), {"type": "dns", "tag": "dns-out"})
        self.assertEqual(c["dns"], self.ref["dns"])
        tg_rules = [r for r in c["route"]["rules"] if r.get("outbound") == "http-tg"]
        self.assertEqual(len(tg_rules), 2, "правила Telegram (CIDR + домены) не тронуты")

    def test_socks_to_http_no_version_residue(self):
        c = self.patch(None, 62954)
        s = outbound_by_tag(c, "socks-out")
        self.assertEqual(s["type"], "http")
        self.assertNotIn("version", s,
                         'outbound пересобран из шаблона: остаточного "version":"5" нет (§9.3)')
        # UDP443-reject появился и стоит сразу после DNS-правила, до Telegram-правил
        rules = c["route"]["rules"]
        idx = next(i for i, r in enumerate(rules) if apply_mod.is_quic_reject(r))
        self.assertEqual(rules[0], {"protocol": "dns", "outbound": "dns-out"})
        self.assertEqual(idx, 1, "reject сразу после DNS-правил")

    def test_udp443_rule_removed_on_return_to_socks(self):
        # применили HTTP-режим, затем вернулись на SOCKS5 — правило обязано сняться
        c1 = self.patch(None, 62954)
        s, h, quic = apply_mod.choose_outbounds(NEW["host"], "u", "p", 62955, 62954)
        c2 = apply_mod.patch_config(c1, s, h, quic)
        self.assertFalse(any(apply_mod.is_quic_reject(r) for r in c2["route"]["rules"]),
                         "правило UDP443 снимается в SOCKS5-режиме (идемпотентность)")
        self.assertEqual(len(c2["route"]["rules"]), len(self.ref["route"]["rules"]))

    def test_repatch_idempotent_no_rule_duplicates(self):
        c1 = self.patch(None, 62954)
        s, h, quic = apply_mod.choose_outbounds(NEW["host"], "u", "p", None, 62954)
        c2 = apply_mod.patch_config(c1, s, h, quic)
        rejects = [r for r in c2["route"]["rules"] if apply_mod.is_quic_reject(r)]
        self.assertEqual(len(rejects), 1, "повторный патч не плодит дубликаты правила")

    def test_tags_never_renamed(self):
        c = self.patch(None, 62954)
        tags = [o.get("tag") for o in c["outbounds"]]
        self.assertEqual(tags, ["socks-out", "http-tg", "dns-out"],
                         "теги — якоря route.rules и dns.detour, состав/порядок не меняется")

    def test_current_upstream(self):
        self.assertEqual(apply_mod.current_upstream(self.ref), "155.212.40.40")
        self.assertEqual(apply_mod.current_upstream(self.patch(62955, 62954)), NEW["host"])


class TestPatchBootScript(unittest.TestCase):
    """vpn-boot-setup.sh: правка анти-луп адреса, включая ХОЛОДНЫЙ старт (old_ip == "").

    Найдено на приёмке публичной сборки 15.08: при пустом прежнем адресе re.sub("")
    вставлял новый IP между каждыми двумя символами — скрипт превращался в кашу.
    """
    OLD_FMT = ("#!/bin/bash\n# VPN boot setup — subnet 10.8.0.0/24, upstream %s (сгенерирован install.sh).\n"
               "ip route replace %s/32 via 198.51.100.1 dev ens3          # анти-луп: до upstream — напрямую\n"
               "echo done\n")
    NEW_FMT = ("#!/bin/bash\n# VPN boot setup — subnet 10.8.0.0/24, upstream %s.\n"
               "UP_HOST=\"%s\"\n"
               "[ -n \"$UP_HOST\" ] && ip route replace \"$UP_HOST/32\" via 198.51.100.1 dev ens3\n"
               "echo done\n")

    def _tmp(self, text):
        import os
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".sh")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return path

    def _read(self, path):
        with open(path, encoding="utf-8") as f:
            return f.read()

    def test_replace_existing_ip_both_formats(self):
        for fmt in (self.OLD_FMT, self.NEW_FMT):
            p = self._tmp(fmt % ("1.1.1.1", "1.1.1.1"))
            self.assertTrue(apply_mod.patch_boot_script(p, "1.1.1.1", "2.2.2.2"))
            self.assertEqual(self._read(p), fmt % ("2.2.2.2", "2.2.2.2"))

    def test_cold_start_old_format_fills_antiloop_line_only(self):
        p = self._tmp(self.OLD_FMT % ("", ""))
        self.assertTrue(apply_mod.patch_boot_script(p, "", "5.6.7.8"))
        got = self._read(p)
        self.assertIn("ip route replace 5.6.7.8/32 via 198.51.100.1 dev ens3", got)
        self.assertEqual(got.count("5.6.7.8"), 1, "адрес вписан ровно один раз, а не между символами")
        self.assertTrue(got.startswith("#!/bin/bash\n"), "скрипт остался скриптом")

    def test_cold_start_new_format_sets_variable(self):
        p = self._tmp(self.NEW_FMT % ("", ""))
        self.assertTrue(apply_mod.patch_boot_script(p, "", "5.6.7.8"))
        got = self._read(p)
        self.assertIn('UP_HOST="5.6.7.8"\n', got)
        self.assertEqual(got.count("5.6.7.8"), 1)
        # следующий кандидат при всё ещё пустом live-конфиге перезаписывает переменную
        self.assertTrue(apply_mod.patch_boot_script(p, "", "9.9.9.9"))
        got = self._read(p)
        self.assertIn('UP_HOST="9.9.9.9"\n', got)
        self.assertNotIn("5.6.7.8", got)

    def test_noop_cases(self):
        p = self._tmp(self.NEW_FMT % ("1.1.1.1", "1.1.1.1"))
        before = self._read(p)
        self.assertFalse(apply_mod.patch_boot_script(p, "1.1.1.1", "1.1.1.1"))
        self.assertFalse(apply_mod.patch_boot_script(p, "1.1.1.1", ""), "пустой новый адрес — ничего не делаем")
        self.assertFalse(apply_mod.patch_boot_script(p + ".missing", "1.1.1.1", "2.2.2.2"))
        self.assertEqual(self._read(p), before)

    # Формат install.sh §7 после сноса №4 (15.08): при пустом UP_HOST boot-скрипт сам ставит
    # прямой выход (default via шлюз) и флаг аварии — без «чёрной дыры» до тика сторожа.
    # Ветвление не должно мешать агенту вписывать адрес: только строка UP_HOST="…".
    BRANCH_FMT = (
        "#!/bin/bash\n# VPN boot setup — subnet 10.8.0.0/24, upstream %s (сгенерирован install.sh).\n"
        "UP_HOST=\"%s\"\n"
        "if [ -n \"$UP_HOST\" ]; then\n"
        "    ip route replace default dev tun0 table middleman\n"
        "    ip route replace \"$UP_HOST/32\" via 198.51.100.1 dev ens3\n"
        "else\n"
        "    ip route replace default via 198.51.100.1 dev ens3 table middleman\n"
        "    echo \"$(date '+%%F %%T') boot: канал не выбран — прямой выход\" > /run/vpn-agent-emergency\n"
        "fi\n"
        "echo \"[$(date)] vpn-boot-setup completed (upstream: ${UP_HOST:-не выбран, прямой выход})\"\n")

    def test_branching_format_cold_start_touches_only_variable(self):
        p = self._tmp(self.BRANCH_FMT % ("", ""))
        self.assertTrue(apply_mod.patch_boot_script(p, "", "5.6.7.8"))
        got = self._read(p)
        self.assertIn('UP_HOST="5.6.7.8"\n', got)
        self.assertEqual(got.count("5.6.7.8"), 1, "адрес вписан ровно один раз — в переменную")
        self.assertIn('ip route replace "$UP_HOST/32" via 198.51.100.1 dev ens3\n', got,
                      "строка анти-лупа осталась через переменную (шаблон агента её не трогает)")
        self.assertIn("default via 198.51.100.1 dev ens3 table middleman", got, "ветка прямого выхода цела")
        self.assertTrue(got.startswith("#!/bin/bash\n"))

    def test_branching_format_replace_existing_ip(self):
        p = self._tmp(self.BRANCH_FMT % ("1.1.1.1", "1.1.1.1"))
        self.assertTrue(apply_mod.patch_boot_script(p, "1.1.1.1", "2.2.2.2"))
        got = self._read(p)
        self.assertEqual(got, self.BRANCH_FMT % ("2.2.2.2", "2.2.2.2"))
        self.assertNotIn("1.1.1.1", got)


class TestValidation(unittest.TestCase):
    def test_stage_rejects_bad_host(self):
        # §15: валидация до каких-либо действий
        row = {"host": "хост;rm -rf", "user": "u", "password": "p"}
        with self.assertRaises(apply_mod.ApplyError):
            apply_mod.stage_candidate({"singbox_config": "nonexistent.json"}, row,
                                      {"socks_port": 1080, "http_port": None})


if __name__ == "__main__":
    unittest.main(verbosity=2)
