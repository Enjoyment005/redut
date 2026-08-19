# -*- coding: utf-8 -*-
"""sysinfo: метрики сервера для полоски «Сервер» в шапке панели (1.8.0).

Живого /proc на dev-машине нет — парсеры тестируем на строках-фикстурах,
snapshot() — на фейковом каталоге с теми же файлами. Числа фикстуры подобраны
под живой пример владельца: нагрузка 4%, память 17%, swap 50%.
"""
import os
import tempfile
import unittest

from _ctx import PANEL_DIR  # noqa: F401 — панель в sys.path
from webpanel import sysinfo


MEMINFO = """MemTotal:        2027840 kB
MemFree:          164512 kB
MemAvailable:    1682212 kB
Buffers:           94024 kB
Cached:          1355844 kB
SwapCached:           12 kB
SwapTotal:       1048572 kB
SwapFree:         524286 kB
Dirty:                 8 kB
битая строка без числа: abc
"""

LOADAVG = "0.08 0.11 0.20 1/123 4567\n"
UPTIME = "123456.78 200000.11\n"


class TestParsers(unittest.TestCase):
    def test_loadavg(self):
        self.assertEqual(sysinfo.parse_loadavg(LOADAVG), 0.08)

    def test_loadavg_garbage(self):
        self.assertIsNone(sysinfo.parse_loadavg(""))
        self.assertIsNone(sysinfo.parse_loadavg("мусор"))

    def test_meminfo(self):
        m = sysinfo.parse_meminfo(MEMINFO)
        self.assertEqual(m["MemTotal"], 2027840)
        self.assertEqual(m["SwapFree"], 524286)
        self.assertNotIn("битая строка без числа", m)

    def test_uptime(self):
        self.assertEqual(sysinfo.parse_uptime(UPTIME), 123456.78)
        self.assertIsNone(sysinfo.parse_uptime(""))


class TestRecommend(unittest.TestCase):
    """Формула: min(ядра×10, (RAM−256МБ)/24МБ) × 0.8 (запас −20%, просьба
    владельца 19.08), floor, но не меньше 2."""

    def test_one_core_one_gb_cpu_bound(self):
        # 1 ядро ограничивает раньше памяти: 10 × 0.8 = 8 устройств
        self.assertEqual(sysinfo.recommend_clients(1, 1024 * 1024), 8)

    def test_two_cores_two_gb(self):
        # 20 × 0.8 = 16
        self.assertEqual(sysinfo.recommend_clients(2, 2 * 1024 * 1024), 16)

    def test_four_cores_node1(self):
        # живой node1: 4 ядра / ~3.9 ГБ → потолок 40, с запасом 32
        self.assertEqual(sysinfo.recommend_clients(4, 2027840 * 2), 32)

    def test_small_ram_bounds(self):
        # 384 МБ: по памяти потолок 5, с запасом −20% → 4
        self.assertEqual(sysinfo.recommend_clients(1, 384 * 1024), 4)

    def test_tiny_ram_floor(self):
        # совсем маленький VPS: меньше 2 не отдаём
        self.assertEqual(sysinfo.recommend_clients(1, 256 * 1024), 2)

    def test_unknown_inputs(self):
        self.assertIsNone(sysinfo.recommend_clients(None, 1024 * 1024))
        self.assertIsNone(sysinfo.recommend_clients(2, 0))
        self.assertIsNone(sysinfo.recommend_clients("мусор", "мусор"))


class TestSnapshot(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proc = os.path.join(self.tmp.name, "proc")
        self.net = os.path.join(self.tmp.name, "net")
        os.makedirs(self.proc)
        os.makedirs(os.path.join(self.net, "wg0"))
        for name, text in (("loadavg", LOADAVG), ("meminfo", MEMINFO), ("uptime", UPTIME)):
            with open(os.path.join(self.proc, name), "w") as f:
                f.write(text)

    def tearDown(self):
        self.tmp.cleanup()

    def snap(self, **kw):
        kw.setdefault("proc", self.proc)
        kw.setdefault("disk_path", self.tmp.name)
        kw.setdefault("cores", 2)
        kw.setdefault("sys_net", self.net)
        return sysinfo.snapshot(**kw)

    def test_full_snapshot(self):
        y = self.snap()
        self.assertEqual(y["cores"], 2)
        self.assertEqual(y["load1"], 0.08)
        self.assertEqual(y["load_pct"], 4)              # 0.08 / 2 ядра = 4%
        self.assertEqual(y["mem_total_mb"], 1980)
        self.assertEqual(y["mem_used_mb"], 338)         # total - MemAvailable
        self.assertEqual(y["mem_pct"], 17)
        self.assertEqual(y["swap_total_mb"], 1024)
        self.assertEqual(y["swap_used_mb"], 512)
        self.assertEqual(y["swap_pct"], 50)
        self.assertEqual(y["uptime_sec"], 123456.78)
        self.assertTrue(y["wg_up"])
        self.assertEqual(y["rec_clients"], 16)          # 2 ядра × 10, −20% запаса
        # диск меряется настоящим shutil.disk_usage по временному каталогу
        self.assertIsNotNone(y["disk_total_gb"])
        self.assertIsNotNone(y["disk_free_gb"])
        self.assertIsNotNone(y["disk_pct"])

    def test_no_swap(self):
        with open(os.path.join(self.proc, "meminfo"), "w") as f:
            f.write("MemTotal: 1048576 kB\nMemAvailable: 524288 kB\n"
                    "SwapTotal: 0 kB\nSwapFree: 0 kB\n")
        y = self.snap()
        self.assertEqual(y["swap_total_mb"], 0)
        self.assertIsNone(y["swap_pct"])
        self.assertEqual(y["mem_pct"], 50)

    def test_old_kernel_without_memavailable(self):
        with open(os.path.join(self.proc, "meminfo"), "w") as f:
            f.write("MemTotal: 1000000 kB\nMemFree: 100000 kB\n"
                    "Buffers: 50000 kB\nCached: 350000 kB\n")
        y = self.snap()
        self.assertEqual(y["mem_pct"], 50)              # used = 1e6 - (100+50+350)к

    def test_wg_down(self):
        y = self.snap(sys_net=os.path.join(self.tmp.name, "нет-такого"))
        self.assertFalse(y["wg_up"])

    def test_load_over_100_capped_at_999(self):
        with open(os.path.join(self.proc, "loadavg"), "w") as f:
            f.write("50.0 40.0 30.0 9/99 111\n")
        y = self.snap(cores=1)
        self.assertEqual(y["load_pct"], 999)

    def test_no_proc_means_none(self):
        self.assertIsNone(sysinfo.snapshot(proc=os.path.join(self.tmp.name, "пусто"),
                                           disk_path=self.tmp.name, cores=1,
                                           sys_net=self.net))


if __name__ == "__main__":
    unittest.main()
