# -*- coding: utf-8 -*-
import os
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def read(relative):
    with open(os.path.join(ROOT, relative), encoding="utf-8") as handle:
        return handle.read()


class TestBootOwnership(unittest.TestCase):
    def test_boot_never_flushes_builtin_prerouting(self):
        install = read("install/install.sh")
        template = read("install/templates/vpn-boot-setup.sh")
        for text in (install, template):
            self.assertNotIn("-F PREROUTING", text)
            self.assertIn("-F REDUT_PREROUTING", text)
            self.assertIn("emergency.intent", text)

    def test_helpers_are_not_route_writers(self):
        for name in ("install/templates/singbox-watchdog.sh",
                     "install/templates/singbox-post.sh"):
            self.assertNotIn("route replace default", read(name))


class TestSupplyChain(unittest.TestCase):
    def test_singbox_binary_and_config_are_staged_and_verified(self):
        text = read("install/install.sh")
        self.assertIn("30420c7e1a0e4b9c7ee2ff3992c53257be85dec2bdc93074594c8b92d19d4d71", text)
        self.assertIn("sha256sum", text)
        self.assertIn("config.json.candidate", text)
        self.assertLess(text.index("check -c /etc/sing-box/config.json.candidate"),
                        text.index("mv /etc/sing-box/config.json.candidate"))

    def test_allowlist_is_exact_pinned_and_does_not_call_boot(self):
        text = read("install/templates/update-ru-whitelist.sh")
        self.assertIn("fad3653ebd4b212643774a4d10af3eb33838e4ff", text)
        for name in ("whitelist.txt", "ipwhitelist.txt", "cidrwhitelist.txt"):
            self.assertIn(name, text)
        self.assertNotIn("git clone", text)
        self.assertNotIn("vpn-boot-setup.sh", text)
        self.assertIn("rolled back", text)

    def test_dns_unit_is_not_enabled_at_install(self):
        unit = read("install/templates/redut-dns-rescue.service")
        install = read("install/install.sh")
        self.assertNotIn("WantedBy=multi-user.target", unit)
        self.assertIn("systemctl disable redut-dns-rescue.service", install)


if __name__ == "__main__":
    unittest.main()
