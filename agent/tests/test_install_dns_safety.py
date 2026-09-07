# -*- coding: utf-8 -*-
import os
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def read(relative):
    with open(os.path.join(ROOT, relative), encoding="utf-8") as handle:
        return handle.read()


def read_layout(canonical, public):
    """Read a file whose allowlisted public destination differs."""
    canonical_path = os.path.join(ROOT, canonical)
    return read(canonical if os.path.exists(canonical_path) else public)


class TestBootOwnership(unittest.TestCase):
    def test_boot_never_flushes_builtin_prerouting(self):
        install = read("install/install.sh")
        template = read("install/templates/vpn-boot-setup.sh")
        for text in (install, template):
            self.assertNotIn("-F PREROUTING", text)
            self.assertIn("-F REDUT_PREROUTING", text)
            self.assertIn("emergency.intent", text)

    def test_boot_always_installs_empty_static_ru_set_and_return_rule(self):
        for relative in ("install/templates/vpn-boot-setup.sh", "install/install.sh"):
            text = read(relative)
            create = text.index("ipset create ru_whitelist_net")
            file_gate = text.index("if [ -f /etc/ru_whitelist_net.ipset ]", create)
            rule = text.index("--match-set ru_whitelist_net dst -j RETURN", file_gate)
            subnet_token = "-d $SUBNET" if relative.endswith("install.sh") else '-d "$SUBNET"'
            self.assertLess(create, file_gate)
            self.assertLess(rule, text.index(subnet_token, rule))
            self.assertNotIn("if ipset list -n ru_whitelist_net", text)

    def test_boot_route_writer_takes_common_lock_before_first_mutation(self):
        template = read("install/templates/vpn-boot-setup.sh")
        install = read("install/install.sh")
        for text in (template, install):
            self.assertIn("REDUT_LOCK_HELD", text)
            self.assertIn("/run/vpn-agent.lock", text)
            self.assertIn("flock -w 180", text)
        rendered = install.split(
            "cat > /usr/local/bin/vpn-boot-setup.sh <<BOOT", 1)[1].split(
                "\nBOOT", 1)[0]
        self.assertIn("set -euo pipefail", rendered)
        self.assertIn("set -euo pipefail", template)
        self.assertLess(template.index("flock -w 180"),
                        template.index("systemctl start wg-quick@wg0"))
        self.assertLess(install.index("# One writer for routes/firewall"),
                        install.index("# 0) фолбэк"))
        self.assertNotIn("systemctl start vpn-boot-setup", install)
        self.assertIn("TimeoutStartSec=240s",
                      read("install/templates/vpn-boot-setup.service"))

    def test_setup_queues_lifecycle_and_propagates_mandatory_failures(self):
        install = read("install/install.sh")
        setup = read_layout("install/setup.sh", "setup.sh")
        self.assertIn('if ! bash /usr/local/bin/vpn-boot-setup.sh; then', install)
        self.assertNotIn('bash /usr/local/bin/vpn-boot-setup.sh || true', install)
        self.assertIn('systemctl start --no-block vpn-boot-setup', setup)
        verify = setup[setup.index("# ── 6. Проверка"):]
        self.assertIn("boot invariant: в table middleman нет default route", verify)
        self.assertIn("boot invariant: нет PREROUTING -> REDUT_PREROUTING", verify)
        self.assertIn('if [ "$fail" != "0" ]; then\n    exit 1', verify)

    def test_direct_setup_stages_sources_until_locked_preflight_and_success(self):
        setup = read_layout("install/setup.sh", "setup.sh")
        candidate = setup.index('SOURCE_CANDIDATE="/opt/redut-src.setup-candidate.$$"')
        lock = setup.index('exec 8>/run/vpn-agent.lock')
        preflight = setup.index('import update', lock)
        install = setup.index('bash "$WORKDIR/install/install.sh"', preflight)
        final_failure = setup.rindex('if [ "$fail" != "0" ]; then')
        publish = setup.rindex('mv "$SOURCE_CANDIDATE" /opt/redut-src')
        self.assertLess(lock, candidate)
        self.assertLess(candidate, preflight)
        self.assertLess(preflight, install)
        self.assertLess(final_failure, publish)
        self.assertNotIn('rm -rf "$WORKDIR"; mkdir -p "$WORKDIR"', setup)

    def test_helpers_are_not_route_writers(self):
        for name in ("install/templates/singbox-watchdog.sh",
                     "install/templates/singbox-post.sh"):
            self.assertNotIn("route replace default", read(name))

    def test_base_manifest_covers_every_legacy_writer_and_skip_base_checks_it(self):
        marker = "# REDUT_BASE_CONTRACT=2"
        for relative in ("install/templates/singbox-watchdog.sh",
                         "install/templates/singbox-post.sh",
                         "install/templates/vpn-boot-setup.sh",
                         "install/templates/server_cleanup.sh"):
            self.assertIn(marker, read(relative))
        self.assertIn(marker, read("install/install.sh"))
        bootstrap = read("install/bootstrap.py")
        self.assertIn("if a.skip_base:", bootstrap)
        self.assertIn("remote_check_command()", bootstrap)
        self.assertIn("def run_result(", bootstrap)


class TestSupplyChain(unittest.TestCase):
    def test_singbox_binary_and_config_are_staged_and_verified(self):
        text = read("install/install.sh")
        self.assertIn('REDUT_LOCK_HELD', text)
        self.assertIn('flock -n 8', text)
        self.assertIn("30420c7e1a0e4b9c7ee2ff3992c53257be85dec2bdc93074594c8b92d19d4d71", text)
        self.assertIn("87be1d6db6d28896b13cb868c02d217c817fec1a820baf999a2f76f1564a32a7", text)
        self.assertIn('installed_sha', text)
        self.assertIn("sha256sum", text)
        self.assertIn("config.json.candidate", text)
        self.assertLess(text.index("check -c /etc/sing-box/config.json.candidate"),
                        text.index("mv /etc/sing-box/config.json.candidate"))
        self.assertIn("conntrack", text)

    def test_allowlist_is_exact_pinned_and_does_not_call_boot(self):
        text = read("install/templates/update-ru-whitelist.sh")
        self.assertIn("fad3653ebd4b212643774a4d10af3eb33838e4ff", text)
        for name in ("whitelist.txt", "ipwhitelist.txt", "cidrwhitelist.txt"):
            self.assertIn(name, text)
        self.assertNotIn("git clone", text)
        self.assertNotIn("vpn-boot-setup.sh", text)
        self.assertIn("rolled back", text)
        self.assertIn("flock -n 9", text)
        self.assertIn("ru-whitelist-update.pending", text)
        self.assertIn("rollback_pending", text)
        self.assertIn("REDUT_PARENT_LOCK_FD", text)
        self.assertIn("/proc/$$/fd/$PARENT_LOCK_FD", text)
        self.assertIn("--connect-timeout 5", text)
        self.assertIn("--max-time 30", text)
        self.assertIn("--speed-time 10", text)
        self.assertIn("--speed-limit 1024", text)
        self.assertIn("fsync_paths", text)
        self.assertLess(text.index('fsync_paths "$TXN_MARK.tmp"'),
                        text.index('mv "$TXN_MARK.tmp" "$TXN_MARK"'))

    def test_dns_unit_is_not_enabled_at_install(self):
        unit = read("install/templates/redut-dns-rescue.service")
        install = read("install/install.sh")
        self.assertNotIn("WantedBy=multi-user.target", unit)
        self.assertIn("systemctl disable redut-dns-rescue.service", install)

    def test_dns_watchdog_is_bounded_and_installed_separately(self):
        service = read("install/templates/redut-dns-rescue-watchdog.service")
        timer = read("install/templates/redut-dns-rescue-watchdog.timer")
        setup = read("install/setup_panel.py")
        self.assertIn("vpn-agent dns-rescue tick", service)
        self.assertIn("OnUnitActiveSec=5s", timer)
        self.assertIn("MemoryMax=128M", service)
        self.assertIn("AF_NETLINK", service)
        self.assertIn("User=redut-dns", read("install/templates/redut-dns-rescue.service"))
        self.assertIn("CapabilityBoundingSet=", read("install/templates/redut-dns-rescue.service"))
        self.assertIn("Restart=no", read("install/templates/redut-dns-rescue.service"))
        self.assertIn("TimeoutStartSec=180s", service)
        self.assertIn("After=network-online.target wg-quick@wg0.service vpn-boot-setup.service",
                      service)
        self.assertIn("Wants=network-online.target vpn-boot-setup.service", service)
        self.assertIn("enable --now redut-dns-rescue-watchdog.timer", setup)
        install = read("install/install.sh")
        self.assertIn("chown root:redut-dns /etc/redut-dns-rescue", install)
        self.assertIn("chmod 0750 /etc/redut-dns-rescue", install)
        self.assertNotIn("chmod 700 /etc/redut-dns-rescue", install)
        self.assertIn("groupadd --system redut-dns", setup)

    def test_all_install_paths_use_the_common_network_lock(self):
        shell_setup = read_layout("install/setup.sh", "setup.sh")
        setup = read("install/setup_panel.py")
        deploy = read_layout("panel/deploy.py", "agent/deploy.py")
        self.assertIn("exec 8>/run/vpn-agent.lock", shell_setup)
        self.assertIn("export REDUT_LOCK_HELD=1", shell_setup)
        self.assertLess(shell_setup.index("exec 8>/run/vpn-agent.lock"),
                        shell_setup.index('bash "$WORKDIR/install/install.sh"'))
        self.assertIn("REDUT_LOCK_HELD", setup)
        self.assertIn("fcntl.LOCK_EX | fcntl.LOCK_NB", setup)
        self.assertIn("acquire_remote_network_lock", deploy)
        self.assertIn("flock -n 9", deploy)

    def test_update_dns_preflight_precedes_dependency_mutation(self):
        setup = read_layout("install/setup.sh", "setup.sh")
        lock = setup.index("exec 8>/run/vpn-agent.lock")
        preflight = setup.index("DNS Rescue unit state is unreadable", lock)
        apt = setup.index("apt-get update", preflight)
        self.assertLess(lock, preflight)
        self.assertLess(preflight, apt)
        self.assertIn("DNS_PREFLIGHT_REQUIRED=0", setup)
        self.assertIn("DNS Rescue state singleton/phase is missing", setup)
        locked_preflight = setup.index("DNS_PREFLIGHT_REQUIRED=0", lock)
        self.assertLess(lock, locked_preflight)
        self.assertLess(locked_preflight, apt)

    def test_every_direct_installer_path_rechecks_dns_under_lock(self):
        install = read("install/install.sh")
        lock = install.index('flock -n "$LOCK_FD"')
        preflight = install.index('base_manifest.py" --dns-preflight', lock)
        apt = install.index('log "1/12 apt пакеты"', preflight)
        self.assertLess(lock, preflight)
        self.assertLess(preflight, apt)
        guard = install[lock:apt]
        self.assertNotIn('if [ "$UPDATE" = "1" ]', guard)
        self.assertIn("/etc/vpn-panel/config.json", guard)
        self.assertIn("/var/lib/vpn-panel/state.db", guard)
        self.assertIn("-L /etc/vpn-panel/config.json", guard)
        self.assertIn("-L /opt/vpn-panel/VERSION", guard)
        self.assertIn("-L /var/lib/vpn-panel/state.db", guard)

        setup = read_layout("install/setup.sh", "setup.sh")
        setup_lock = setup.index('flock -n "$LOCK_FD"')
        setup_preflight = setup.index("DNS_PREFLIGHT_REQUIRED=0", setup_lock)
        setup_apt = setup.index('say "Ставлю curl/tar/python3', setup_preflight)
        self.assertLess(setup_lock, setup_preflight)
        self.assertLess(setup_preflight, setup_apt)
        self.assertIn("os.path.lexists", setup[setup_preflight:setup_apt])

        bootstrap = read("install/bootstrap.py")
        main = bootstrap.index("def main(")
        early = bootstrap.index("remote_dns_preflight(c)", main)
        upload = bootstrap.index("upload(c, p, net)", early)
        self.assertLess(early, upload)
        self.assertIn('"%s/base_manifest.py" % REMOTE', bootstrap)
        install_rc = bootstrap.index("if rc != 0:", upload)
        fetch = bootstrap.index("saved = fetch_clients", install_rc)
        self.assertIn("raise SystemExit", bootstrap[install_rc:fetch])

    def test_allowlist_commits_only_after_mandatory_domain_flush(self):
        text = read("install/templates/update-ru-whitelist.sh")
        flush = text.index('ipset flush "$DOMAIN_SET"')
        commit = text.rindex('rm -f -- "$TXN_MARK"')
        commit_fsync = text.rindex('fsync_paths "$(dirname "$TXN_MARK")"')
        old_hash_cleanup = text.rindex('rm -f -- "$LKG_DIR/.old_set_hash"')
        destroy = text.rindex('ipset destroy "${NET_SET}_candidate"')
        self.assertLess(flush, commit)
        self.assertLess(commit, commit_fsync)
        self.assertLess(commit_fsync, old_hash_cleanup)
        self.assertLess(old_hash_cleanup, destroy)
        self.assertIn('.old_set_hash', text)
        self.assertIn('set_mark rollback', text)

    def test_allowlist_rollback_guards_every_durable_mutation(self):
        text = read("install/templates/update-ru-whitelist.sh")
        start = text.index("rollback_pending(){")
        end = text.index("\n}\ncleanup(){", start)
        rollback = text[start:end]
        self.assertIn('if ! ipset swap "${NET_SET}_candidate" "$NET_SET"', rollback)
        self.assertIn("if ! restore_files", rollback)
        self.assertIn("if ! fsync_paths", rollback)
        self.assertIn('if ! rm -f -- "$TXN_MARK"', rollback)
        self.assertIn('ipset flush "$DOMAIN_SET"', rollback)
        self.assertLess(rollback.index('ipset flush "$DOMAIN_SET"'),
                        rollback.index('rm -f -- "$TXN_MARK"'))
        self.assertLess(rollback.index('rm -f -- "$TXN_MARK"'),
                        rollback.index('fsync_paths "$(dirname "$TXN_MARK")"'))
        self.assertLess(rollback.index('fsync_paths "$(dirname "$TXN_MARK")"'),
                        rollback.index('rm -f -- "$LKG_DIR/.old_set_hash"'))

    def test_allowlist_rollback_survives_reboot_without_network(self):
        updater = read("install/templates/update-ru-whitelist.sh")
        self.assertIn('OLD_SNAPSHOT="$LKG_DIR/old-live-candidate.ipset"', updater)
        self.assertIn('snapshot_valid', updater)
        self.assertIn('ipset restore < "$OLD_SNAPSHOT"', updater)
        self.assertIn('ipset create "$NET_SET" hash:net', updater)
        self.assertIn('if [ "$RECOVER_ONLY" = "1" ]', updater)
        self.assertLess(updater.index('rollback_pending || exit 1'),
                        updater.index('if [ "$RECOVER_ONLY" = "1" ]'))
        self.assertLess(updater.index('if [ "$RECOVER_ONLY" = "1" ]'),
                        updater.index('fetch(){'))

        for path in ("install/templates/vpn-boot-setup.sh", "install/install.sh"):
            boot = read(path)
            recovery = boot.index('update-ru-whitelist.sh --recover-only')
            first_kernel_restore = min(
                pos for token in ('ip link show wg0', 'ipset create ru_whitelist')
                if (pos := boot.index(token)) >= 0
            )
            self.assertLess(recovery, first_kernel_restore, path)
            self.assertIn('ru-whitelist-update.pending', boot)


if __name__ == "__main__":
    unittest.main()
