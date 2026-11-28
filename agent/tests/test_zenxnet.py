import base64
import copy
import json
import os
import socket
import tempfile
import unittest
from unittest import mock
from urllib.parse import urlencode

import _ctx
import apply
import contours
import pool
import vless
from providers import make_providers
from providers.base import ProviderError
from providers.zenxnet import parse_node, parse_subscription, validate_url, public_addresses, ZenXNet


URL = "https://key.zenx.zone/EXAMPLE_SUBSCRIPTION"
HWID = "redut-example-device"
UUID = "11111111-1111-4111-8111-111111111111"


def uri(host="example.com", port=443, sid="", label="🇫🇮 Finland", **overrides):
    values = {"encryption": "none", "type": "tcp", "security": "reality", "flow": "xtls-rprx-vision",
              "sni": "www.example.org", "pbk": "A" * 43, "fp": "firefox", "sid": sid, "spx": "/"}
    values.update(overrides)
    return "vless://%s@%s:%s?%s#%s" % (UUID, host, port, urlencode(values), label)


class SubscriptionTests(unittest.TestCase):
    def test_plain_and_base64_catalogs_are_equivalent(self):
        body = (uri() + "\n" + uri(port=8443, label="🇩🇪 Germany")).encode()
        nodes = parse_subscription(body)
        self.assertEqual(nodes, parse_subscription(base64.b64encode(body)))
        self.assertEqual([x["country"] for x in nodes], ["fi", "de"])
        self.assertTrue(all(x["protocol"] == "vless" for x in nodes))
        self.assertTrue(all(x["port_socks5"] is None and x["port_http"] is None for x in nodes))

    def test_rename_and_order_preserve_identity_but_credentials_are_versioned(self):
        before = parse_node(uri())
        renamed = parse_node(uri(label="🇫🇮 New name"))
        changed = parse_node(uri().replace(UUID, "22222222-2222-4222-8222-222222222222"))
        self.assertEqual(before["ext_id"], renamed["ext_id"])
        self.assertEqual(before["ext_id"], changed["ext_id"])
        self.assertNotEqual(before["connection_digest"], changed["connection_digest"])

    def test_ambiguous_credentials_do_not_replace_catalog(self):
        body = (uri() + "\n" + uri().replace(UUID, "22222222-2222-4222-8222-222222222222")).encode()
        with self.assertRaises(ProviderError):
            parse_subscription(body)

    def test_empty_short_id_and_tcp_do_not_disable_udp(self):
        row = parse_node(uri())
        out = vless.outbound(row)
        self.assertEqual(out["tls"]["reality"]["short_id"], "")
        self.assertNotIn("network", out)
        self.assertNotIn("transport", out)

    def test_unknown_security_fields_are_not_silently_dropped(self):
        for value in (uri(unknown="unsafe"), uri(type="ws"), uri(security="none"),
                      uri(sid="0"), uri(spx="/nondefault"), uri(host="127.0.0.1")):
            with self.subTest(value=value[-30:]), self.assertRaises(ProviderError):
                parse_node(value)

    def test_url_boundaries_and_error_redaction(self):
        self.assertEqual(validate_url(" " + URL + " "), URL)
        for value in ("http://key.zenx.zone/SECRET", "https://key.zenx.zone.evil.test/SECRET",
                      "https://your_user_here:your_password_here@key.zenx.zone/SECRET", "https://127.0.0.1/SECRET",
                      URL + "\nX-Evil: true", URL + "#SECRET"):
            with self.assertRaises(ProviderError) as error:
                validate_url(value)
            self.assertNotIn("SECRET", str(error.exception))

    def test_private_dns_answer_is_rejected_before_connect(self):
        with mock.patch("socket.getaddrinfo", return_value=[(socket.AF_INET, 1, 6, "", ("127.0.0.1", 443))]):
            with self.assertRaises(ProviderError):
                public_addresses("key.zenx.zone")

    def test_html_and_empty_response_are_failures(self):
        for body in (b"", b"<html>register device</html>", base64.b64encode(b"no devices")):
            with self.assertRaises(ProviderError):
                parse_subscription(body)

    def test_device_identity_is_required_and_reused(self):
        with self.assertRaises(ProviderError):
            ZenXNet(URL)
        with mock.patch("providers.zenxnet.public_addresses", return_value=["1.1.1.1"]), mock.patch("providers.zenxnet.fetch_subscription", return_value=(uri().encode(), {})) as fetch:
            provider = make_providers({"zenxnet": {"api_key": URL, "hwid": HWID}})["zenxnet"]
            provider.list()
            provider.list()
            fetch.assert_called_once_with(URL, HWID)
            self.assertFalse(provider.caps["buy"])
            self.assertFalse(provider.caps["balance"])

    def test_refresh_failure_keeps_last_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            db = pool.Pool(os.path.join(directory, "state.db"))
            try:
                row = parse_node(uri())
                uid = db.upsert_proxy(row)
                db.set_role(uid, "auto")
                provider = mock.Mock()
                provider.list.side_effect = ProviderError("invalid", kind="invalid")
                result = db.refresh({"zenxnet": provider})
                self.assertIn("zenxnet", result["errors"])
                self.assertEqual(db.get(uid)["role"], "auto")
                self.assertFalse(db.get(uid)["gone"])
            finally:
                db.close()

    def test_changed_credentials_invalidate_probe_without_repinning(self):
        with tempfile.TemporaryDirectory() as directory:
            db = pool.Pool(os.path.join(directory, "state.db"))
            try:
                row = parse_node(uri())
                uid = db.upsert_proxy(row)
                db.set_role(uid, "auto")
                db.record_probe(uid, {"ok": True, "score": 120, "exit_cc": "fi", "connection_digest": row["connection_digest"]})
                changed = parse_node(uri().replace(UUID, "22222222-2222-4222-8222-222222222222"))
                provider = mock.Mock()
                provider.list.return_value = [changed]
                db.refresh({"zenxnet": provider})
                after = db.get(uid)
                self.assertIsNone(after["probe_ok"])
                self.assertIsNone(after["last_probe_at"])
                self.assertEqual(after["role"], "auto")
            finally:
                db.close()

    def test_stage_uses_real_vless_outbounds_and_preserves_dns_tags(self):
        row = parse_node(uri())
        result = {"ok": True, "connection_digest": row["connection_digest"]}
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "sing-box.json")
            baseline = _ctx.fixture("singbox_config_reference.json")
            apply.dump_json_replace(baseline, path)
            stage, cfg, main, telegram, reject = apply.stage_candidate({"singbox_config": path}, row, result)
            self.assertEqual(main["type"], "vless")
            self.assertEqual(telegram["type"], "vless")
            self.assertEqual(main["tag"], "socks-out")
            self.assertEqual(telegram["tag"], "http-tg")
            self.assertFalse(reject)
            self.assertEqual(cfg["route"]["final"], "socks-out")
            self.assertEqual(apply.load_json(path), baseline)
            self.assertEqual(os.stat(stage).st_mode & 0o777, 0o600)
        with self.assertRaises(apply.ApplyError):
            apply.candidate_outbounds(row, {"ok": True, "connection_digest": "stale"})


class ContourIsolationTests(unittest.TestCase):
    def test_primary_uses_existing_functions(self):
        with mock.patch.object(apply, "restart_singbox", return_value=True) as restart:
            self.assertTrue(apply.restart_for({}))
            restart.assert_called_once_with()

    def test_secondary_restart_never_touches_primary(self):
        with mock.patch.object(apply, "run_cmd", return_value=(0, "")) as run, mock.patch.object(apply, "restart_singbox") as primary:
            self.assertTrue(apply.restart_for({"contour_id": "2"}))
            self.assertEqual([c.args[0] for c in run.call_args_list], [["systemctl", "stop", contours.DNS_SERVICE], ["systemctl", "restart", contours.SERVICE], ["systemctl", "start", contours.DNS_SERVICE]])
            primary.assert_not_called()

    def test_secondary_verification_uses_its_interface(self):
        with mock.patch.object(apply, "verify_egress", return_value={"ok": True}) as verify:
            apply.verify_for({"contour_id": "2"})
            verify.assert_called_once_with(interface=contours.TUN)

    def test_no_implicit_second_contour_and_invalid_registry_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = {"_source": os.path.join(directory, "config.json")}
            self.assertEqual(len(contours.public(cfg)["contours"]), 1)
            with self.assertRaises(contours.ContourError):
                contours.config(cfg)
            apply.dump_json_replace({"version": 999}, contours.registry_path(cfg))
            with self.assertRaises(contours.ContourError):
                contours.read(cfg)

    def test_wireguard_public_key_assignment_does_not_follow_reused_ip(self):
        cfg = {"subnet": "10.77.0.0/24"}
        registry = {"assignments": {"old-key": "2"}}
        text = "[Peer]\nPublicKey = new-key\nAllowedIPs = 10.77.0.2/32\n"
        with mock.patch("webpanel.clients._wg0_text", return_value=text):
            ips, _, known = contours.peer_addresses(cfg, registry)
            self.assertEqual(ips, [])
            self.assertIn("new-key", known)

    def test_request_contexts_are_independent(self):
        import contextvars
        a, b = contextvars.copy_context(), contextvars.copy_context()
        a.run(contours.CURRENT.set, "2")
        self.assertEqual(a.run(contours.CURRENT.get), "2")
        self.assertEqual(b.run(contours.CURRENT.get), "1")


if __name__ == "__main__":
    unittest.main()

class VlessCliTests(unittest.TestCase):
    def test_apply_dry_run_accepts_vless_without_fake_socks_port(self):
        import agent, contextlib, io
        from types import SimpleNamespace
        row=parse_node(uri());row.update(uid='zenxnet:test',role='auto')
        result={'ok':True,'disqualified':None,'matrix':{'443/vless':'1.1.1.1'},'exit_ip':'1.1.1.1','exit_cc':'FI','tg_ok':True,'latency_ms':12,'score':90,'socks_port':None,'http_port':None,'connection_digest':row['connection_digest']}
        with tempfile.TemporaryDirectory() as root:
            path=os.path.join(root,'sb.json');apply.dump_json_replace(_ctx.fixture('singbox_config_reference.json'),path)
            database=mock.Mock();database.get.return_value=row;out=io.StringIO()
            with mock.patch.object(agent,'open_pool',return_value=database),mock.patch.object(agent,'load_secrets',return_value=({'zenxnet': {'api_key': URL, 'hwid': HWID, 'contours': ['1']}},None)),mock.patch.object(agent,'_probe_one',return_value=result),mock.patch('shutil.which',return_value=None),contextlib.redirect_stdout(out):
                rc=agent.cmd_apply({'singbox_config':path},SimpleNamespace(uid=row['uid'],dry_run=True))
            self.assertEqual(rc,0);self.assertIn('VLESS',out.getvalue());self.assertNotIn(UUID,out.getvalue())

    def test_failed_vless_probe_has_cli_matrix(self):
        row=parse_node(uri())
        with mock.patch.object(vless,'probe_listener',side_effect=ValueError('invalid')):
            result=vless.probe(row)
        self.assertFalse(result['ok']);self.assertEqual(result['matrix'],{})


class VlessLiveFallbackTests(unittest.TestCase):
    def test_live_connection_remains_probeable_after_catalog_credentials_change(self):
        import contextlib
        import states

        original = parse_node(uri(host="1.1.1.1", port=8443))
        live = {"outbounds": [vless.outbound(original)]}
        changed = parse_node(uri(host="1.1.1.1", port=8443).replace(
            UUID, "22222222-2222-4222-8222-222222222222"))
        self.assertFalse(apply.matches_current(changed, original["host"], sb=live))
        row = states._row_from_sb(live, original["host"])
        for connected in (True, False):
            with self.subTest(connected=connected), mock.patch.object(
                    vless, "probe_listener", return_value=contextlib.nullcontext(10808)), \
                    mock.patch("probe.probe", return_value={
                        "ok": connected, "exit_ip": "1.0.0.1" if connected else None}):
                result = vless.probe(row)
                self.assertEqual(result["ok"], connected)
                self.assertEqual(result["matrix"], {"8443/vless": "1.0.0.1" if connected else None})
                self.assertEqual(result["connection_digest"], original["connection_digest"])
        self.assertEqual(vless.outbound(row), live["outbounds"][0])


class VlessCoreDnsTests(unittest.TestCase):
    def test_bootstrap_preserves_existing_resolver_and_passes_real_core(self):
        import subprocess
        row=parse_node(uri(host='1.1.1.1'))
        base={'dns':{'servers':[{'type':'https','tag':'proxy-dns','server':'1.1.1.1','detour':'socks-out'}]},
              'outbounds':[{'type':'direct','tag':'socks-out'},{'type':'direct','tag':'http-tg'}],
              'route':{'rules':[],'final':'socks-out'}}
        with tempfile.TemporaryDirectory() as root:
            path=os.path.join(root,'live.json');apply.dump_json_replace(base,path)
            stage,cfg,*_=apply.stage_candidate({'singbox_config':path},row,{'ok':True,'connection_digest':row['connection_digest']})
            self.assertEqual(cfg['route']['default_domain_resolver'],'proxy-dns')
            self.assertEqual(cfg['dns']['servers'][0],base['dns']['servers'][0])
            binary=os.environ.get('REDUT_TEST_SINGBOX')
            if binary:
                result=subprocess.run([binary,'check','-c',stage],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
            base['route']['default_domain_resolver']='redut-bootstrap'
            apply.dump_json_replace(base,path)
            _,cfg,*_=apply.stage_candidate({'singbox_config':path},row,{'ok':True,'connection_digest':row['connection_digest']})
            self.assertEqual(cfg['route']['default_domain_resolver'],'redut-bootstrap')
