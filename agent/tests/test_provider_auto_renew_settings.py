# -*- coding: utf-8 -*-
"""Opt-in provider billing settings: real schema/server, isolated process boundary."""
import ast
import contextlib
from email.message import Message
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import _ctx  # noqa: F401
import config_schema
from webpanel import server, views


FLAG = "proxywing_provider_auto_renew"
PATH = "auto_prolong." + FLAG
PANEL = Path(__file__).resolve().parents[1]
ROOT = PANEL.parent


def literal_assignment(path, name):
    """Read packaging declarations without loading machine credentials."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == name
                for target in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError("Missing declaration: " + name)


class TestProviderAutoRenewSchema(unittest.TestCase):
    def test_legacy_config_defaults_provider_autopay_to_false(self):
        cfg = config_schema.normalize({"auto_prolong": {"enabled": True}})
        self.assertIs(cfg["auto_prolong"].get(FLAG), False)

    def test_provider_autopay_requires_json_boolean(self):
        for value in ("true", "false", "yes", 1, 0, None, [], {}):
            with self.subTest(value=value):
                cfg = config_schema.normalize({"auto_prolong": {FLAG: value}})
                self.assertIs(cfg["auto_prolong"][FLAG], False)
                issue = next(item for item in cfg["_config_meta"]["issues"]
                             if item["path"] == PATH)
                self.assertEqual(issue["action"], "disabled")
                self.assertEqual(cfg["_config_meta"]["sources"][PATH], "safe-default")
        for value in (True, False):
            cfg = config_schema.normalize({"auto_prolong": {FLAG: value}})
            self.assertIs(cfg["auto_prolong"][FLAG], value)

    def test_safe_mode_disables_provider_autopay_with_safe_source(self):
        cfg = config_schema.normalize({"config_schema_version": 999,
                                       "auto_prolong": {FLAG: True}})
        self.assertIs(cfg["auto_prolong"][FLAG], False)
        self.assertEqual(cfg["_config_meta"]["sources"][PATH], "safe-default")


class TestProviderAutoRenewApi(unittest.TestCase):
    """Exercise real HTTP parsing, sessions and CSRF with a mocked child process."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config_path = Path(self.tmp.name) / "config.json"
        self.raw = {"config_schema_version": config_schema.CURRENT_VERSION,
                    "server": "test", "role": "test",
                    "db": str(Path(self.tmp.name) / "state.db"),
                    "ring": str(Path(self.tmp.name) / "ring"),
                    "auto_prolong": {"enabled": True, FLAG: False},
                    "owner_data": {"keep": "unchanged"}}
        self.save_config()
        secrets_path = Path(self.tmp.name) / "secrets.json"
        secrets_path.write_text(json.dumps({"admin": {"pw": "dummy", "totp": "DUMMY"}}))
        env = mock.patch.dict(os.environ, {"VPN_PANEL_CONFIG": str(self.config_path),
                                          "VPN_PANEL_SECRETS": str(secrets_path)})
        env.start()
        self.addCleanup(env.stop)
        self.app = server.App()
        self.addCleanup(self.app.pool.close)
        app_patch = mock.patch.object(server, "APP", self.app)
        app_patch.start()
        self.addCleanup(app_patch.stop)
        self.token, self.csrf = self.app.store.create_session("127.0.0.1")

    def save_config(self):
        self.config_path.write_text(json.dumps(self.raw), encoding="utf-8")

    def request(self, method="POST", payload=None, session=True, csrf=True):
        handler = object.__new__(server.Handler)
        handler.path = "/api/provider-auto-renew"
        handler.command = method
        handler.client_address = ("127.0.0.1", 12345)
        handler.headers = Message()
        body = json.dumps(payload if payload is not None else {}).encode("utf-8")
        handler.headers["Content-Length"] = str(len(body))
        if session:
            handler.headers["Cookie"] = server.auth.COOKIE_NAME + "=" + self.token
        if csrf:
            handler.headers["X-CSRF-Token"] = self.csrf
        handler.rfile = io.BytesIO(body)
        result = []
        handler._json = lambda code, value, extra=None: result.append((code, value))
        getattr(handler, "do_" + method)()
        self.assertEqual(len(result), 1)
        return result[0]

    def test_post_delegates_config_persistence_to_cli_without_reflecting_stdout(self):
        def child_process(args, **kwargs):
            # Model only the process boundary; schema + HTTP handler remain real.
            self.raw["auto_prolong"][FLAG] = args[-1] == "--enable"
            self.save_config()
            return 0, "dummy-private-child-output"

        with mock.patch.object(server, "_run_agent", side_effect=child_process) as run:
            for enabled in (True, False):
                with self.subTest(enabled=enabled):
                    code, body = self.request(payload={"enabled": enabled})
                    self.assertEqual(code, 200)
                    run.assert_called_with(["provider-auto-renew", "--enable" if enabled else "--disable"])
                    self.assertIs(body["enabled"], enabled)
                    self.assertIs(body["ok"], True)
                    self.assertNotIn("dummy-private-child-output", json.dumps(body))
                    self.assertNotIn("output", body)
                    self.assertEqual(json.loads(self.config_path.read_text())["owner_data"],
                                     {"keep": "unchanged"})

    def test_get_reports_fresh_opt_in_and_real_local_ownership_without_network(self):
        import proxywing_autopay
        self.raw["auto_prolong"][FLAG] = True
        self.save_config()
        journal = {"version": 1,
                   "observation": None,
                   "owned": [{"family": "datacenter", "order_id": "order-test",
                              "service_id": "service-test", "phase": "owned",
                              "next_due_date": "2027-01-01", "submitted": True,
                              "credential_identity": "a" * 64}],
                   "last": {"ok": False, "pending_cleanup": True}}
        self.app.pool.set_setting(proxywing_autopay.STATE_KEY, json.dumps(journal))
        with mock.patch.object(server, "_run_agent") as run:
            code, body = self.request(method="GET")
        self.assertEqual(code, 200)
        self.assertIs(body["enabled"], True)
        self.assertIs(body["auto_prolong_enabled"], True)
        self.assertEqual(body["state"], proxywing_autopay.status(self.app.pool))
        self.assertIs(body["state"]["pending_cleanup"], True)
        self.assertEqual(len(body["state"]["owned"]), 1)
        self.assertEqual(body["state"]["owned"][0]["service_id"], "service-test")
        self.assertNotIn("a" * 64, json.dumps(body))
        run.assert_not_called()

    def test_zero_exit_cannot_claim_success_without_persisted_opt_in(self):
        with mock.patch.object(server, "_run_agent", return_value=(0, "dummy-private-output")):
            code, body = self.request(payload={"enabled": True})
        self.assertEqual(code, 409)
        self.assertIs(body["ok"], False)
        self.assertIs(body["enabled"], False)
        self.assertNotIn("dummy-private-output", json.dumps(body))

    def test_cli_failure_is_generic_and_does_not_write_config(self):
        before = self.config_path.read_bytes()
        with mock.patch.object(server, "_run_agent", return_value=(1, "dummy-private-failure")):
            code, body = self.request(payload={"enabled": True})
        self.assertEqual(code, 409)
        self.assertIs(body["ok"], False)
        self.assertIn("error", body)
        self.assertNotIn("dummy-private-failure", json.dumps(body))
        self.assertEqual(self.config_path.read_bytes(), before)

    def test_unauthorized_requests_cannot_run_cli(self):
        with mock.patch.object(server, "_run_agent") as run:
            self.assertEqual(self.request(payload={"enabled": True}, session=False)[0], 401)
            self.assertEqual(self.request(method="GET", session=False)[0], 401)
            self.assertEqual(self.request(payload={"enabled": True}, csrf=False)[0], 403)
        run.assert_not_called()

    def test_invalid_toggle_payload_cannot_run_cli(self):
        before = self.config_path.read_bytes()
        with mock.patch.object(server, "_run_agent") as run:
            for value in (None, "true", "false", "yes", 1, 0, [], {}):
                with self.subTest(value=value):
                    self.assertEqual(self.request(payload={"enabled": value})[0], 400)
            for payload in ({}, [], True):
                self.assertEqual(self.request(payload=payload)[0], 400)
        run.assert_not_called()
        self.assertEqual(self.config_path.read_bytes(), before)

    def test_panel_loader_has_explicit_opt_in_false_default(self):
        self.raw["auto_prolong"].pop(FLAG)
        self.save_config()
        cfg = server.load_config()
        self.assertIs(cfg["auto_prolong"][FLAG], False)
        self.assertEqual(cfg["_config_meta"]["sources"][PATH], "default")

    def test_unverified_domain_state_cannot_claim_toggle_success(self):
        import proxywing_autopay
        self.app.pool.set_setting(proxywing_autopay.STATE_KEY, "{invalid")
        def child_process(_args):
            self.raw["auto_prolong"][FLAG] = True
            self.save_config()
            return 0, "dummy-private-output"
        with mock.patch.object(server, "_run_agent", side_effect=child_process):
            code, body = self.request(payload={"enabled": True})
        self.assertEqual(code, 409)
        self.assertIs(body["enabled"], True)
        self.assertIs(body["ok"], False)
        self.assertIs(body["state"]["pending_cleanup"], True)


class TestProviderAutoRenewUi(unittest.TestCase):
    def test_settings_explains_provider_billing_and_has_separate_switch(self):
        html = views.dashboard_page("test", "dummy-csrf")
        for text in ('id="card_settings"', "Автоплатёж ProxyWing для боевого прокси",
                     'id="pw_autopay_toggle"', 'role="switch"',
                     "billing cycle", "баланса ProxyWing", "без локальных лимитов Редута",
                     "не оплачивает текущий invoice", "Чужой включённый автоплатёж",
                     "несколькими прокси", "при смене боевого прокси",
                     "proxywing_months=1", "3/6/12"):
            self.assertTrue(text in html, "Missing settings copy/control: " + text)

    def test_actual_js_loads_fresh_state_and_posts_explicit_boolean_with_csrf(self):
        harness = r"""
const assert = require('node:assert/strict'), vm = require('node:vm');
let source=''; process.stdin.on('data', x => source+=x);
process.stdin.on('end', async () => {try {
  new vm.Script(source); // Compile the whole generated dashboard, not a stub.
  const start=source.indexOf('let __providerAutoRenew='), end=source.indexOf('/* ── стратегия выбора стран', start);
  assert.ok(start>=0 && end>start, 'missing actual billing UI functions');
  const elements=new Map(), requests=[], confirmations=[];
  const el=id=>{if(!elements.has(id))elements.set(id,{textContent:'',disabled:true,className:'',attributes:{},
    setAttribute(k,v){this.attributes[k]=v}});return elements.get(id)};
  let enabled=false;
  const ctx=vm.createContext({CSRF:'dummy-csrf',document:{getElementById:el},
    sum(){},toast(){},confirm:text=>{confirmations.push(text);return true},
    fetch:async(url, opts={})=>{requests.push({url,...opts});
      assert.equal(url,'/api/provider-auto-renew');
      assert.equal(opts.headers['X-CSRF-Token'],'dummy-csrf');
      if(opts.method==='POST')enabled=JSON.parse(opts.body).enabled;
      return {ok:true,text:async()=>JSON.stringify({ok:true,enabled,auto_prolong_enabled:true,
        state:{ok:true,owned:[],pending_cleanup:!enabled}})};
    }});
  const apiStart=source.indexOf('async function api('), apiEnd=source.indexOf('\nfunction fl(',apiStart);
  vm.runInContext(source.slice(apiStart,apiEnd)+source.slice(start,end),ctx);
  await vm.runInContext('loadProviderAutoRenew()',ctx);
  const button=el('pw_autopay_toggle');
  assert.equal(button.attributes['aria-checked'],'false');assert.equal(button.disabled,false);
  assert.match(el('pw_autopay_status').textContent,/отключени/i);
  await vm.runInContext('toggleProviderAutoRenew(document.getElementById("pw_autopay_toggle"))',ctx);
  const post=requests.find(x=>x.method==='POST');
  assert.deepEqual(JSON.parse(post.body),{enabled:true});
  assert.equal(post.headers['Content-Type'],'application/json');
  assert.equal(button.attributes['aria-checked'],'true');
  assert.match(confirmations[0],/без локальных лимитов Редута/);
  assert.match(confirmations[0],/не оплачивает текущий invoice/);
  await vm.runInContext('toggleProviderAutoRenew(document.getElementById("pw_autopay_toggle"))',ctx);
  assert.deepEqual(JSON.parse(requests.filter(x=>x.method==='POST')[1].body),{enabled:false});
  assert.equal(button.attributes['aria-checked'],'false');
  assert.equal(button.disabled,false);
  assert.match(el('pw_autopay_status').textContent,/отключени/i);
  const foldsStart=source.indexOf('const FOLDS='),foldsEnd=source.indexOf('const FOLD_MEM=',foldsStart);
  vm.runInContext(source.slice(foldsStart,foldsEnd),ctx);
  assert.equal(vm.runInContext('FOLD_ORDER.includes("settings")',ctx),true);
  await vm.runInContext('FOLDS.settings.load()',ctx);
  console.log('actual UI: load, enable, disable, CSRF, cleanup, fold wiring PASS');
} catch(e) {console.error(e);process.exitCode=1}});
"""
        self.run_ui(harness)

    def run_ui(self, harness):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js required for UI behavior")
        script = re.search(r"<script>(.*?)</script>",
                           views.dashboard_page("test", "dummy-csrf"), re.S).group(1)
        proc = subprocess.run([node, "-e", harness], input=script, text=True,
                              capture_output=True, timeout=20,
                              env={"PATH": os.environ.get("PATH", "")})
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_ui_does_not_reuse_stale_toggle_after_failed_status_read(self):
        self.run_ui(r"""
const assert=require('node:assert/strict'),vm=require('node:vm');
let source='';process.stdin.on('data',x=>source+=x);process.stdin.on('end',async()=>{try{
  const start=source.indexOf('let __providerAutoRenew='),end=source.indexOf('/* ── стратегия выбора стран',start);
  assert.ok(start>=0 && end>start);
  const elements=new Map();const el=id=>{if(!elements.has(id))elements.set(id,{textContent:'',disabled:true,className:'',setAttribute(){}});return elements.get(id)};
  let fail=false,cancel=false,calls=0;
  const ctx=vm.createContext({document:{getElementById:el},sum(){},toast(){},confirm:()=>!cancel,
    api:async()=>{calls++;if(fail)throw Error('status unavailable');return {enabled:false,auto_prolong_enabled:true,state:{}}}});
  vm.runInContext(source.slice(start,end),ctx);
  await vm.runInContext('loadProviderAutoRenew()',ctx);
  cancel=true;
  await vm.runInContext('toggleProviderAutoRenew(document.getElementById("pw_autopay_toggle"))',ctx);
  assert.equal(calls,1,'cancel must not request mutation');cancel=false;
  fail=true;await vm.runInContext('loadProviderAutoRenew()',ctx);
  assert.equal(el('pw_autopay_toggle').disabled,true,'stale state must disable control');
  await vm.runInContext('toggleProviderAutoRenew(document.getElementById("pw_autopay_toggle"))',ctx);
  assert.equal(calls,2,'stale state cannot request mutation');
  fail=false;await vm.runInContext('loadProviderAutoRenew()',ctx);
  fail=true;
  await vm.runInContext('toggleProviderAutoRenew(document.getElementById("pw_autopay_toggle"))',ctx);
  assert.equal(el('pw_autopay_toggle').disabled,true,'failed POST and failed readback stay disabled');
  console.log('UI: cancellation and stale/readback failure PASS');
}catch(e){console.error(e);process.exitCode=1}});
""")


class TestProviderAutoRenewPackaging(unittest.TestCase):
    def test_isolated_install_copies_module_and_preserves_explicit_opt_in(self):
        spec = importlib.util.spec_from_file_location(
            "settings_installer", ROOT / "install/setup_panel.py")
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        with tempfile.TemporaryDirectory() as temp:
            installer.OPT = str(Path(temp) / "opt")
            installer.ETC = str(Path(temp) / "etc")
            Path(installer.OPT).mkdir()
            Path(installer.ETC).mkdir()
            net = {"gw": "192.0.2.1", "wan": "eth-test", "server_ip": "192.0.2.10"}
            with contextlib.redirect_stdout(io.StringIO()):
                installer.copy_files(str(PANEL), with_panel=False)
                installer.write_config("test", net, 8443, "10.77.0.0/24", 51820, False)
            installed = Path(installer.OPT) / "proxywing_autopay.py"
            self.assertEqual(installed.read_bytes(), (PANEL / installed.name).read_bytes())
            path = Path(installer.ETC) / "config.json"
            cfg = json.loads(path.read_text())
            self.assertIs(cfg["auto_prolong"][FLAG], False)
            cfg["auto_prolong"].update({FLAG: True, "days_before": 9, "custom_owner_field": 42})
            path.write_text(json.dumps(cfg))
            with contextlib.redirect_stdout(io.StringIO()):
                installer.write_config("renamed", net, 9443, "10.77.0.0/24", 51820, False)
            updated = json.loads(path.read_text())
            self.assertEqual(updated["auto_prolong"], cfg["auto_prolong"])

    def test_installer_and_deployer_default_provider_autopay_to_false(self):
        defaults = literal_assignment(ROOT / "install/setup_panel.py", "DEFAULTS")
        deploy = literal_assignment(PANEL / "deploy.py", "MONEY_CONFIG")
        for cfg in (defaults, deploy):
            self.assertIs(cfg["auto_prolong"].get(FLAG), False)

    def test_all_runtime_packages_include_autopay_before_agent(self):
        for path in (ROOT / "install/setup_panel.py", PANEL / "deploy.py"):
            files = literal_assignment(path, "AGENT_FILES")
            self.assertIn("proxywing_autopay.py", files)
            self.assertLess(files.index("proxywing_autopay.py"), files.index("agent.py"))
            self.assertLess(files.index("providers/base.py"), files.index("providers/proxywing.py"))
            self.assertLess(files.index("providers/proxywing.py"), files.index("proxywing_autopay.py"))
            self.assertEqual(files.count("providers/proxywing.py"), 1)
        # Public mirror has no scripts directory; canonical-only builder checks.
        builder = ROOT.parent / "scripts/build_public.py"
        if builder.is_file():
            self.assertIn(("panel/proxywing_autopay.py", "agent/proxywing_autopay.py"),
                          literal_assignment(builder, "COPY"))


if __name__ == "__main__":
    unittest.main()
