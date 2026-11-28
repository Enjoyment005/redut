"""Strict DNS UI behavior and contour boundary; no services or provider calls."""
import json
import shutil
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

import _ctx  # noqa: F401
from webpanel import server, views


class StrictDnsApiTests(unittest.TestCase):
    def handler(self, body):
        handler = mock.Mock()
        handler.headers = {}
        handler._body.return_value = json.dumps(body).encode()
        handler._json.side_effect = lambda status, payload: (status, payload)
        return handler

    def test_primary_rejects_strict_before_invoking_agent(self):
        app = SimpleNamespace(cfg={"contour_id": "1"}, pool=mock.Mock())
        with mock.patch.object(server, "APP", app), \
                mock.patch.object(server, "_run_agent") as runner:
            status, result = server.Handler._api_post(
                self.handler({"mode": "provider_strict"}), "/api/dns-policy")
        self.assertEqual(status, 400)
        self.assertIn("2 контуре", result["error"])
        runner.assert_not_called()

    def test_secondary_passes_strict_mode_to_agent_and_returns_proven_status(self):
        app = SimpleNamespace(cfg={"contour_id": "2"}, pool=mock.Mock())
        public = {"mode": "provider_strict", "strict": True, "pending": False,
                  "proxy_endpoint": "10.77.0.1:10802", "service_records": "refused"}
        with mock.patch.object(server, "APP", app), \
                mock.patch.object(server, "_run_agent", return_value=(0, "{}")) as runner, \
                mock.patch.object(server.dns_policy, "status", return_value=public):
            status, result = server.Handler._api_post(
                self.handler({"mode": "provider_strict"}), "/api/dns-policy")
        runner.assert_called_once_with(
            ["dns-policy", "set", "--mode", "provider_strict"], timeout=240)
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        self.assertEqual(result["proxy_endpoint"], "10.77.0.1:10802")


_JS = r"""
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const html=fs.readFileSync(0,'utf8');
assert.match(html, /id="dns-mode"[^>]+onchange="updateDNSPolicyHelp\(\)"/);
assert.match(html, /id="dns-strict-option"[^>]+hidden disabled/);
const code=html.slice(html.indexOf('let DNS_BUSY=false;'),html.indexOf('async function reloadAll()'));
const ids=['sum_dns','dns-mode','dns-strict-option','dns-strict-help','dns-provider-help',
  'dns-cloudflare-help','dns-proxy','dns-proxy-endpoint','dns-save','dns-state'];
const nodes=Object.fromEntries(ids.map(id=>[id,{style:{},textContent:'',value:'',disabled:false,
  hidden:false,focus(){this.focused=true},select(){this.selected=true}}]));
let response={mode:'provider_strict',strict:true,available:true,pending:false,emergency:false,
  proxy_endpoint:'10.77.0.1:10802',service_records:'refused'}, saved, copied;
const context=vm.createContext({CONTOUR:'2',document:{getElementById:id=>nodes[id]},
  navigator:{clipboard:{writeText:async value=>{copied=value}}},toast:()=>{},
  api:async(path,opts)=>{assert.equal(path,'/api/dns-policy');if(opts){saved=JSON.parse(opts.body);
    response={...response,mode:saved.mode,strict:saved.mode==='provider_strict'}}return response}});
vm.runInContext(code,context);
async function run(){
  await vm.runInContext('loadDNSPolicy()',context);
  assert.equal(nodes['dns-mode'].value,'provider_strict');
  assert.equal(nodes['dns-strict-option'].hidden,false);
  assert.equal(nodes['dns-strict-option'].disabled,false);
  assert.equal(nodes['dns-strict-help'].style.display,'');
  assert.equal(nodes['dns-provider-help'].style.display,'none');
  assert.equal(nodes['dns-proxy'].style.display,'');
  assert.equal(nodes['dns-proxy-endpoint'].value,'10.77.0.1:10802');
  await vm.runInContext('copyDNSProxy()',context);
  assert.equal(copied,'10.77.0.1:10802');
  const activeState=nodes['dns-state'].textContent;
  nodes['dns-mode'].value='provider';
  vm.runInContext('updateDNSPolicyHelp()',context);
  assert.equal(nodes['dns-strict-help'].style.display,'none');
  assert.equal(nodes['dns-provider-help'].style.display,'');
  assert.equal(nodes['dns-cloudflare-help'].style.display,'none');
  nodes['dns-mode'].value='cloudflare';
  vm.runInContext('updateDNSPolicyHelp()',context);
  assert.equal(nodes['dns-provider-help'].style.display,'none');
  assert.equal(nodes['dns-cloudflare-help'].style.display,'');
  assert.equal(nodes['dns-strict-help'].style.display,'none');
  assert.equal(nodes['dns-state'].textContent,activeState);
  assert.equal(saved,undefined,'choosing a description must not apply DNS');
  nodes['dns-mode'].value='provider_strict';
  await vm.runInContext("saveDNSPolicy(document.getElementById('dns-save'))",context);
  assert.equal(saved.mode,'provider_strict');
  assert.equal(nodes['dns-save'].disabled,false);
  response={...response,mode:'cloudflare',strict:false,proxy_endpoint:null};
  await vm.runInContext('loadDNSPolicy()',context);
  assert.equal(nodes['dns-mode'].value,'cloudflare');
  assert.equal(nodes['dns-proxy'].style.display,'none');
  assert.equal(nodes['dns-proxy-endpoint'].value,'');
  response={...response,mode:'provider',pending:true};
  await vm.runInContext('loadDNSPolicy()',context);
  assert.equal(nodes['dns-mode'].disabled,true);
  assert.equal(nodes['dns-save'].disabled,true);
  context.CONTOUR='1';
  response={...response,mode:'legacy',pending:false};
  await vm.runInContext('loadDNSPolicy()',context);
  assert.equal(nodes['dns-strict-option'].hidden,true);
  assert.equal(nodes['dns-strict-option'].disabled,true);
  assert.equal(nodes['dns-proxy'].style.display,'none');
  assert.match(nodes['dns-state'].textContent,/DNS самого сервера/);
}
run().catch(error=>{console.error(error);process.exitCode=1});
"""


@unittest.skipUnless(shutil.which("node"), "Node.js is required for rendered panel checks")
class StrictDnsUiTests(unittest.TestCase):
    def test_rendered_controls_follow_active_contour_and_applied_mode(self):
        result = subprocess.run(["node", "-e", _JS],
                                input=views.dashboard_page("test", "synthetic-csrf"),
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
