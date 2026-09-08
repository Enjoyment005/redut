"""Full-audit regressions: TLS, saved clients, rollback events and atomic schema."""
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import _ctx  # noqa: F401
import alerts
import metrics
import pool
from webpanel import clients, server, views


class TestSMTPEncryption(unittest.TestCase):
    def sender(self, port=587):
        return alerts.Alerter(smtp={
            "host": "smtp.example.invalid", "port": port,
            "user": "sender@example.invalid", "password": "synthetic-password",
            "to": "owner@example.invalid"}, log=lambda _: None)

    def test_starttls_refusal_never_authenticates_or_sends(self):
        for error in (alerts.smtplib.SMTPNotSupportedError("no STARTTLS"),
                      alerts.smtplib.SMTPResponseException(454, b"TLS unavailable"),
                      alerts.ssl.SSLCertVerificationError("certificate invalid")):
            with self.subTest(error=type(error).__name__):
                smtp = mock.MagicMock()
                smtp.__enter__.return_value = smtp
                smtp.starttls.side_effect = error
                sender = self.sender()
                with mock.patch.object(alerts.smtplib, "SMTP", return_value=smtp):
                    self.assertFalse(sender.send("test", "synthetic body"))
                self.assertTrue(sender.last_error)
                smtp.login.assert_not_called()
                smtp.send_message.assert_not_called()

    def test_successful_starttls_and_smtps_keep_certificate_validation(self):
        for port, transport in ((587, "SMTP"), (465, "SMTP_SSL")):
            with self.subTest(port=port):
                smtp = mock.MagicMock()
                smtp.__enter__.return_value = smtp
                with mock.patch.object(alerts.smtplib, transport, return_value=smtp) as ctor:
                    self.assertTrue(self.sender(port).send("test", "synthetic body"))
                ctx = (ctor.call_args.kwargs["context"] if port == 465
                       else smtp.starttls.call_args.kwargs["context"])
                self.assertTrue(ctx.check_hostname)
                self.assertEqual(ctx.verify_mode, alerts.ssl.CERT_REQUIRED)
                smtp.login.assert_called_once()
                smtp.send_message.assert_called_once()
                if port == 587:
                    self.assertEqual([call[0] for call in smtp.method_calls],
                                     ["ehlo", "starttls", "ehlo", "login", "send_message"])
                else:
                    smtp.starttls.assert_not_called()


class TestSavedClientName(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.patch = mock.patch.object(clients, "CLIENTS_DIR", self.tmp.name)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def saved_profile(self, name, address):
        content = "[Interface]\nAddress = %s/32\n" % address
        Path(self.tmp.name, name + ".conf").write_text(content, encoding="utf-8")
        return content

    def listing(self, names):
        text = "[Interface]\n" + "".join(
            "[Peer]\n# %s\nPublicKey = pub-%d\nAllowedIPs = 10.8.0.%d/32\n"
            % (name, index, index + 2) for index, name in enumerate(names))
        with mock.patch.object(clients, "server_params", return_value={"text": text}), \
             mock.patch.object(clients, "_wg_dump", return_value={}):
            return clients.list_clients({"subnet": "10.8.0.0/24"})

    def test_display_name_and_stored_name_are_separate(self):
        for display_name in ("My Phone", "alias"):
            with self.subTest(display_name=display_name):
                expected = self.saved_profile("phone", "10.8.0.2")
                row = self.listing([display_name])[0]
                self.assertTrue(row["has_conf"])
                self.assertEqual(row["name"], display_name)
                self.assertEqual(row["conf_name"], "phone")
                self.assertEqual(clients.client_conf_text(row["conf_name"]), expected)

    def test_duplicate_display_names_resolve_selected_peer(self):
        expected = [self.saved_profile("phone", "10.8.0.2"),
                    self.saved_profile("tablet", "10.8.0.3")]
        rows = self.listing(["Same name", "Same name"])
        self.assertEqual([row["conf_name"] for row in rows], ["phone", "tablet"])
        self.assertEqual([clients.client_conf_text(row["conf_name"]) for row in rows], expected)
        self.assertEqual([row["pubkey"] for row in rows], ["pub-0", "pub-1"])

    def test_ambiguous_profile_stays_unavailable(self):
        self.saved_profile("phone", "10.8.0.2")
        self.saved_profile("duplicate", "10.8.0.2")
        row = self.listing(["My Phone"])[0]
        self.assertFalse(row["has_conf"])
        self.assertIsNone(row["conf_name"])
        self.assertTrue(row["unsupported"])


class TestRollbackMetrics(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = pool.Pool(os.path.join(self.tmp.name, "state.db"))
        self.addCleanup(self.db.close)

    def test_handler_event_counts_in_metrics(self):
        self.db.log_event("rotate", result="ok", actor="auto")
        app = SimpleNamespace(pool=self.db, saga_pool=self.db, cfg={})
        handler = mock.Mock()
        handler._client_ip.return_value = "127.0.0.1"
        handler._json.side_effect = lambda code, payload: (code, payload)
        result = {"ok": True, "bad_ip": "198.51.100.2", "good_ip": "198.51.100.1",
                  "verify": {"egress_ip": "198.51.100.1", "ok": True}}
        with mock.patch.object(server, "APP", app), \
             mock.patch.object(server.apply_mod, "rollback_from_ring", return_value=result), \
             mock.patch.object(server.apply_mod, "commit_operation"), \
             mock.patch.object(server.states_mod, "finish_explicit_apply", return_value={"ok": True}):
            code, response = server.Handler._api_post(handler, "/api/rollback")
        self.assertEqual(code, 200)
        self.assertTrue(response["ok"])
        raw = self.db.conn.execute("SELECT detail FROM event WHERE action='rollback'").fetchone()[0]
        self.assertEqual(json.loads(raw), {"bad_ip": result["bad_ip"], "good_ip": result["good_ip"]})
        switches = metrics.local_report(self.db)["switches"]
        self.assertEqual((switches["rollbacks"], switches["false_switches"],
                          switches["rollback_unknown"]), (1, 1, 0))

    def test_legacy_and_current_formats_are_read_without_rewriting_history(self):
        for names in (("bad", "good"), ("bad_ip", "good_ip")):
            with self.subTest(names=names):
                self.db.conn.execute("DELETE FROM event")
                self.db.conn.commit()
                self.db.log_event("rotate", actor="auto", result="ok")
                self.db.log_event("rollback", result="ok", detail=json.dumps(
                    dict(zip(names, ("198.51.100.2", "198.51.100.1")))))
                self.db.log_event("rollback", result="ok", detail=json.dumps(
                    dict(zip(names, ("198.51.100.1", "198.51.100.1")))))
                before = list(self.db.conn.execute("SELECT * FROM event"))
                switches = metrics.local_report(self.db)["switches"]
                self.assertEqual((switches["rollbacks"], switches["false_switches"],
                                  switches["rollback_unknown"]), (1, 1, 0))
                self.assertEqual(list(self.db.conn.execute("SELECT * FROM event")), before)


class TestAtomicSchemaMigration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "state.db")
        db = pool.Pool(self.path)
        db.conn.execute("ALTER TABLE proxy DROP COLUMN order_id")
        db.set_setting("retained", "user-setting")
        db.close()

    def connect(self):
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def test_two_migrators_use_one_schema_snapshot_at_a_time(self):
        first_read, second_arrived, first_done = (threading.Event() for _ in range(3))

        class ConcurrentConnection:
            """Force the old duplicate-ALTER race without blocking serialized migration."""
            def __init__(self, conn, index):
                self.conn, self.index, self.once, self.began = conn, index, False, False

            def execute(self, sql, *args):
                if sql == "BEGIN IMMEDIATE":
                    self.began = True
                    if self.index == 1:
                        second_arrived.set()
                cursor = self.conn.execute(sql, *args)
                if sql == "PRAGMA table_info(proxy)" and not self.once:
                    self.once = True
                    snapshot = list(cursor)
                    if self.index == 0:
                        first_read.set()
                        if not second_arrived.wait(5):
                            raise TimeoutError("second migrator did not start")
                    elif not self.began:
                        second_arrived.set()
                        if not first_done.wait(5):
                            raise TimeoutError("first migrator did not finish")
                    return iter(snapshot)
                return cursor

            def __getattr__(self, name):
                return getattr(self.conn, name)

        def migrate_worker(index):
            if index == 1 and not first_read.wait(5):
                return "first schema snapshot missing"
            conn = self.connect()
            try:
                pool.migrate(ConcurrentConnection(conn, index), self.path)
                return "ok"
            except Exception as error:
                return type(error).__name__ + ": " + str(error)
            finally:
                conn.close()
                if index == 0:
                    first_done.set()

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(migrate_worker, range(2)))
        self.assertEqual(outcomes, ["ok", "ok"])
        with self.connect() as conn:
            self.assertEqual([row[1] for row in conn.execute("PRAGMA table_info(proxy)")].count("order_id"), 1)
            self.assertEqual(conn.execute("SELECT value FROM setting WHERE key='retained'").fetchone()[0], "user-setting")
        conn.close()

    def test_failed_migration_rolls_back_ddl_and_releases_transaction(self):
        conn = self.connect()
        self.addCleanup(conn.close)

        class FailingConnection:
            def execute(self, sql, *args):
                if sql.startswith("UPDATE setting SET value=? WHERE key='schema_version'"):
                    raise sqlite3.OperationalError("synthetic interrupted migration")
                return conn.execute(sql, *args)

            def __getattr__(self, name):
                return getattr(conn, name)

        with self.assertRaisesRegex(sqlite3.OperationalError, "synthetic"):
            pool.migrate(FailingConnection(), self.path)
        self.assertNotIn("order_id", {row[1] for row in conn.execute("PRAGMA table_info(proxy)")})
        self.assertFalse(conn.in_transaction)
        pool.migrate(conn, self.path)
        self.assertIn("order_id", {row[1] for row in conn.execute("PRAGMA table_info(proxy)")})

    def test_caller_transaction_is_rejected_without_commit_or_rollback(self):
        conn = self.connect()
        self.addCleanup(conn.close)
        conn.execute("UPDATE setting SET value='uncommitted' WHERE key='retained'")
        with self.assertRaises(sqlite3.OperationalError):
            pool.migrate(conn, self.path)
        self.assertTrue(conn.in_transaction)
        self.assertEqual(conn.execute("SELECT value FROM setting WHERE key='retained'").fetchone()[0], "uncommitted")
        conn.rollback()
        self.assertEqual(conn.execute("SELECT value FROM setting WHERE key='retained'").fetchone()[0], "user-setting")
        self.assertNotIn("order_id", {row[1] for row in conn.execute("PRAGMA table_info(proxy)")})


CLIENT_UI = r"""
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const html=fs.readFileSync(process.argv[1],'utf8');
const source=html.slice(html.indexOf('async function loadClients(){'),html.indexOf('async function addClient(){'));
const rows=[],calls=[],elements=new Map();
const table={innerHTML:'',appendChild:row=>rows.push(row)};
const clients=[{name:'My Phone',conf_name:'phone',pubkey:'pub-0',has_conf:true},
  {name:'My Phone',conf_name:'tablet',pubkey:'pub-1',has_conf:true}];
function row(){const buttons=new Map();return {innerHTML:'',querySelector:name=>{
  if(!buttons.has(name))buttons.set(name,{addEventListener:(kind,callback)=>buttons.get(name)[kind]=callback});
  return buttons.get(name)}}}
const context=vm.createContext({api:async()=>({clients,can_add:true}),document:{querySelector:()=>table,
  createElement:row,getElementById:id=>{if(!elements.has(id))elements.set(id,{style:{}});return elements.get(id)}},
  window:{},esc:String,ago:()=>'',fbytes:()=>'',sum:()=>{},vitals:()=>{},clientRec:()=>{},
  dlClient:name=>calls.push(['download',name]),qrClient:name=>calls.push(['qr',name]),
  delClient:(name,pub)=>calls.push(['revoke',name,pub])});
vm.runInContext(source,context);
(async()=>{await vm.runInContext('loadClients()',context);
  for(const row of rows){for(const name of ['download','qr','revoke'])row.querySelector('.client-'+name).click()}
  assert.deepEqual(calls,[['download','phone'],['qr','phone'],['revoke','My Phone','pub-0'],
    ['download','tablet'],['qr','tablet'],['revoke','My Phone','pub-1']]);
  console.log('Saved client profile UI PASS');
})().catch(error=>{console.error(error);process.exitCode=1});
"""


@unittest.skipUnless(shutil.which("node"), "Node.js is required for rendered dashboard tests")
class TestRenderedPanel(unittest.TestCase):
    def run_node(self, *args):
        with tempfile.TemporaryDirectory() as tmp:
            page = Path(tmp, "dashboard.html")
            page.write_text(views.dashboard_page("audit", "synthetic-csrf"), encoding="utf-8")
            result = subprocess.run(["node", *args, str(page)], capture_output=True,
                                    text=True, encoding="utf-8", timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_proxyline_rendered_renewal_button(self):
        self.run_node(str(Path(__file__).with_name("proxyline_ui_regression.js")))

    def test_client_download_qr_and_revoke_use_correct_identifiers(self):
        self.run_node("-e", CLIENT_UI)
