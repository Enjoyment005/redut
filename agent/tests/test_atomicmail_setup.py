"""AtomicMail onboarding: only the proven recipient can enable notifications."""
import hashlib,json,pathlib,re,sqlite3,tempfile,time,unittest
from types import SimpleNamespace
from unittest import mock
import _ctx  # noqa: F401
from webpanel import auth,server,views


class AtomicMailSetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=pathlib.Path(self.tmp.name)/'secrets.json'
        self.sender={'api_key':'your_atomic_api_key_here','address':'test@atomicmail.ai','status':'ready','installation_id':'stable-id'}
        auth.write_secrets_atomic(str(self.path),{'atomicmail':self.sender})
        self.db=sqlite3.connect(':memory:');self.addCleanup(self.db.close)
        self.app=SimpleNamespace(cfg={'mail_transport':'atomicmail'},setup={},secrets_path=str(self.path),
            provisioned=False,store=auth.AuthStore(self.db),pool=mock.Mock(),reload_secrets=mock.Mock(),
            bootstrap_path=str(pathlib.Path(self.tmp.name)/'bootstrap.json'))
        patch=mock.patch.object(server,'APP',self.app);patch.start();self.addCleanup(patch.stop)
        self.h=object.__new__(server.Handler);self.h._json=lambda status,payload:(status,payload)
        self.h._client_ip=lambda:'127.0.0.1'
        patch=mock.patch.object(server.atomicmail,'status',return_value={'ready':True,'address':'test@atomicmail.ai'})
        patch.start();self.addCleanup(patch.stop)
        self.sent=[]
        def send(path,to,subject,body):self.sent.append((path,to,subject,body))
        patch=mock.patch.object(server.atomicmail,'send',side_effect=send)
        self.send=patch.start();self.addCleanup(patch.stop)

    def send_pin(self):
        result=self.h._setup_smtp_test({'to':'owner@example.com'})
        self.code=re.search(r'Код проверки: (\d{6})',self.sent[-1][-1]).group(1)
        return result

    def verify(self,**extra):
        return self.h._setup_smtp(dict({'to':'owner@example.com','code':self.code},**extra))

    def finish(self):
        self.app.setup.update(pw='test-password',totp='synthetic',totp_ok=True,providers={'proxy6':'synthetic-provider-key'})
        with mock.patch.object(server.threading,'Thread'):
            return self.h._setup_finish()

    def test_email_only_pin_and_finish_keep_sender_and_store_proven_recipient(self):
        status,payload=self.send_pin();self.assertEqual(status,200)
        self.assertNotIn(self.code,json.dumps(payload))
        self.assertNotIn('code',self.app.setup['mail_pending'])
        self.assertNotIn('mail',json.loads(self.path.read_text()))
        self.assertEqual(self.verify()[0],200)
        self.assertEqual(self.finish()[0],200)
        saved=json.loads(self.path.read_text())
        self.assertEqual(saved['atomicmail'],self.sender)
        self.assertEqual(saved['mail'],{'to':'owner@example.com'})
        self.assertNotIn('smtp',saved)
        self.assertIn('admin',saved);self.assertEqual(saved['proxy6']['api_key'],'synthetic-provider-key')

    def test_wrong_code_has_finite_attempts(self):
        self.send_pin();wrong='0'*6 if self.code!='0'*6 else '1'*6
        for _ in range(self.h.CODE_TRIES):self.assertEqual(self.verify(code=wrong)[0],400)
        self.assertEqual(self.verify()[0],400)
        self.assertNotIn('mail_to',self.app.setup)

    def test_expired_pin_and_edited_recipient_require_new_test(self):
        self.send_pin();self.app.setup['mail_pending']['at']-=self.h.CODE_TTL_S+1
        self.assertTrue(self.verify()[1]['need_test'])
        self.app.setup['mail_last_sent']=0;self.send_pin()
        self.assertTrue(self.verify(to='different@example.com')[1]['need_test'])
        self.assertNotIn('mail_to',self.app.setup)

    def test_skip_keeps_sender_but_disables_notifications(self):
        self.assertEqual(self.h._setup_smtp({'skip':True})[0],200)
        self.assertEqual(self.finish()[0],200)
        saved=json.loads(self.path.read_text())
        self.assertEqual(saved['atomicmail'],self.sender);self.assertEqual(saved['mail'],{})

    def test_finish_requires_pin_or_explicit_skip(self):
        self.assertEqual(self.finish()[0],400)
        self.send_pin();self.assertEqual(self.finish()[0],400)
        self.assertNotIn('admin',json.loads(self.path.read_text()))

    def test_resend_is_rate_limited_and_bad_address_never_sends(self):
        self.assertEqual(self.h._setup_smtp_test({'to':'bad-address'})[0],400)
        self.send.assert_not_called()
        self.send_pin();self.assertEqual(self.h._setup_smtp_test({'to':'owner@example.com'})[0],429)
        self.assertEqual(self.send.call_count,1)

    def test_unknown_outcome_allows_received_pin_without_retry(self):
        real_side_effect=self.send.side_effect
        def uncertain(*args):
            real_side_effect(*args)
            raise server.atomicmail.AtomicMailError('send_unknown','unknown',unknown=True)
        self.send.side_effect=uncertain
        status,payload=self.send_pin();self.assertEqual(status,202);self.assertFalse(payload['sent'])
        self.assertEqual(self.verify()[0],200);self.assertEqual(self.send.call_count,1)

    def test_known_failure_does_not_leave_verifiable_pending_pin(self):
        self.send.side_effect=server.atomicmail.AtomicMailError('send_rejected','Rejected')
        self.assertEqual(self.h._setup_smtp_test({'to':'owner@example.com'})[0],503)
        self.assertNotIn('mail_pending',self.app.setup)

    def test_prepare_reuses_ready_sender_or_retries_not_ready(self):
        with mock.patch.object(server.atomicmail,'ensure_ready',return_value={'ready':True}) as prepare:
            self.assertEqual(self.h._setup_mail_prepare()[0],200);prepare.assert_not_called()
            with mock.patch.object(server.atomicmail,'status',return_value={'ready':False}):
                self.assertEqual(self.h._setup_mail_prepare()[1],{'ready':True})
            prepare.assert_called_once_with(str(self.path))

    def test_prepare_unexpected_failure_does_not_leak_credentials(self):
        with mock.patch.object(server.atomicmail,'status',side_effect=RuntimeError('your_atomic_api_key_here')):
            status,payload=self.h._setup_mail_prepare()
        self.assertEqual(status,503);self.assertNotIn('your_atomic_api_key_here',json.dumps(payload))

    def test_mail_routes_require_bootstrap_claim(self):
        self.app.setup_claim_valid=lambda token:False
        self.h.headers={};self.h._body=lambda limit:b'{}'
        with mock.patch.object(server.atomicmail,'ensure_ready') as prepare:
            self.assertEqual(self.h._do_setup('/api/setup/mail/prepare')[0],403)
            self.assertEqual(self.h._do_setup('/api/setup/mail/test')[0],403)
        prepare.assert_not_called();self.send.assert_not_called()

    def test_atomic_wizard_has_no_smtp_input_fields(self):
        html=views.setup_page('atomicmail')
        for name in ['sm_host','sm_port','sm_user','sm_password','sm_from']:
            self.assertNotIn('id="'+name+'"',html)
        self.assertIn('id="sm_to"',html);self.assertIn('id="sm_code"',html)
        self.assertIn('id="sm_host"',views.setup_page('smtp'))

    def test_admin_write_preserves_latest_sender_under_lock(self):
        updated=dict(self.sender,uncertain_sends=['example-hash'])
        auth.update_secrets_atomic(str(self.path),lambda data:dict(data,atomicmail=updated))
        auth.write_admin_credentials_atomic(str(self.path),{'admin':{'pw':'hash'},'mail':{'to':'owner@example.com'}},
            self.app.store,replace_all=True,preserve_keys=('atomicmail',))
        self.assertEqual(json.loads(self.path.read_text())['atomicmail'],updated)


if __name__=='__main__':unittest.main()
