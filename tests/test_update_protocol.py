"""Update job isolation and checked-installer contract; no native launch/network."""
import ast
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock
from PYAS_Updates import UpdateDownloadManager, normalize_asset
from PYAS_UpdateInstall import InstallLaunchUncertain

ROOT = Path(__file__).resolve().parents[1]

class DeferredThread:
    def __init__(self, **kwargs): self.kwargs = kwargs
    def start(self): pass

class UpdateProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.payload = b'fixture installer bytes'
        self.fetch = Mock()
        self.emit, self.log, self.launcher = Mock(), Mock(), Mock(return_value=True)
        self.manager = UpdateDownloadManager(self.temp.name, self.fetch, self.emit, self.log,
            launcher=self.launcher, thread_factory=DeferredThread)
        self.asset = self.selected('1')
        self.manager.select(self.asset)

    def selected(self, version):
        name = 'PYAS_Setup_v' + version + '.exe'
        return dict(name=name, url='https://github.com/upcyan/PYAS_cyanmod/releases/download/v' + version + '/' + name,
            size=len(self.payload), digest='sha256:' + hashlib.sha256(self.payload).hexdigest(), version='v' + version)

    def start(self, digit='a'):
        return self.manager.start(self.asset['url'], self.asset['name'], digit * 32)

    def response(self, payload=None, header=True):
        response = Mock()
        response.status_code = 200
        data = self.payload if payload is None else payload
        response.headers = {'Content-Length': str(len(data))} if header else {}
        response.iter_content.return_value = [data]
        self.fetch.return_value = response
        return response

    def ready(self):
        self.assertTrue(self.start()['started'])
        response = self.response()
        self.manager._download(self.manager.job)
        self.assertEqual(self.manager.snapshot()['phase'], 'ready')
        response.close.assert_called_once()
        return self.manager.snapshot()

    def test_invalid_assets_and_requests_are_rejected(self):
        for change in ({'url': 'https://example.invalid/installer.exe'}, {'name': '../PYAS_Setup.exe'},
                       {'name': 'PYAS_Setup.exe:stream.exe'}, {'digest': 'sha256:bad'}, {'size': -1}):
            candidate = {**self.asset, **change}
            with self.subTest(change=change), self.assertRaises(ValueError): normalize_asset(candidate)
        self.assertFalse(self.manager.start(self.asset['url'], self.asset['name'], 'bad')['success'])
        self.assertFalse(self.manager.start(self.asset['url'], 'other.exe')['success'])
        self.manager.select(None)
        self.assertFalse(self.start()['success'])

    def test_job_snapshot_is_identified_and_detached(self):
        result = self.start()
        state = result['state']
        self.assertEqual(state['download_id'], 'a' * 32)
        self.assertEqual(state['asset_id'], normalize_asset(self.asset)['asset_id'])
        self.assertEqual(state['phase'], 'downloading')
        state['phase'] = 'tampered'
        self.assertEqual(self.manager.snapshot()['phase'], 'downloading')
        self.assertTrue(self.start('b')['already'])
        self.assertEqual(self.manager.snapshot()['download_id'], 'a' * 32)

    def test_ready_package_installs_once_and_process_exit_clears_record(self):
        state = self.ready()
        self.assertFalse(self.manager.install(state['result']['path'], 'b' * 32))
        self.assertFalse(self.manager.install(str(Path(self.temp.name) / 'unrelated.exe'), 'a' * 32))
        self.assertTrue(self.manager.install(state['result']['path'], 'a' * 32))
        self.launcher.assert_called_once()
        self.assertFalse(self.manager.install(state['result']['path'], 'a' * 32))
        self.launcher.call_args.kwargs['on_exit'](0)
        self.assertEqual(self.manager.snapshot()['phase'], 'installer_finished')
        self.assertIsNone(self.manager.verified)

    def test_replaced_package_never_reaches_launcher(self):
        state = self.ready()
        file = Path(state['result']['path'])
        file.write_bytes(b'X' * len(self.payload))
        self.assertFalse(self.manager.install(str(file), 'a' * 32))
        self.launcher.assert_not_called()
        self.assertIn('changed', self.manager.snapshot()['error'])

    def test_new_selection_cannot_install_old_verified_asset(self):
        state = self.ready()
        self.manager.select(self.selected('2'))
        self.assertFalse(self.manager.install(state['result']['path'], 'a' * 32))
        self.launcher.assert_not_called()

    def test_old_job_completion_cannot_overwrite_new_job(self):
        self.start()
        old = self.manager.job
        response = self.response()
        def close_old_connection():
            self.asset = self.selected('2')
            self.manager.select(self.asset)
            self.assertTrue(self.start('b')['started'])
        response.close.side_effect = close_old_connection
        self.manager._download(old)
        self.manager._publish(old, 'failed', result={'success': False})
        current = self.manager.snapshot()
        self.assertTrue(current['downloading'])
        self.assertEqual(current['download_id'], 'b' * 32)
        self.assertEqual(current['version'], 'v2')
        self.assertIsNone(self.manager.verified)

    def test_bad_checksum_size_and_empty_body_fail_without_installer(self):
        for payload in (b'X' * len(self.payload), b'short', b''):
            with self.subTest(payload=payload):
                self.manager = UpdateDownloadManager(self.temp.name, self.fetch, self.emit, self.log,
                    launcher=self.launcher, thread_factory=DeferredThread)
                self.manager.select(self.asset)
                self.start()
                response = self.response(payload)
                self.manager._download(self.manager.job)
                self.assertEqual(self.manager.snapshot()['phase'], 'failed')
                self.assertIsNone(self.manager.verified)
                response.close.assert_called_once()
                self.assertEqual(list(Path(self.temp.name).rglob('*.part')), [])
        self.launcher.assert_not_called()

    def test_unknown_size_progress_and_response_close_failure_are_safe(self):
        self.asset = {**self.asset, 'size': 0}
        self.manager.select(self.asset)
        self.start()
        response = self.response(header=False)
        response.close.side_effect = OSError('close failed')
        self.manager._download(self.manager.job)
        self.assertEqual(self.manager.snapshot()['phase'], 'ready')
        self.assertEqual(self.manager.snapshot()['percent'], 100)
        self.assertEqual(list(Path(self.temp.name).rglob('*.part')), [])

    def test_untracked_accepted_launch_is_never_retried_automatically(self):
        state = self.ready()
        self.launcher.side_effect = InstallLaunchUncertain('fixture uncertain')
        self.assertFalse(self.manager.install(state['result']['path'], 'a' * 32))
        self.assertEqual(self.manager.snapshot()['phase'], 'install_unknown')
        self.assertTrue(self.manager.snapshot()['installing'])
        self.assertFalse(self.start('b')['success'])
        self.assertFalse(self.manager.install(state['result']['path'], 'a' * 32))
        self.launcher.assert_called_once()

    def test_worker_creation_failure_clears_busy_state(self):
        self.manager.thread_factory = Mock(side_effect=RuntimeError('no worker'))
        self.assertFalse(self.start()['success'])
        self.assertFalse(self.manager.snapshot()['downloading'])
        self.assertEqual(self.manager.snapshot()['phase'], 'failed')

class LatestCheckTests(unittest.TestCase):
    def test_state_read_does_not_wait_for_global_driver_configuration_lock(self):
        tree = ast.parse((ROOT / 'PYAS_Tools.py').read_text(encoding='utf-8'))
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'ToolsMixin')
        names = {'_get_update_manager', 'get_update_download_state'}
        funcs = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in names]
        scope = {}; exec(compile(ast.Module(body=funcs, type_ignores=[]), 'PYAS_Tools.py', 'exec'), scope)
        API = type('API', (), {name: scope[name] for name in names})
        with tempfile.TemporaryDirectory() as directory:
            app = API(); app.path_user = directory; app.lock_update = threading.RLock()
            app._github_get = Mock(); app._emit_ui_js = Mock(); app.write_log = Mock()
            held, release = threading.Event(), threading.Event()
            def hold():
                with app.lock_update: held.set(); release.wait(2)
            holder = threading.Thread(target=hold); reader = threading.Thread(target=app.get_update_download_state)
            try:
                holder.start(); self.assertTrue(held.wait(1))
                reader.start(); reader.join(.3)
                self.assertFalse(reader.is_alive())
            finally:
                release.set(); holder.join(2); reader.join(2)


    def test_late_check_cannot_replace_newer_selection(self):
        tree = ast.parse((ROOT / 'PYAS_Tools.py').read_text(encoding='utf-8'))
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'ToolsMixin')
        fn = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'check_update')
        scope = {}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), 'PYAS_Tools.py', 'exec'), scope)
        entered, release = threading.Event(), threading.Event()
        def asset(version):
            name = 'PYAS_Setup_v' + version + '.exe'
            return {'url': 'https://github.com/upcyan/PYAS_cyanmod/releases/download/v' + version + '/' + name, 'name': name, 'size': 1}
        app = SimpleNamespace(lock_update=threading.RLock(), _is_dev_channel=lambda: False)
        def old_check(): entered.set(); release.wait(2); return {'has_update': True, 'asset': asset('1')}
        app._check_self_update = old_check
        results = []
        worker = threading.Thread(target=lambda: results.append(scope['check_update'](app)))
        try:
            worker.start(); self.assertTrue(entered.wait(1))
            app._check_self_update = lambda: {'has_update': True, 'asset': asset('2')}
            current = scope['check_update'](app)
            release.set(); worker.join(2)
            self.assertEqual(app._checked_update_asset['version'], 'v2')
            self.assertEqual(results[0]['error_code'], 'superseded')
            self.assertEqual(current['asset']['version'], 'v2')
        finally:
            release.set(); worker.join(2)

if __name__ == '__main__': unittest.main()
