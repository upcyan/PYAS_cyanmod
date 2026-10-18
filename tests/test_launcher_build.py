"""Frozen smoke runner checks; native compilation is tested only on Windows."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
import subprocess
import build_launcher

class LauncherBuildTests(unittest.TestCase):
    def test_smoke_checks_clean_and_removed_parent_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher=Path(directory)/'PYAS_Launcher.exe'
            (Path(directory)/'PYAS.exe').write_bytes(b'fixture')
            process=Mock(returncode=0);process.communicate.return_value=(b'',b'')
            with patch.object(subprocess,'Popen',return_value=process) as popen:
                build_launcher.smoke_launch(launcher)
            self.assertEqual(popen.call_count,2)
            first,second=[call.kwargs['env'] for call in popen.call_args_list]
            self.assertNotIn('_PYI_APPLICATION_HOME_DIR',first)
            self.assertNotIn('PYINSTALLER_RESET_ENVIRONMENT',second)
            self.assertIn('_MEI-already-removed',second['_PYI_APPLICATION_HOME_DIR'])
            self.assertFalse(Path(second['_PYI_APPLICATION_HOME_DIR']).exists())
            for call in popen.call_args_list:
                self.assertEqual(call.args[0],[str(launcher),'--pyas-bootstrap-probe'])
    def test_failed_or_timed_out_probe_stops_build_and_releases_process(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher=Path(directory)/'PYAS_Launcher.exe';(Path(directory)/'PYAS.exe').write_bytes(b'fixture')
            process=Mock(returncode=1);process.communicate.return_value=(b'',b'')
            with patch.object(subprocess,'Popen',return_value=process),self.assertRaises(RuntimeError):
                build_launcher.smoke_launch(launcher)
            process=Mock();process.communicate.side_effect=[subprocess.TimeoutExpired('probe',40),(b'',b'')]
            with patch.object(subprocess,'Popen',return_value=process),self.assertRaises(RuntimeError):
                build_launcher.smoke_launch(launcher)
            process.kill.assert_called_once();self.assertEqual(process.communicate.call_count,2)

if __name__=='__main__':unittest.main()
