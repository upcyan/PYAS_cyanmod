"""Exercise the actual helper and installer shutdown script in isolated folders."""
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'


@unittest.skipUnless(os.name == 'nt' and (ROOT / 'MenuPackage/PYAS_Menu.exe').exists(), 'Windows menu build required')
class MenuShutdownTests(unittest.TestCase):
    def start_helper(self, directory):
        target = Path(directory) / 'PYAS_Menu.exe'
        shutil.copy2(ROOT / 'MenuPackage/PYAS_Menu.exe', target)
        process = subprocess.Popen([str(target), '-Embedding'], creationflags=subprocess.CREATE_NO_WINDOW)
        self.addCleanup(self.cleanup_helper, process)
        time.sleep(0.4)
        self.assertIsNone(process.poll(), 'COM helper must be running for the test')
        return process

    @staticmethod
    def cleanup_helper(process):
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)

    def test_installer_stops_only_exact_directory_and_can_repeat(self):
        with tempfile.TemporaryDirectory() as target, tempfile.TemporaryDirectory() as other:
            selected = self.start_helper(target)
            unrelated = self.start_helper(other)
            command = [str(POWERSHELL), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                       '-File', str(ROOT / 'SetupResources/stop_menu.ps1'), '-InstallPath', target]
            for _ in range(2):
                result = subprocess.run(command, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
            selected.wait(timeout=5)
            self.assertIsNone(unrelated.poll(), 'same filename in another directory must survive')
            self.cleanup_helper(unrelated)

    def test_idle_helper_exits_with_registered_factory(self):
        with tempfile.TemporaryDirectory() as directory:
            helper = self.start_helper(directory)
            self.assertEqual(helper.wait(timeout=70), 0)


if __name__ == '__main__':
    unittest.main()
