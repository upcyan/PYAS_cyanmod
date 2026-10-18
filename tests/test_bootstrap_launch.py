"""Independent packaged launches must never reuse a dead onefile directory."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import PYAS_Startup as startup

ROOT=Path(__file__).resolve().parents[1]

class FrozenLaunchTests(unittest.TestCase):
    def test_frozen_gui_marks_descendants_as_independent_without_touching_private_state(self):
        inherited={'_PYI_ARCHIVE_FILE':'C:/Program Files/PYAS/PYAS.exe',
            '_PYI_APPLICATION_HOME_DIR':'C:/Temp/_MEI-already-removed','_PYI_PARENT_PROCESS_LEVEL':'1'}
        with patch.dict(os.environ,inherited,clear=True),patch.object(sys,'frozen',True,create=True):
            startup.configure_frozen_children()
            self.assertEqual(os.environ.get('PYINSTALLER_RESET_ENVIRONMENT'),'1')
            for key,value in inherited.items(): self.assertEqual(os.environ[key],value)
    def test_source_process_does_not_rewrite_its_host_environment(self):
        with patch.dict(os.environ,{},clear=True),patch.object(sys,'frozen',False,create=True):
            startup.configure_frozen_children()
            self.assertNotIn('PYINSTALLER_RESET_ENVIRONMENT',os.environ)
    def test_installer_uses_native_launcher_for_new_exe_maintenance_and_postinstall(self):
        text=(ROOT/'PYAS_Inno.iss').read_text(encoding='utf-8')
        self.assertIn('Source: "Payload\\PYAS_Launcher.exe"',text)
        run=next(line for line in text.splitlines() if 'postinstall' in line and line.startswith('Filename:'))
        self.assertIn('PYAS_Launcher.exe',run)
        self.assertIn('runasoriginaluser',run)
        start=text.index('procedure FinalizeDriverRemoval;')
        end=text.index('function InitializeSetup',start)
        self.assertIn('PYAS_Launcher.exe',text[start:end])
    def test_normal_launcher_does_not_kill_updaters_when_gui_exits(self):
        text=(ROOT/'Plugins'/'Bootstrap'/'PYAS_Launcher.cpp').read_text(encoding='utf-8')
        self.assertIn('if (probe) {',text)
        self.assertIn('if (!waitForExit)',text)
        self.assertIn('if (job) CloseHandle(job)',text)
        self.assertIn('SetEnvironmentVariableW(L"PYINSTALLER_RESET_ENVIRONMENT", L"1")',text)
        self.assertIn('CreateProcessW(executable.c_str()',text)
        self.assertNotIn('cmd.exe',text)

    def test_probe_exits_before_gui_and_diagnostics_imports(self):
        text=(ROOT/'PYAS.py').read_text(encoding='utf-8')
        self.assertLess(text.index('--pyas-bootstrap-probe'),text.index('from PYAS_Diagnostics'))

if __name__=='__main__':unittest.main()
