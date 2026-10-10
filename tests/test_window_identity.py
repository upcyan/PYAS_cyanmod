import ctypes
import ctypes.wintypes as W
import unittest
from unittest.mock import Mock, patch
from PYAS_WindowIdentity import find_main_window

class WindowIdentityTests(unittest.TestCase):
    def fixture(self, windows):
        user, kernel = Mock(), Mock()
        lookup = {row[0]: row for row in windows}
        def next_window(parent, previous, klass, title):
            handles = [row[0] for row in windows]
            index = handles.index(previous) + 1 if previous in handles else 0
            return handles[index] if index < len(handles) else None
        user.FindWindowExW.side_effect = next_window
        def class_name(hwnd, buffer, size):
            buffer.value = lookup[hwnd][1]
            return len(buffer.value)
        user.GetClassNameW.side_effect = class_name
        def process_id(hwnd, pointer):
            ctypes.cast(pointer, ctypes.POINTER(W.DWORD)).contents.value = lookup[hwnd][2]
            return 1
        user.GetWindowThreadProcessId.side_effect = process_id
        kernel.OpenProcess.side_effect = lambda access, inherit, pid: pid
        def image(process, flags, buffer, size):
            buffer.value = next(row[3] for row in windows if row[2] == process)
            return True
        kernel.QueryFullProcessImageNameW.side_effect = image
        return user, kernel

    def test_explorer_folder_with_same_title_is_not_pyas(self):
        with patch('PYAS_WindowIdentity._apis', return_value=self.fixture([(1, 'CabinetWClass', 100, r'C:\Windows\explorer.exe')])):
            self.assertIsNone(find_main_window('PYAS Security Cyanmod'))

    def test_enumerates_past_same_title_folder_to_real_app(self):
        apis = self.fixture([(1, 'CabinetWClass', 100, r'C:\Windows\explorer.exe'),
            (2, 'WindowsForms10.Window.8.app.0.test', 200, r'C:\Program Files\PYAS\PYAS.exe')])
        with patch('PYAS_WindowIdentity._apis', return_value=apis):
            self.assertEqual(find_main_window('PYAS Security Cyanmod'), 2)
        apis[1].CloseHandle.assert_called_once_with(200)

    def test_similarly_titled_unrelated_form_is_rejected(self):
        apis = self.fixture([(2, 'WindowsForms10.Window.8.app.0.test', 200, r'C:\Other\Other.exe')])
        with patch('PYAS_WindowIdentity._apis', return_value=apis):
            self.assertIsNone(find_main_window('PYAS Security Cyanmod'))
        apis[1].CloseHandle.assert_called_once_with(200)

    def test_own_window_lookup_checks_pid(self):
        apis = self.fixture([(1, 'WindowsForms10.Window.8.app.0.test', 100, r'C:\PYAS.exe'),
            (2, 'WindowsForms10.Window.8.app.0.test', 200, r'C:\PYAS.exe')])
        with patch('PYAS_WindowIdentity._apis', return_value=apis):
            self.assertEqual(find_main_window('PYAS Security Cyanmod', own_pid=200), 2)
        apis[1].OpenProcess.assert_not_called()

    def test_unreadable_process_not_used_and_no_leaked_handle(self):
        apis = self.fixture([(2, 'WindowsForms10.Window.8.app.0.test', 200, r'C:\PYAS.exe')])
        apis[1].QueryFullProcessImageNameW.return_value = False
        apis[1].QueryFullProcessImageNameW.side_effect = None
        with patch('PYAS_WindowIdentity._apis', return_value=apis):
            self.assertIsNone(find_main_window('PYAS Security Cyanmod'))
        apis[1].CloseHandle.assert_called_once_with(200)
