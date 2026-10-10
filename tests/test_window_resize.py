"""Test the production methods without booting the antivirus or its drivers."""
import ast
import ctypes
import threading
import unittest
import uuid
from pathlib import Path
from unittest.mock import Mock

class Rect(ctypes.Structure):
    _fields_ = [(key, ctypes.c_long) for key in ('left', 'top', 'right', 'bottom')]

tree = ast.parse((Path(__file__).resolve().parents[1] / 'PYAS.py').read_text(encoding='utf-8'))
main = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == '_MainMixin')
names = {'begin_window_resize', 'update_window_resize', '_apply_window_resize', 'end_window_resize'}
methods = [node for node in main.body if isinstance(node, ast.FunctionDef) and node.name in names]
scope = {'ctypes': ctypes, 'RECT': Rect, 'uuid': uuid}
exec(compile(ast.Module(body=methods, type_ignores=[]), 'PYAS.py', 'exec'), scope)
ResizeAPI = type('ResizeAPI', (), {name: scope[name] for name in names})

class ResizeTests(unittest.TestCase):
    def make_api(self):
        api = ResizeAPI()
        api._resize_lock = threading.RLock()
        api._resize_state = None
        api._find_main_hwnd = Mock(return_value=123)
        api.RESIZE_WINDOW_MIN_WIDTH = 720
        api.RESIZE_WINDOW_MIN_HEIGHT = 560
        def read_rect(hwnd, pointer):
            rect = ctypes.cast(pointer, ctypes.POINTER(Rect)).contents
            rect.left, rect.top, rect.right, rect.bottom = 100, 100, 1100, 900
            return True
        api.user32 = Mock()
        api.user32.GetWindowRect.side_effect = read_rect
        api.user32.GetDpiForWindow.return_value = 144
        return api

    def test_stale_session_cannot_move_or_end_new_drag(self):
        api = self.make_api()
        first = api.begin_window_resize('se')
        second = api.begin_window_resize('se')
        self.assertFalse(api.update_window_resize(20, 20, first))
        self.assertFalse(api.end_window_resize(first))
        self.assertTrue(api.update_window_resize(20, 20, second))
        self.assertTrue(api.end_window_resize(second))
        self.assertFalse(api.update_window_resize(100, 100, second))
        api.user32.SetWindowPos.assert_called_once_with(123, None, 100, 100, 1030, 830, 0x0014)

    def test_cache_dpi_and_preserve_minimum_size(self):
        api = self.make_api()
        token = api.begin_window_resize('nw')
        for _ in range(10):
            self.assertTrue(api.update_window_resize(999, 999, token))
        api._find_main_hwnd.assert_called_once()
        api.user32.GetDpiForWindow.assert_called_once()
        self.assertEqual(api.user32.SetWindowPos.call_args.args[4:6], (720, 560))
        self.assertFalse(api.update_window_resize(float('inf'), 0, token))

    def test_end_waits_for_native_update(self):
        api = self.make_api()
        token = api.begin_window_resize('se')
        entered, release, ended = threading.Event(), threading.Event(), threading.Event()
        def native(*args):
            entered.set()
            release.wait(2)
        api.user32.SetWindowPos.side_effect = native
        update = threading.Thread(target=api.update_window_resize, args=(10, 10, token))
        update.start()
        self.assertTrue(entered.wait(1))
        end = threading.Thread(target=lambda: (api.end_window_resize(token), ended.set()))
        end.start()
        self.assertFalse(ended.wait(.05))
        release.set()
        update.join(1)
        end.join(1)
        self.assertTrue(ended.is_set())
        self.assertFalse(api._window_interacting)
