"""驱动「最近写入方」查询的用户态一半:编码、解码与路径换算。

内核侧无法在无 WDK 的机器上编译,所以这里把用户态能验证的部分钉死:
命令号、请求结构尺寸、路径必须是设备路径、回复解析、失败时返回 None。
"""

import ctypes
import os
import tempfile
import threading
import unittest

from PYAS_Driver import DriverMixin, _dos_path_to_device_path
from PYAS_WinAPI import PYAS_USER_MESSAGE, PYAS_WRITE_OWNER_REPLY


class _FakeFlt:
    def __init__(self, reply_pid=0):
        self.reply_pid = reply_pid
        self.calls = []

    def FilterSendMessage(self, port, in_buf, in_size,
                          out_buf, out_size, returned):
        message = ctypes.cast(in_buf, ctypes.POINTER(PYAS_USER_MESSAGE)).contents
        self.calls.append({
            'command': message.Command,
            'path': message.Path,
            'in_size': in_size,
            'out_size': out_size,
        })

        if out_buf:
            reply = ctypes.cast(out_buf, ctypes.POINTER(PYAS_WRITE_OWNER_REPLY)).contents
            reply.Found = 1 if self.reply_pid else 0
            reply.ProcessId = self.reply_pid

        return 0


class _Host:
    """只带查询所需的三样东西,避免把整个 DriverMixin 初始化起来。"""

    query_write_owner = DriverMixin.query_write_owner

    def __init__(self, flt, port=None):
        self.fltlib = flt
        self.driver_port = port if port is not None else object()
        self.lock_driver = threading.RLock()


class WriteOwnerQueryTests(unittest.TestCase):
    def test_request_uses_command_8_and_device_path(self):
        flt = _FakeFlt(reply_pid=4242)
        host = _Host(flt)

        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as handle:
            path = handle.name

        try:
            pid = host.query_write_owner(path)
        finally:
            os.unlink(path)

        self.assertEqual(pid, 4242)
        self.assertEqual(len(flt.calls), 1)
        self.assertEqual(flt.calls[0]['command'], 8, '命令号必须与驱动枚举一致')
        self.assertTrue(flt.calls[0]['path'].startswith('\\Device\\'),
                        '驱动按规范化设备路径做哈希,用户态必须先换算')
        self.assertEqual(flt.calls[0]['in_size'], ctypes.sizeof(PYAS_USER_MESSAGE))
        self.assertEqual(flt.calls[0]['out_size'], ctypes.sizeof(PYAS_WRITE_OWNER_REPLY))

    def test_no_record_returns_none(self):
        host = _Host(_FakeFlt(reply_pid=0))
        self.assertIsNone(host.query_write_owner(r'C:\Windows\System32\notepad.exe'))

    def test_no_port_returns_none_without_sending(self):
        flt = _FakeFlt(reply_pid=1)
        host = _Host(flt, port=False)

        self.assertIsNone(host.query_write_owner(r'C:\Windows\System32\notepad.exe'))
        self.assertEqual(flt.calls, [], '没连上驱动时不该发消息')

    def test_empty_path_returns_none(self):
        flt = _FakeFlt(reply_pid=1)
        self.assertIsNone(_Host(flt).query_write_owner(''))
        self.assertEqual(flt.calls, [])

    def test_message_layout_matches_driver(self):
        # 驱动侧 struct 是 ULONG + WCHAR[1024],ctypes 必须完全一致,
        # 否则 FilterSendMessage 的长度一错,内核读到的是垃圾
        self.assertEqual(ctypes.sizeof(PYAS_USER_MESSAGE), 4 + 1024 * 2)
        self.assertEqual(ctypes.sizeof(PYAS_WRITE_OWNER_REPLY), 8)


if __name__ == '__main__':
    unittest.main()
