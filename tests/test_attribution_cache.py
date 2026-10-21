"""发起进程溯源缓存的行为约束。"""

import os
import unittest

from PYAS_Attribution import AttributionLayer, AttributionCache


class AttributionCacheTests(unittest.TestCase):
    def test_record_then_lookup_is_case_insensitive(self):
        cache = AttributionCache(ttl_seconds=10, max_entries=8)
        cache.record(r"C:\Temp\A.exe", 1234, "builder.exe", now=100.0)

        hit = cache.lookup(r"c:\temp\a.exe", now=101.0)

        self.assertIsNotNone(hit, "Windows 路径大小写不敏感,必须能命中")
        self.assertEqual(hit[0], 1234)
        self.assertEqual(hit[1], "builder.exe")

    def test_expired_entry_is_dropped(self):
        cache = AttributionCache(ttl_seconds=5, max_entries=8)
        cache.record(r"C:\Temp\B.exe", 99, "x.exe", now=100.0)

        self.assertIsNone(cache.lookup(r"C:\Temp\B.exe", now=106.0), "超过 TTL 必须失效")
        self.assertEqual(len(cache), 0, "过期条目应被清掉,不能留着占内存")

    def test_capacity_is_bounded(self):
        cache = AttributionCache(ttl_seconds=60, max_entries=3)

        for index in range(10):
            cache.record(rf"C:\Temp\{index}.exe", index + 1, "p.exe", now=100.0 + index)

        self.assertLessEqual(len(cache), 3, "缓存必须有上限,否则长时间运行会无限增长")
        self.assertIsNotNone(cache.lookup(r"C:\Temp\9.exe", now=101.0), "最新的应保留")
        self.assertIsNone(cache.lookup(r"C:\Temp\0.exe", now=101.0), "最旧的应被淘汰")

    def test_empty_paths_are_ignored(self):
        cache = AttributionCache(ttl_seconds=10, max_entries=8)
        cache.record("", 1, "x.exe", now=100.0)

        self.assertEqual(len(cache), 0)
        self.assertIsNone(cache.lookup("", now=100.0))


class AttributionLayerTests(unittest.TestCase):
    def test_driver_takes_priority_over_etw(self):
        layer = AttributionLayer()
        layer.record_etw(r"C:\Temp\C.exe", 200, "etw.exe")
        layer.record_driver(r"C:\Temp\C.exe", 100, "driver.exe")

        hit = layer.lookup(r"C:\Temp\C.exe")

        self.assertIsNotNone(hit)
        self.assertEqual(hit[2], "driver", "驱动事件更准,应优先命中")

    def test_falls_back_to_etw_then_miss(self):
        layer = AttributionLayer()
        layer.record_etw(r"C:\Temp\D.exe", 300, "etw.exe")

        self.assertEqual(layer.lookup(r"C:\Temp\D.exe")[2], "etw")
        self.assertIsNone(layer.lookup(r"C:\Temp\missing.exe"), "两层都没有时应交给 Restart Manager")

    def test_status_counts_hits(self):
        layer = AttributionLayer()
        layer.record_driver(r"C:\Temp\E.exe", 1, "a.exe")
        layer.lookup(r"C:\Temp\E.exe")
        layer.lookup(r"C:\Temp\nope.exe")

        status = layer.status()

        self.assertEqual(status["driver_entries"], 1)
        self.assertEqual(status["hits"]["driver"], 1)
        self.assertEqual(status["hits"]["miss"], 1)


if __name__ == "__main__":
    unittest.main()
