"""发布侧契约:publish 流水的函数签名与产物形状,不触网络不建 Release。

publish() 只在 CI 执行,历史教训(2026-11-13 CI):改签名漏改调用点,
py_compile/本地构建都不经过它,直到发布步骤才炸——所以必须契约锁定。
"""
import hashlib
import importlib.util
import inspect
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location('build', ROOT / 'build.py')
build = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build)


class BuildPublishContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.payload = b'PYAS Setup fixture payload for publish contract'
        self.asset = Path(self.temp.name) / 'PYAS_Setup_v9.9.9-1.exe'
        self.asset.write_bytes(self.payload)
        self.digest = hashlib.sha256(self.payload).hexdigest()

    def test_sidecar_arity_and_content(self):
        # 2026-11-13 CI 事故:签名加了 digest_hex 而调用点没改,只在发布时炸
        self.assertEqual(list(inspect.signature(build.write_update_sidecar).parameters),
            ['asset', 'digest_hex'])
        sidecar = build.write_update_sidecar(self.asset, self.digest)
        self.assertEqual(sidecar.name, 'PYAS_Setup_v9.9.9-1.exe.sha256')
        self.assertEqual(sidecar.read_text(encoding='ascii'),
            f'{self.digest}  {self.asset.name}\n')

    def test_manifest_schema_matches_normalize_asset(self):
        # 清单里的 asset 必须原样通过应用端 normalize_asset 的源锚校验,
        # 否则 API 全断时的兜底通道下载端会拒绝(双校验来源缺一不可)
        from PYAS_Updates import normalize_asset
        root_latest = build.ROOT / 'latest.json'
        saved = root_latest.read_bytes() if root_latest.exists() else None
        self.addCleanup(lambda: root_latest.write_bytes(saved) if saved is not None
            else root_latest.unlink(missing_ok=True))
        manifest = build.write_update_manifest(self.asset, '9.9.9-1', self.digest)
        data = json.loads(manifest.read_text(encoding='utf-8'))
        self.assertEqual(data['version'], 'v9.9.9-1')
        self.assertEqual(data['asset']['digest'], 'sha256:' + self.digest)
        self.assertEqual(data['asset']['size'], len(self.payload))
        self.assertEqual(data['asset']['checksum_url'],
            data['asset']['url'] + '.sha256')
        self.assertIn('notes', data)
        selected = normalize_asset(data['asset'])
        self.assertEqual(selected['digest'], 'sha256:' + self.digest)

    def test_publish_pipeline_calls_are_consistent(self):
        # 静态检查:publish 源码里对 sidecar/manifest/R2 的调用必须与签名对齐
        source = inspect.getsource(build.publish)
        self.assertIn('write_update_sidecar(asset, digest_hex)', source)
        self.assertIn('write_update_manifest(asset, version, digest_hex, r2_base=r2_base)', source)
        self.assertIn('upload_release_to_r2(asset, sidecar, version)', source)
        self.assertIn('commit_update_manifest()', source)
        for name in ('create_release_gh', 'create_release_api'):
            signature = list(inspect.signature(getattr(build, name)).parameters)
            self.assertEqual(signature, ['asset', 'version', 'extra_assets'])


if __name__ == '__main__':
    unittest.main()
