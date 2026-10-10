"""Validate real generated certificate checks without altering certificate stores."""
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import build_menu


class MenuCertificateTests(unittest.TestCase):
    def test_exact_certificate_passes_checks_and_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix='PYAS certificate ') as directory:
            root = Path(directory)
            with patch.object(build_menu, 'OUT', root):
                build_menu.write_scripts('3.7.0.11', 'test.msix')
            certificate = root / 'menu_cert.cer'
            shutil.copy2(build_menu.CERT_CER, certificate)
            generated = (root / 'trust_menu.ps1').read_text(encoding='utf-8-sig')
            # Execute all actual hash/identity/validity/EKU checks, then stop
            # before accessing or changing any machine certificate store.
            prefix = generated.split('$storePath =')[0]
            probe = root / 'certificate_probe.ps1'
            probe.write_text(prefix + '\nWrite-Output "certificate verified"\n', encoding='utf-8-sig')
            good = build_menu.run_powershell(f"& '{probe}'")
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertIn('certificate verified', good.stdout)
            certificate.write_bytes(b'tampered certificate')
            bad = build_menu.run_powershell(f"& '{probe}'")
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn('fingerprint mismatch', bad.stderr)
            self.assertNotIn('certificate verified', bad.stdout)
            self.assertIn('Cert:\\LocalMachine\\TrustedPeople', generated)
            self.assertNotIn('\\Root', generated)


if __name__ == '__main__':
    unittest.main()
