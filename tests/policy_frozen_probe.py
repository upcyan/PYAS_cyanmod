"""Build-only onefile fixture: exercise the unmodified fixed policy helper entry.

This file is NOT imported by PYAS and its binary is never put in Payload.
Only this fixture redirects the broker destination to an isolated test root.
"""
import os
from pathlib import Path
import subprocess
import sys
import PYAS_PolicyWindows as windows


def main():
    root = Path(os.environ['PYAS_TEST_POLICY_ROOT'])
    fixed = "$root=[IO.Path]::Combine($programData,'PYAS.Policy')"
    assert windows.BROKER.count(fixed) == 1
    windows.BROKER = windows.BROKER.replace(fixed, "$root='" + str(root).replace("'", "''") + "'")
    if sys.argv[1:] and sys.argv[1] == '--pyas-policy-helper':
        return windows.helper_main(sys.argv[2:])
    windows.user_data_dir = lambda: str(root.parent / 'UserData')
    backend = windows.WindowsPolicyBackend()
    backend.root = str(root)
    backend.policy_file = str(root / 'Config.json')
    lease = windows.WindowsPolicyLease(backend, {'process_switch'}, None, 'initialize', True)
    backend.leases.add(lease)
    def launch_helper(request, digest):
        env = dict(os.environ, PYINSTALLER_RESET_ENVIRONMENT='1')
        return subprocess.Popen([sys.executable, '--pyas-policy-helper', request, digest], env=env)
    windows._run_broker = launch_helper
    try:
        lease.start()
        document = lease.commit({'process_switch': True})
        assert document['_request'] == lease.nonce
        assert document['process_switch'] is True
        print('FROZEN_POLICY_COMMIT_OK', flush=True)
    finally:
        lease.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
