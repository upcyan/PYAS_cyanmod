"""Fork update protocol: immutable assets, job IDs, revisions and verified install."""
import copy
import hashlib
import json
import os
import re
import threading
import time
from urllib.parse import unquote, urlsplit
from uuid import uuid4
from PYAS_FileTrust import locked_read, sha256_stream
from PYAS_UpdateInstall import InstallLaunchUncertain, launch_verified_installer


_CONTROL_INIT_LOCK = threading.Lock()


def update_control_lock(owner):
    # Independent from configuration/driver operations, which may wait on native I/O.
    with _CONTROL_INIT_LOCK:
        lock = getattr(owner, '_update_protocol_lock', None)
        if lock is None:
            lock = owner._update_protocol_lock = threading.RLock()
        return lock


def normalize_asset(asset):
    if not isinstance(asset, dict):
        return None
    url, name = str(asset.get('url') or ''), str(asset.get('name') or '')
    parsed = urlsplit(url)
    prefix = '/upcyan/PYAS_cyanmod/releases/download/'
    if parsed.scheme != 'https' or parsed.hostname != 'github.com' or parsed.username or parsed.password or not parsed.path.startswith(prefix):
        raise ValueError('Invalid update source')
    if not name.lower().startswith('pyas_setup') or not name.lower().endswith(('.exe', '.msi')):
        raise ValueError('Invalid installer filename')
    if any(ch in '<>:"/\\|?*' or ord(ch) < 32 for ch in name) or name.endswith((' ', '.')):
        raise ValueError('Invalid installer filename')
    parts = parsed.path[len(prefix):].split('/')
    if len(parts) != 2 or unquote(parts[1]) != name:
        raise ValueError('Installer does not match the asset URL')
    version = str(asset.get('version') or unquote(parts[0]))
    if version != unquote(parts[0]):
        raise ValueError('Update version does not match the asset URL')
    size = asset.get('size') or 0
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ValueError('Invalid update size')
    digest = asset.get('digest')
    if digest is not None:
        digest = str(digest).lower()
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
            raise ValueError('Unsupported update checksum')
    selected = dict(url=url, name=name, version=version, size=size, digest=digest)
    selected['asset_id'] = hashlib.sha256(json.dumps(selected, sort_keys=True,
        separators=(',', ':')).encode('utf-8')).hexdigest()
    return selected


class UpdateDownloadManager:
    def __init__(self, user_path, fetch, emit, log, launcher=None, thread_factory=None):
        self.directory = os.path.realpath(os.path.join(user_path, 'Downloads'))
        self.fetch, self.emit, self.log = fetch, emit, log
        self.launcher = launcher or launch_verified_installer
        self.thread_factory = thread_factory or threading.Thread
        self.lock = threading.RLock()
        self.selection = None
        self.job = None
        self.state = {'downloading': False, 'phase': 'empty', 'revision': 0}
        self.verified = None
        self.seen = set()

    def select(self, asset):
        selected = normalize_asset(asset)
        with self.lock:
            self.selection = selected
        return copy.deepcopy(selected)

    def snapshot(self):
        with self.lock:
            return copy.deepcopy(self.state)

    def _packet_locked(self, job, phase, **changes):
        previous = self.state if self.state.get('download_id') == job['download_id'] else {}
        state = dict(previous)
        state.update(download_id=job['download_id'], asset_id=job['asset']['asset_id'],
            asset_url=job['asset']['url'], file_name=job['asset']['name'], version=job['asset']['version'],
            revision=int(previous.get('revision', -1)) + 1, phase=phase,
            downloading=phase in ('downloading', 'verifying'), installing=phase in ('installing', 'install_unknown'))
        state.update(changes)
        self.state = state
        return copy.deepcopy(state)

    def _emit(self, state):
        try:
            self.emit('if(window.updateDownloadState) window.updateDownloadState(' + json.dumps(state) + ');')
        except Exception:
            pass  # snapshot remains authoritative when the view is closed

    def _publish(self, job, phase, **changes):
        with self.lock:
            if self.job is not job:
                return
            state = self._packet_locked(job, phase, **changes)
        self._emit(state)

    def start(self, url, file_name, download_id=None):
        with self.lock:
            asset = copy.deepcopy(self.selection)
            if not asset or asset['url'] != url or asset['name'] != file_name:
                return {'success': False, 'error': 'Check for updates again before downloading'}
            if self.state.get('installing'):
                return {'success': False, 'error': 'An installer is already running', 'state': self.snapshot()}
            if self.state.get('downloading'):
                same = self.state.get('asset_id') == asset['asset_id']
                return {'success': same, 'already': same,
                        'error': None if same else 'Another update is downloading', 'state': self.snapshot()}
            identifier = str(download_id or uuid4().hex).lower()
            if not re.fullmatch(r'[0-9a-f]{32}', identifier) or identifier in self.seen:
                return {'success': False, 'error': 'Invalid or repeated download ID'}
            # Bounded history; normal clients use fresh cryptographic UUIDs.
            if len(self.seen) >= 1024:
                return {'success': False, 'error': 'Restart the application before starting more downloads'}
            self.seen.add(identifier)
            job = {'download_id': identifier, 'asset': asset}
            self.job = job
            self.verified = None
            state = self._packet_locked(job, 'downloading', received=0,
                total=asset['size'], percent=0 if asset['size'] else -1, result=None)
            try:
                self.thread_factory(target=self._download, args=(job,), daemon=True,
                    name='PYAS.UpdateDownload').start()
            except Exception as error:
                result = {'success': False, 'path': None, 'error': str(error), 'size': 0}
                state = self._packet_locked(job, 'failed', result=result)
                response = {'success': False, 'error': str(error), 'state': copy.deepcopy(state)}
            else:
                response = {'success': True, 'started': True, 'state': copy.deepcopy(state)}
        self._emit(state)
        return response

    def _download(self, job):
        asset = job['asset']
        target = os.path.join(self.directory, asset['name'])
        part = target + '.' + job['download_id'] + '.part'
        response = None
        received = 0
        try:
            os.makedirs(self.directory, exist_ok=True)
            response = self.fetch(asset['url'], stream=True)
            response.raise_for_status()
            header_size = int(response.headers.get('Content-Length') or 0)
            if header_size < 0:
                raise ValueError('Invalid response size')
            total = asset['size'] or header_size
            digest = hashlib.sha256()
            next_report = 0.0
            with open(part, 'xb') as stream:
                for chunk in response.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    stream.write(chunk)
                    digest.update(chunk)
                    received += len(chunk)
                    now = time.monotonic()
                    if now >= next_report:
                        next_report = now + .2
                        self._publish(job, 'downloading', received=received, total=total,
                            percent=min(100, int(received * 100 / total)) if total > 0 else -1)
            if received == 0:
                raise ValueError('Empty update download')
            if total > 0 and received != total:
                raise ValueError('Incomplete update download')
            actual = digest.hexdigest()
            if asset['digest'] and asset['digest'] != 'sha256:' + actual:
                raise ValueError('Update checksum mismatch')
            self._publish(job, 'verifying', received=received, total=total, percent=100)
            os.replace(part, target)
            # Detect replacement between publication into Downloads and verification.
            with locked_read(target) as stream:
                if sha256_stream(stream) != actual:
                    raise ValueError('Downloaded installer changed')
                stat = os.fstat(stream.fileno())
                verified = dict(path=os.path.realpath(target), sha256=actual,
                    device=stat.st_dev, inode=stat.st_ino, size=stat.st_size)
            result = {'success': True, 'path': verified['path'], 'error': None, 'size': received}
            with self.lock:
                if self.job is not job:
                    return
                self.verified = verified
                state = self._packet_locked(job, 'ready', received=received, total=total,
                    percent=100, result=result)
            self._emit(state)
            self.log('INFO', 'Update Download', detail='Saved ' + verified['path'])
        except Exception as error:
            with self.lock:
                if self.job is not job:
                    return
                self.verified = None
                state = self._packet_locked(job, 'failed',
                    result={'success': False, 'path': None, 'error': str(error), 'size': received})
            self._emit(state)
            self.log('WARN', 'Update Download', detail=str(error), success=False)
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
            # Only this job's unique temporary file may be removed.
            if os.path.dirname(os.path.abspath(part)) == self.directory and part.endswith('.' + job['download_id'] + '.part'):
                try:
                    os.unlink(part)
                except FileNotFoundError:
                    pass
                except OSError:
                    pass

    def install(self, path, download_id=None):
        with self.lock:
            job, verified, selected = self.job, self.verified, self.selection
            if (not job or not verified or not selected or self.state.get('phase') != 'ready'
                    or selected['asset_id'] != job['asset']['asset_id']
                    or (download_id is not None and download_id != job['download_id'])
                    or not isinstance(path, str) or os.path.realpath(os.path.abspath(path)) != verified['path']):
                return False
            state = self._packet_locked(job, 'installing', error=None)
            digest = verified['sha256']
        self._emit(state)
        def finished(exit_code):
            with self.lock:
                if self.job is not job:
                    return
                self.verified = None
                packet = self._packet_locked(job, 'installer_finished', exit_code=exit_code)
            self._emit(packet)
        try:
            with locked_read(verified['path']) as stream:
                current = os.fstat(stream.fileno())
                if ((current.st_dev, current.st_ino, current.st_size) !=
                        (verified['device'], verified['inode'], verified['size'])
                        or sha256_stream(stream) != digest):
                    raise ValueError('Installer changed after download')
                accepted = self.launcher(verified['path'], digest, on_exit=finished)
                if not accepted:
                    raise OSError('Installer launch was rejected')
            return True
        except InstallLaunchUncertain as error:
            # Never retry automatically when the shell may already have started it.
            self._publish(job, 'install_unknown', error=str(error))
            return False
        except Exception as error:
            self._publish(job, 'ready', error=str(error))
            self.log('WARN', 'Update Install', detail=str(error), success=False)
            return False
