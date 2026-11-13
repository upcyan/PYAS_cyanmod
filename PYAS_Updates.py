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


# GitHub 直连不通时的传输兜底。镜像只负责「把字节送到」:
# 安装包仍按 API 给的 sha256 与发布里的 .sha256 双重校验,内容被换就装不上。
RELEASE_MIRRORS = ('https://gh-proxy.com/', 'https://ghfast.top/', 'https://ghproxy.net/')

# 断点续传:中流断开后的最多续传轮数;孤儿 .part(崩溃残留)最长保留时间。
RESUME_ROUNDS = 5
PART_MAX_AGE = 7 * 24 * 3600

# 本会话从更新清单学到的补充镜像(latest.json 的 mirrors 字段);
# 镜像生态漂移时不用发版就能换血,只存内存,重启回基础列表。
_SESSION_MIRRORS = []

def effective_mirrors():
    """基础镜像 + 清单补充镜像(去重,保持顺序)。"""
    return tuple(RELEASE_MIRRORS) + tuple(m for m in _SESSION_MIRRORS if m not in RELEASE_MIRRORS)

def register_session_mirrors(mirrors):
    """登记更新清单下发的补充镜像;只收 https 且形态干净的条目,至多 6 条。"""
    accepted = []
    for item in mirrors if isinstance(mirrors, list) else []:
        if not isinstance(item, str) or len(accepted) >= 6:
            continue
        candidate = item.strip()
        if not candidate.endswith('/'):
            candidate += '/'
        parsed = urlsplit(candidate)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.path not in ('', '/') or len(candidate) > 100):
            continue
        if candidate not in accepted:
            accepted.append(candidate)
    _SESSION_MIRRORS[:] = accepted
    return accepted


# R2 自有分发渠道(Cloudflare 静态桶,自定义域名直链)。R2 不是前缀代理,
# 不能拼 mirror+github-url;它按确定性布局直接托管对象:
#   {base}/latest.json                    清单(no-cache,始终最新)
#   {base}/releases/<tag>/<文件名>        安装包与 .sha256 旁路文件
# 内置常量由发版烘焙;更新清单的 r2_base 字段也能在会话内激活(免发版接线)。
R2_PUBLIC_BASE = ''
_SESSION_R2_BASE = ''

def register_session_r2_base(base):
    """登记清单下发的 R2 公开源(会话级);空串/None=清除回落内置常量,非法值忽略。"""
    global _SESSION_R2_BASE
    candidate = str(base or '').strip()
    if not candidate:
        _SESSION_R2_BASE = ''
        return ''
    parsed = urlsplit(candidate)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ('', '/') or len(candidate) > 120):
        return None
    if not candidate.endswith('/'):
        candidate += '/'
    _SESSION_R2_BASE = candidate
    return candidate

def active_r2_base():
    """当前生效的 R2 公开源(清单会话注册优先于内置常量);空=未启用。"""
    return _SESSION_R2_BASE or R2_PUBLIC_BASE

def r2_manifest_url():
    base = active_r2_base()
    return base + 'latest.json' if base else None

def r2_object_urls(asset):
    """R2 渠道的安装包/旁路文件直链;未启用或资产信息不完整返回 None。"""
    base = active_r2_base()
    if not base:
        return None
    version, name = str(asset.get('version') or ''), str(asset.get('name') or '')
    if not version or not name or any(ch in version + name for ch in '/?#\\'):
        return None
    root = base + 'releases/' + version + '/'
    return {'installer': root + name, 'sidecar': root + name + '.sha256'}

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
    # 第二份校验码:同一发布里附带的 .sha256 文件
    checksum_url = str(asset.get('checksum_url') or '')

    if checksum_url:
        parsed_checksum = urlsplit(checksum_url)
        if (parsed_checksum.scheme != 'https' or parsed_checksum.hostname != 'github.com'
                or parsed_checksum.username or parsed_checksum.password
                or not parsed_checksum.path.startswith(prefix)):
            raise ValueError('Invalid update checksum source')
        if unquote(parsed_checksum.path).rsplit('/', 1)[-1] != name + '.sha256':
            raise ValueError('Update checksum does not match the installer')
    selected = dict(url=url, name=name, version=version, size=size, digest=digest,
                    checksum_url=checksum_url)
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

    def _open_stream(self, url, offset=0):
        """取安装包流;offset>0 时带 Range 请求断点续传。

        渠道顺序:R2 自有渠道(启用时,确定性直链,不走镜像阶梯)→ 注入的
        fetch 阶梯(生产环境 ToolsMixin._github_get:直连→系统代理→镜像)。
        200 全量;offset>0 时 206 且 Content-Range 起点吻合为续传,200 视为
        服务器忽略 Range(调用方须从零重写)。其余视为该渠道不可用,换下一个。
        返回 (response, resumed)。
        """
        if offset < 0:
            offset = 0
        targets = []
        r2_urls = r2_object_urls(self.selection or {})
        if r2_urls:
            targets.append((r2_urls['installer'], False))
        targets.append((url, True))
        error = None
        for target, allow_mirrors in targets:
            kwargs = {'stream': True}
            if offset:
                kwargs['extra_headers'] = {'Range': 'bytes=' + str(offset) + '-'}
            if not allow_mirrors:
                kwargs['mirrors'] = False
            try:
                response = self.fetch(target, **kwargs)
            except Exception as exc:
                error = error or exc
                continue
            status = getattr(response, 'status_code', 200)
            if status == 200:
                return response, False
            if status == 206 and offset:
                headers = getattr(response, 'headers', None) or {}
                match = re.match(r'bytes\s+(\d+)-', str(headers.get('Content-Range') or ''))
                if match and int(match.group(1)) == offset:
                    return response, True
            self._close_quiet(response)
            error = ValueError('Update source returned HTTP ' + str(status))
        raise error if error else RuntimeError('update source unavailable')

    def _read_checksum(self, asset):
        """读发布里的 .sha256 旁路文件得第二份校验码:R2 直链优先,其余走 fetch 阶梯。"""
        targets = []
        r2_urls = r2_object_urls(asset)
        if r2_urls:
            targets.append((r2_urls['sidecar'], False))
        targets.append((asset['checksum_url'], True))
        error = None
        for target, allow_mirrors in targets:
            kwargs = {'timeout': 15}
            if not allow_mirrors:
                kwargs['mirrors'] = False
            try:
                response = self.fetch(target, **kwargs)
            except Exception as exc:
                error = error or exc
                continue
            try:
                text = str(getattr(response, 'text', '') or '')
            finally:
                self._close_quiet(response)
            match = re.search(r'\b([0-9a-fA-F]{64})\b', text)
            if match:
                return 'sha256:' + match.group(1).lower()
            error = ValueError('Invalid checksum file')
        raise ValueError('Update checksum unavailable') from error

    def _prune_orphan_parts(self, name):
        """清掉同安装包名下过期的孤儿 .part(崩溃残留;本任务自己的 .part 不在此列)。"""
        try:
            deadline = time.time() - PART_MAX_AGE
            prefix = name + '.'
            for entry in os.listdir(self.directory):
                if not entry.startswith(prefix) or not entry.endswith('.part'):
                    continue
                path = os.path.join(self.directory, entry)
                try:
                    if os.path.getmtime(path) < deadline:
                        os.unlink(path)
                except OSError:
                    pass
        except OSError:
            pass

    @staticmethod
    def _close_quiet(response):
        try:
            response.close()
        except Exception:
            pass

    def _download(self, job):
        asset = job['asset']
        target = os.path.join(self.directory, asset['name'])
        part = target + '.' + job['download_id'] + '.part'
        response = None
        received = 0
        total = asset['size'] or 0
        try:
            os.makedirs(self.directory, exist_ok=True)
            self._prune_orphan_parts(asset['name'])
            # 续传循环:中流断开不清 .part,下一轮从已收字节接着拉;
            # 轮数用尽仍未收完整才按失败处理。
            for round_index in range(RESUME_ROUNDS):
                response = None
                try:
                    if total and received >= total:
                        break
                    response, resumed = self._open_stream(asset['url'], offset=received)
                    headers = getattr(response, 'headers', None) or {}
                    if resumed:
                        # 续传前提:盘上 .part 的字节数与断点一致(被清掉/截断就重来)
                        try:
                            on_disk = os.path.getsize(part)
                        except OSError:
                            on_disk = -1
                        if on_disk != received:
                            resumed = False
                            received = 0
                    if not resumed:
                        # 全量重发(首拉,或服务器忽略 Range);.part 名内嵌本任务唯一
                        # download_id,seen 集合保证不会撞到别的任务,截断重写安全
                        received = 0
                        header_size = int(headers.get('Content-Length') or 0)
                        if header_size < 0:
                            raise ValueError('Invalid response size')
                        total = asset['size'] or header_size
                    elif not total:
                        match = re.match(r'bytes\s+\d+-\d+/(\d+)',
                            str(headers.get('Content-Range') or ''))
                        total = int(match.group(1)) if match else 0
                    next_report = 0.0
                    with open(part, 'r+b' if resumed else 'wb') as stream:
                        if resumed:
                            stream.seek(received)
                        for chunk in response.iter_content(chunk_size=65536):
                            if not chunk:
                                continue
                            stream.write(chunk)
                            received += len(chunk)
                            now = time.monotonic()
                            if now >= next_report:
                                next_report = now + .2
                                self._publish(job, 'downloading', received=received, total=total,
                                    percent=min(100, int(received * 100 / total)) if total > 0 else -1)
                    if total and received > total:
                        raise ValueError('Part exceeds update size')
                    if total and received < total:
                        self._close_quiet(response)
                        response = None
                        continue  # 未收完整,下一轮从断点续传
                    # 收完整:响应留给外层 finally 关闭——旧契约(桥接侧回调、
                    # 守卫测试)依赖「完成发布之后才关闭」的时序
                    break
                except Exception as round_error:
                    self._close_quiet(response)
                    response = None
                    if round_index + 1 >= RESUME_ROUNDS:
                        raise
                    continue
            else:
                raise ValueError('Incomplete update download')
            if received == 0:
                raise ValueError('Empty update download')
            # 校验码改在收完后对 .part 整读计算:续传把流式哈希打散了,
            # 而比对时点本来就在下载结束之后,安全语义不变
            with open(part, 'rb') as stream:
                actual = sha256_stream(stream)
            # 多校验码:API/清单里的 digest 与发布附带的 .sha256 都要对得上;
            # 一份都没有就拒绝安装(镜像只能换传输路径,不能改变内容)
            checksums = []
            if asset.get('digest'):
                checksums.append(('github-api', str(asset['digest']).lower()))
            if asset.get('checksum_url'):
                try:
                    checksums.append(('sha256-asset', self._read_checksum(asset)))
                except Exception as sidecar_error:
                    # 旁路文件拉不到不再一票否决:还有别的校验码就继续用,
                    # 零校验码仍然拒绝
                    if not checksums:
                        raise
                    self.log('INFO', 'Update Download',
                        detail='Checksum sidecar unavailable (' + str(sidecar_error)[:80] + '), verifying with ' + checksums[0][0])
            if not checksums:
                raise ValueError('Missing update checksum')
            for source, expected in checksums:
                if expected != 'sha256:' + actual:
                    raise ValueError('Update checksum mismatch (' + source + ')')
            self._publish(job, 'verifying', received=received, total=total, percent=100)
            os.replace(part, target)
            # 落盘后复核:杀软/索引器可能刚打开这个新文件,读到的内容会短暂不一致,
            # 给它几次机会;三次都对不上就按「被替换」处理(失败关闭)。
            verified = None
            for attempt in range(3):
                try:
                    with locked_read(target) as stream:
                        if sha256_stream(stream) != actual:
                            raise ValueError('Downloaded installer changed')
                        stat = os.fstat(stream.fileno())
                        verified = dict(path=os.path.realpath(target), sha256=actual,
                            device=stat.st_dev, inode=stat.st_ino, size=stat.st_size)
                    break
                except (OSError, ValueError):
                    verified = None
                    if attempt == 2:
                        raise
                    time.sleep(0.05)
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
                # 实时防护可能短暂持有刚写出的临时文件,给清理几次机会
                for _ in range(3):
                    try:
                        os.unlink(part)
                        break
                    except FileNotFoundError:
                        break
                    except OSError:
                        time.sleep(0.15)

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
