import json
import os
import tempfile
import time

# 实时防护(Defender 等)会短暂持有刚写完的 .tmp 或目标文件,单次 os.replace
# 在这类环境偶发 WinError 32(实测持有可达数秒):退避重试穿过扫描窗口,
# 而不是把一次瞬时冲突抛给调用方(2026-10-31 曾据此打断特权恢复线程)。
# WinError 5 不重试:拒绝访问多为持久性 ACL/属主问题(2026-10-16 事故),
# 重试只会白白拖慢调用方(日志刷写每轮多等数秒)。
_REPLACE_ATTEMPTS = 8
_REPLACE_BACKOFF = 0.3


def _transient(error):
    return getattr(error, "winerror", None) == 32


def atomic_write_json(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(prefix=".pyas-", suffix=".tmp", dir=directory)

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = None

            json.dump(data, stream, indent=4, ensure_ascii=False)

            stream.flush()
            os.fsync(stream.fileno())

        for attempt in range(_REPLACE_ATTEMPTS):
            try:
                os.replace(temporary_path, path)
                return
            except PermissionError as error:
                if not _transient(error) or attempt + 1 == _REPLACE_ATTEMPTS:
                    raise

                time.sleep(_REPLACE_BACKOFF * (attempt + 1))
    finally:
        if descriptor is not None:
            os.close(descriptor)

        try:
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)
        except OSError:
            # 目标/tmp 被实时防护持续持有的极端情况下放弃清理:
            # 留一个 .pyas-*.tmp 比在 finally 里抛错打断调用方更可取
            pass
