"""Recognize byte-identical copies of the installed menu helper."""
import hashlib
import os
import stat


MAX_COMPONENT_BYTES = 16 * 1024 * 1024


def component_digest(path):
    """Return a bounded digest only if the same regular file stayed unchanged."""
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    try:
        with open(path, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_COMPONENT_BYTES:
                return None
            digest = hashlib.sha256()
            remaining = before.st_size
            while remaining:
                chunk = stream.read(min(65536, remaining))
                if not chunk:
                    return None
                digest.update(chunk)
                remaining -= len(chunk)
            if stream.read(1):
                return None
            after = os.fstat(stream.fileno())
            current = os.stat(path)
            # Windows/Python may expose different ctime meanings for stat/fstat.
            # Compare ctime between handles, and file identity/size/mtime to the path.
            if identity(before) != identity(after) or identity(after)[:4] != identity(current)[:4]:
                return None
            return digest.hexdigest()
    except (OSError, ValueError):
        return None


def is_menu_component_copy(path, expected_digest):
    if not expected_digest or os.path.basename(path).casefold() != "pyas_menu.exe":
        return False
    return component_digest(path) == expected_digest
