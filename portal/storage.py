"""Small atomic file writer shared with the short-lived certificate tooling."""
import os
from pathlib import Path


def write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    os.fchmod(fd, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data.encode() if isinstance(data, str) else data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
