"""One campaign at a time per machine."""

import os

from .settings import from_environment

if os.name == 'nt':
    import msvcrt
else:
    import fcntl


class CampaignBusy(RuntimeError):
    pass


class CampaignLock:
    def __init__(self, settings=None):
        settings = settings or from_environment()
        self.path = settings.lock
        self.disabled = settings.parallel
        self.stream = None

    def __enter__(self):
        if self.disabled:
            return self
        self.stream = open(self.path, 'a+')
        try:
            self.stream.seek(0)
            if os.name == 'nt':
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(self.stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.stream.seek(0)
            holder = self.stream.read().strip() or 'an unknown process'
            self.stream.close()
            self.stream = None
            raise CampaignBusy(f'another fuzz campaign is running (process {holder}, lock file {self.path}). Wait for it, '
                               'or set ADAPTER_FUZZ_ALLOW_PARALLEL=1 to run both and accept the interference.') from None
        self.stream.seek(0)
        self.stream.truncate()
        self.stream.write(str(os.getpid()))
        self.stream.flush()
        return self

    def __exit__(self, *exception):
        if self.stream is not None:
            try:
                self.stream.seek(0)
                if os.name == 'nt':
                    msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(self.stream, fcntl.LOCK_UN)
            finally:
                self.stream.close()
                self.stream = None
