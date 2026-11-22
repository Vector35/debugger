"""Process and descriptor helpers, from the module for the host platform."""

import os

if os.name == 'nt':
    from .windows import (available_signals, descendants, kill_process, open_pipe_count, process_exists,
                          process_identity, signal_process)
else:
    from .posix import (available_signals, descendants, kill_process, open_pipe_count, process_exists,
                        process_identity, signal_process)

__all__ = ['available_signals', 'descendants', 'kill_process', 'open_pipe_count', 'process_exists',
           'process_identity', 'signal_process']
