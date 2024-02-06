import shlex
from pty import openpty, fork
import logging
import os
from typing import Optional
from select import select


class Pty():
    def __init__(self, cmd: Optional[str] = None):
        self.MAX_OUTPUT = 1024
        if cmd:
            (pid, fd) = fork()
            if pid == 0:
                # child proc -> execute cmd
                args = shlex.split(cmd)
                os.execvp(args[0], args)
            else:
                # else parent process -> setup IO
                self.stdin = fd
                self.stdout = fd
                self.pid = pid
        else:
            (master_fd, slave_fd) = openpty()
            self.master_fd = master_fd
            self.slave_fd = slave_fd
            self.stdin = master_fd
            self.stdout = master_fd
            self.ttyname = os.ttyname(slave_fd)
            logging.info("creating pty")

    def write(self, data: str) -> None:
        encoded_data = data.encode()
        os.write(self.stdin, encoded_data)

    def read(self) -> Optional[str]:
        if self.stdout is None:
            return "done"
        timeout_sec = 0
        (data, _, _) = select([self.stdout], [], [], timeout_sec)
        if data:
            try:
                response = os.read(self.stdout, self.MAX_OUTPUT).decode()
                if response:
                    return response
            except (OSError, UnicodeDecodeError):
                return None
        return None
