from pty import openpty
import logging


class Pty():
    def __init__(self):
        (master_fd, slave_fd) = openpty()
        self.master_fd = master_fd
        self.slave_fd = slave_fd
        self.stdin = master_fd
        self.stdout = master_fd
        logging.info("creating pty")

    def write(self):
        # TODO write commands to the child
        return 0

    def read(self):
        # TODO read the output from the child
        return 0
