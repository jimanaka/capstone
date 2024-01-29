import logging
from typing import Dict, List, Optional
from pygdbmi.IoManager import IoManager
from src.utils.pty import Pty


class GdbSession:
    def __init__(self, pygdbmi_IOManger: IoManager, gdb_pty: Pty, program_pty: Pty, pid: int):
        self.pygdbmi_IOManager = pygdbmi_IOManger
        self.gdb_pty = gdb_pty
        self.program_pty = program_pty
        self.pid = pid


class GdbSessionManager:
    def __init__(self):
        self.connections: Dict[GdbSession, List[str]] = {}

    def create_session(self, cmd: str, id: str) -> GdbSession:
        logging.info(f"creating pty with cmd: {cmd} from session: {id}")
        gui_pty = Pty()
        program_pty = Pty()
        gui_cmds = [
            f"new-ui mi {gui_pty.ttyname}",
            f"set inferior-tty {program_pty.ttyname}",
            "set pagination off",
        ]
        startup_cmds = " ".join([f"-iex='{c}'" for c in gui_cmds])
        gdb_pty = Pty(cmd=f"gdb {gui_cmds}")
