import logging
import os
import signal
import io
from pprint import pprint
from tracemalloc import start
from typing import Dict, List, Optional
from pygdbmi.IoManager import IoManager
from src.utils.pty import Pty


class GdbSession:
    def __init__(self, pygdbmi_IOManager: IoManager, gdb_pty: Pty, program_pty: Pty, gui_pty: Pty, pid: int):
        self.pygdbmi_IOManager = pygdbmi_IOManager
        self.gdb_pty = gdb_pty
        self.program_pty = program_pty
        self.gui_pty = gui_pty
        self.pid = pid

    def terminate(self) -> None:
        if not self.pid:
            logging.error("failed to terminate gdb session, no pid")

        try:
            # logging.info(f"attempting to close fd {self.gui_pty.master_fd}")
            # os.close(self.gui_pty.master_fd)
            # logging.info(f"attempting to close fd {self.gui_pty.slave_fd}")
            # os.close(self.gui_pty.slave_fd)
            # logging.info(
            #     f"attempting to close fd {self.program_pty.master_fd}")
            # os.close(self.program_pty.master_fd)
            # logging.info(f"attempting to close fd {self.program_pty.slave_fd}")
            # os.close(self.program_pty.slave_fd)
            # logging.info(f"attempting to kill pid: {self.pid}")
            os.kill(self.pid, signal.SIGKILL)
            logging.info(f"pid {self.pid} killed, waiting for process to finish...")
            os.waitpid(self.pid, os.WSTOPPED)
            logging.info(f"pid {self.pid} successfully killed")
        except Exception as e:
            logging.error(f"failed to kill gdb session {self.pid} {e}")


class GdbSessionManager:
    def __init__(self):
        self.connections: Dict[GdbSession, List[str]] = {}
        self.output_reader = None

    def create_session(self, gdb_cmd: str, id: str) -> GdbSession:
        logging.info(f"creating pty with cmd: {gdb_cmd} from session: {id}")
        gui_pty = Pty()
        program_pty = Pty()
        gui_cmds = [
            f"new-ui mi {gui_pty.ttyname}",
            f"set inferior-tty {program_pty.ttyname}",
            "set pagination off",
        ]
        startup_cmds = " ".join([f"-iex='{c}'" for c in gui_cmds])
        logging.info(f"creating session with : {gdb_cmd} {startup_cmds}")
        gdb_pty = Pty(
            cmd=f"{gdb_cmd} {startup_cmds}")
        io_manager = IoManager(
            io.open(gui_pty.stdin, "wb", 0),
            io.open(gui_pty.stdout, "rb", 0),
            None)
        gdb_session = GdbSession(
            pygdbmi_IOManager=io_manager, gdb_pty=gdb_pty, program_pty=program_pty, gui_pty=gui_pty, pid=gdb_pty.pid)
        self.connections[gdb_session] = id
        return gdb_session

    def get_session_by_pid(self, pid: int) -> Optional[GdbSession]:
        for session in self.connections:
            if pid == session.pid:
                return session
        return None

    def get_session_by_sid(self, sid: str) -> Optional[GdbSession]:
        for session, id in self.connections.items():
            if sid == id:
                return session
        return None

    def remove_session(self, session: GdbSession) -> Optional[GdbSession]:
        ret = self.connections.pop(session, None)
        if ret:
            return session
        return ret

    def terminate_session_by_pid(self, pid: int) -> Optional[GdbSession]:
        session = self.get_session_by_pid(pid)
        session.terminate()
        ret = self.remove_session(session)
        return ret

    def terminate_session_by_sid(self, sid: str) -> Optional[GdbSession]:
        session = self.get_session_by_sid(sid)
        session.terminate()
        ret = self.remove_session(session)
        pprint(self.connections)
        return ret
