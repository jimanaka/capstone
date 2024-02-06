import logging
import os
import signal
import io
from pprint import pprint
from typing import Dict, List, Optional
from pygdbmi.IoManager import IoManager
import shlex
from pty import openpty, fork


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
        encoded_data = os.read(self.stdout, self.MAX_OUTPUT)
        print("Recieved:", encoded_data.decode())


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
            logging.info(
                f"pid {self.pid} killed, waiting for process to finish...")
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


session_manager = GdbSessionManager()
gdb_session = session_manager.create_session("gdb", "1234")
iomanager = gdb_session.pygdbmi_IOManager
# iomanager.write("-file-exec-and-symbols /app/example-bins/hello_world.out",
#                 timeout_sec=0, raise_error_on_timeout=False, read_response=False)
# iomanager.write("-exec-run", timeout_sec=0,
#                 raise_error_on_timeout=False, read_response=False)
# response = iomanager.get_gdb_response(
#     timeout_sec=0, raise_error_on_timeout=False)
# pprint(response)
response = iomanager.write("-file-exec-and-symbols /app/example-bins/hello_world.out")
pprint(response)
print("--------------------")
response = iomanager.write("-exec-run")
pprint(response)
print("--------------------")

# r2 = gdb_session.gdb_pty.read()
# if r2:
#     pprint(r2)

r3 = gdb_session.program_pty.read()
if r3:
    pprint(r3)
