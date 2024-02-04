import eventlet
eventlet.monkey_patch(
    # os=True,
    # select=True,
    # socket=True,
    # thread=False,
    # time=True,
)
from os import read
import logging
from flask import Flask, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from src.utils.gdb_session import GdbSessionManager
from threading import Thread
from pprint import pprint

# with code from: https://github.com/cs01/gdbgui/

app = Flask(__name__)
app.config.from_object("src.config.Config")
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, manage_session=False,
                    cors_allowed_origins="*", logger=True)
session_manager = GdbSessionManager()
logging.basicConfig(level=logging.INFO)
app.config["GDB_EXECUTABLE"] = "gdb"
app.config["GDB_INTERPRETER"] = "mi"


@socketio.on("test_event")
def test_event(data):
    print("connected")
    print(data)


@socketio.on("connect")
def connect():
    logging.info("connected")
    cmds = request.args.get("cmd", default=app.config["GDB_EXECUTABLE"])
    sid = request.sid
    gdb_session = session_manager.create_session(cmds, sid)
    if session_manager.output_reader is None:
        logging.info("staring gdb reader thread")
        session_manager.output_reader = Thread(
            target=gdb_output_reader,
        )
        session_manager.output_reader.start()
        logging.info(f"{session_manager.output_reader}")
    emit("gdb_session_connected", {
        "ok": True,
        "pid": gdb_session.pid,
        "msg": f"gdb session {gdb_session.pid} created",
    })


@socketio.on("terminate_pid")
def terminate_pid(data):
    sid = request.sid
    session_manager.terminate_session_by_pid(data['pid'])
    logging.info(f"disconnecting sid: {sid} from pid: {data['pid']}")


@socketio.on("send_command")
def handle_command(data):
    sid = request.sid
    session = session_manager.get_session_by_sid(sid)
    iomanager = session.pygdbmi_IOManager
    cmds = data["cmds"]
    logging.info(f"sending cmd: {cmds}")
    iomanager.write(cmds, timeout_sec=0,
                    raise_error_on_timeout=False, read_response=False)


@socketio.on("disconnect")
def disconnect():
    sid = request.sid
    terminated_session = session_manager.terminate_session_by_sid(sid)
    if terminated_session:
        logging.info(
            f"removed session pid: {terminated_session.pid} for session: {sid}")


def gdb_output_reader():
    logging.info("threading!")
    count = 0
    while True:
        socketio.sleep(2)
        print(count)
        count += 1
        sessions = session_manager.connections
        for gdb_session, id in sessions.items():
            try:
                logging.info(f"loop id: {id}")
                logging.info(
                    f"trying to get gdb response: {gdb_session}")
                response = gdb_session.pygdbmi_IOManager.get_gdb_response(
                    timeout_sec=0, raise_error_on_timeout=False)
                # response = read(gdb_session.gdb_pty.stdout, 150)
                if response:
                    pprint(response)
                else:
                    logging.info("thread passing")
                    pass
            except Exception as e:
                logging.info(f"thingy {e}")
