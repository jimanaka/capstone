import logging
import socket
from flask import Flask, jsonify, request, session
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from src.utils.request_util import corsify_response
from src.utils.gdb_session import GdbSession, GdbSessionManager
from src.utils.pty import Pty

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


# @app.route("/")
# def hello_world():
#     return jsonify(hello="world")

@socketio.on("test_event")
def test_event(data):
    print("connected")
    print(data)


@socketio.on("connect")
def connect():
    logging.info("connected")
    cmds = request.args.get("cmd", default=app.config["GDB_EXECUTABLE"])
    sid = request.sid
    print(f'cmds: {cmds}\nsid: {sid}')
    gdb_session = session_manager.create_session(cmds, sid)

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


@socketio.on("disconnect")
def disconnect():
    logging.info("disconnecting socket")
    sid = request.sid
    terminated_session = session_manager.terminate_session_by_sid(sid)
    if terminated_session:
        logging.info(
            f"removed session pid: {terminated_session.pid} for session: {sid}")
    # orphan_session = session_manager.get_session_by_sid(sid)
    # if orphan_session:
    #     logging.info(f"removing orphan session {orphan_session.pid}")
    #     orphan_session.terminate()
