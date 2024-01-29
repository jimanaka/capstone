import logging
import socket
from flask import Flask, jsonify, request, session
from flask_cors import CORS
from flask_socketio import SocketIO
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
