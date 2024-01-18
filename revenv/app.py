from flask import Flask, jsonify, request, session
from flask_socketio import SocketIO
from src.utils.request_util import corsify_response
from src.utils.gdb_session import GdbSession, GdbSessionManager
from src.utils.pty import Pty

# with code from: https://github.com/cs01/gdbgui/

app = Flask(__name__)
app.config.from_object("src.config.Config")
socketio = SocketIO(manage_session=False)
session_manager = GdbSessionManager()


@app.route("/")
def hello_world():
    return jsonify(hello="world")


@socketio.on("connect", namespace="/gdb_session")
def connect():
    cmds = request.args.get("cmd", default=app.config["GDB_EXECUTABLE"])
    sid = request.sid
    gdb_session = session_manager.create_session(cmds, sid)
