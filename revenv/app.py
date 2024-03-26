import logging
import os
import shutil
from http import HTTPStatus as HTTP
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from pathlib import Path
from src.utils.gdb_utils.gdb_session import GdbSessionManager
from src.utils.pg_utils.pg_manager import PGManager
import src.utils.radare2_util as rd2
import src.utils.pg_utils.pg_util as pg_util

# with code from: https://github.com/cs01/gdbgui/

app = Flask(__name__)
app.config.from_object("src.config.Config")
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, manage_session=False,
                    cors_allowed_origins="*", logger=True)
logging.basicConfig(level=logging.INFO)
app.config["GDB_EXECUTABLE"] = "gdb"
app.config["GDB_INTERPRETER"] = "mi"
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False
app.config["UPLOAD_USER_PATH"] = "/app/user-uploads"
app.config["UPLOAD_LESSON_PATH"] = "/app/lesson-uploads"
app.config["TEMP-PAYLOADS"] = "/app/temp-payloads"

jwt = JWTManager(app)
session_manager = GdbSessionManager()
pg_manager = PGManager()


def _get_substring_before_dot(string: str) -> str:
    parts = string.split(".", 1)
    return parts[0] if len(parts) > 1 else string


@jwt_required()
def __test_jwt():
    pass


@app.route("/test")
def hello_world():
    return jsonify(status="api is up!"), 200

# Todo: error handling
# Todo: extract to separate module


@app.route("/start-pg", methods=["POST"])
@jwt_required()
def start_pg():
    user = get_jwt_identity()
    request_details = request.get_json()
    pg = pg_manager.create_instance(user, request_details["filePath"])
    if pg:
        response = pg_util.get_info(pg)
    else:
        response = jsonify(
            msg="could not create payload generator"), HTTP.SERVICE_UNAVAILABLE.value
    return response


@app.route("/create-payload", methods=["POST"])
@jwt_required()
def create_chain():
    user = get_jwt_identity()
    request_details = request.get_json()
    pg = pg_manager.get_instance_by_user(user)
    response = pg_util.create_chain(pg, request_details["input"])
    return response


# change this as a socketio function
@app.route("/use-payload", methods=["POST"])
@jwt_required()
def use_payload():
    user = get_jwt_identity()
    request_details = request.get_json()
    pid = request_details["pid"]
    pg = pg_manager.get_instance_by_user(user)
    iomanager = session_manager.get_session_by_pid(pid).pygdbmi_IOManager
    response = pg_util.use_payload(pg, iomanager)
    return response


@app.route("/upload-file", methods=["POST"])
@jwt_required()
def upload_file():
    user = get_jwt_identity()
    files = request.files.getlist('file')
    if files is None:
        return jsonify(msg="no file provided"), 200
    if files[0].filename == "":
        return jsonify(msg="no filename provided"), 200

    filename = secure_filename(files[0].filename)
    if files[0] and filename:
        if request.form.get("lesson") == "true":
            path = os.path.join(
                app.config["UPLOAD_LESSON_PATH"], request.form.get("lessonName"))
        else:
            proj_name = _get_substring_before_dot(files[0].filename)
            path = os.path.join(
                app.config["UPLOAD_USER_PATH"], user, proj_name)
        Path(path).mkdir(parents=True, exist_ok=True)
        files[0].save(os.path.join(path, filename))
        os.chmod(os.path.join(path, filename), 0o754)

    if len(files) > 1:
        filename = secure_filename(files[1].filename)
        if files[1] and filename:
            files[1].save(os.path.join(path, filename))
            os.chmod(os.path.join(path, filename), 0o744)
    response = jsonify(msg="file upload successfull")
    return response, 200


# Todo: error handling
@app.route("/delete-file", methods=["POST"])
@jwt_required()
def delete_file():
    user = get_jwt_identity()
    request_details = request.get_json()
    insecure_filename = request_details["filename"]
    filename = secure_filename(insecure_filename)
    path = os.path.join(app.config["UPLOAD_USER_PATH"],
                        user, filename)
    shutil.rmtree(path)
    # Path(os.path.join(app.config["UPLOAD_USER_PATH"],
    #      user, filename)).unlink(missing_ok=True)
    response = jsonify(msg="file removed", file=filename)
    return response, 200


@app.route("/list-files", methods=["GET"])
@jwt_required()
def list_files():
    user = get_jwt_identity()
    path = os.path.join(app.config["UPLOAD_USER_PATH"], user)
    if os.path.isdir(path) is False:
        response = jsonify(
            msg="User directory does not yet exist. Please upload a file", files=[])
        return response, 200

    files = os.listdir(path)
    response = jsonify(msg="file listing", files=files)
    return response, 200


@app.route("/get-file-info", methods=["POST"])
@jwt_required()
def get_file_info():
    request_details = request.get_json()
    response = rd2.get_file_info(request_details)
    return response


@app.route("/disassemble-binary", methods=["POST"])
@jwt_required()
def disassemble_binary():
    request_details = request.get_json()
    filename = request_details["filename"]
    direction = request_details["direction"]
    target = request_details["target"]
    mode = request_details["mode"]
    response = rd2.disassemble_binary(filename, direction, target, mode)
    return response


@app.route("/decompile-function", methods=["POST"])
@jwt_required()
def decompile_function():
    request_details = request.get_json()
    filename = request_details["filename"]
    address = request_details["address"]
    response = rd2.decompile_function(filename, address)
    return response


@socketio.on("connect")
def connect():
    logging.info("connected")
    try:
        __test_jwt()
    except Exception:
        emit("error", {
            "ok": False,
            "msg": "Unauthorized session access",
        })
        return
    cmds = request.args.get("cmd", default=app.config["GDB_EXECUTABLE"])
    workdir = request.args.get("workdir", default="")
    sid = request.sid
    gdb_session = session_manager.create_session(cmds, workdir, sid)
    if session_manager.output_reader is None:
        logging.info("staring gdb reader thread")
        session_manager.output_reader = socketio.start_background_task(
            target=gdb_output_reader,
        )
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
    if iomanager is None:
        emit
    cmds = data["cmds"]
    iomanager.write(cmds, timeout_sec=0,
                    raise_error_on_timeout=False, read_response=False)


@socketio.on("send_program_input")
def send_program_input(data):
    sid = request.sid
    session = session_manager.get_session_by_sid(sid)
    iomanager = session.pygdbmi_IOManager
    if iomanager is None:
        emit
    input = data["input"]
    session.program_pty.write(input + "\n")


@socketio.on("disconnect")
def disconnect():
    sid = request.sid
    terminated_session = session_manager.terminate_session_by_sid(sid)
    if terminated_session:
        logging.info(
            f"removed session pid: {terminated_session.pid} for session: {sid}")


def gdb_output_reader():
    while True:
        socketio.sleep(.5)
        sessions = session_manager.connections.copy()
        for gdb_session, id in sessions.items():
            try:
                if gdb_session.pygdbmi_IOManager is not None:
                    response = gdb_session.pygdbmi_IOManager.get_gdb_response(
                        timeout_sec=0, raise_error_on_timeout=False)
                else:
                    logging.info("IO was none on read")
                if response:
                    socketio.emit("gdb_gui_response", {
                        "ok": True,
                        "msg": response
                    }, to=id)
                # read program stdout of program
                try:
                    program_response = gdb_session.program_pty.read()
                    if program_response:
                        socketio.emit("program_pty_response", {
                            "ok": True,
                            "msg": program_response
                        }, to=id)
                except Exception as e:
                    logging.error(
                        f"Failed to read program pty on gdb response: {e}")
                # read stdout of the gdb process
                try:
                    gdb_response = gdb_session.gdb_pty.read()
                    if gdb_response:
                        socketio.emit("gdb_pty_response", {
                            "ok": True,
                            "msg": gdb_response
                        }, to=id)
                except Exception as e:
                    logging.error(
                        f"Failed to read gdb pty on gdb response: {e}")
                else:
                    pass
            except Exception as e:
                logging.error(f"GDB session was killed before read {e}")
                logging.info(f"thingy {e}")
