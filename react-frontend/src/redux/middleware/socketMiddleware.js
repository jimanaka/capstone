import SocketFactory from "../../scripts/SocketConnection";
import {
  initSocket,
  disconnect,
  connectionEstablished,
  connectionLost,
  setGdbPID,
  sendCommand,
  sendProgramInput,
  setDisassemblyOutput,
  setGdbBreakpoints,
  setGdbRegisterNames,
  setGdbRegisterValues,
  setGdbChangedRegisters,
  setGdbStack,
  setGdbFrame,
  setOutput,
  addOutput,
  doStuff,
} from "../slice/sessionSlice";
import {
  setFileInfo,
  setFunctions,
  setExports,
  setImports,
  setSections,
  setClasses,
  setEntry,
  setSymbols,
  setStrings,
  setAssembly,
  setTopAddress,
  setBotAddress,
  setDecompiledCode,
} from "../slice/codeListingSlice";
import { handleGdbGuiResponse } from "../../scripts/gdbResponse";

const socketMiddleware = (store) => {
  let socketConnection = null;

  return (next) => (action) => {
    if (initSocket.match(action)) {
      if (!socketConnection) {
        socketConnection = SocketFactory.create();
        let socket = socketConnection.socket;
        socket.connect();
        // handle connect
        socket.on("connect", () => {
          store.dispatch(connectionEstablished());
        });
        // handle errors
        socket.on("error", (message) => {
          console.error(message);
        });
        socket.on("gdb_session_connected", (data) => {
          store.dispatch(setGdbPID(data.pid));
        });
        // handle disconnect
        socket.on("disconnect", () => {
          store.dispatch(connectionLost());
          store.dispatch(setGdbPID(null));
          store.dispatch(setDisassemblyOutput(null));
          store.dispatch(setGdbBreakpoints([]));
          store.dispatch(setGdbRegisterNames([]));
          store.dispatch(setGdbRegisterValues([]));
          store.dispatch(setGdbChangedRegisters([]));
          store.dispatch(setGdbStack([]));
          store.dispatch(setGdbFrame(null));
          store.dispatch(setOutput([]));
        });
        socket.on("gdb_gui_response", (data) => {
          data.msg.map((msg) => {
            handleGdbGuiResponse(store, socket, msg);
          });
        });
        socket.on("program_pty_response", (data) => {
          if (data.ok) {
            store.dispatch(addOutput(data.msg));
          }
        });
      }
    }

    if (disconnect.match(action)) {
      if (socketConnection) {
        let socket = socketConnection.socket;
        socket.off("connect");
        socket.off("error");
        socket.off("gdb_gui_response");
        socket.disconnect();
        socket.off("disconnect");
        socketConnection = null;
      }
    }

    if (sendCommand.match(action)) {
      if (!socketConnection) {
        return;
      }
      let socket = socketConnection.socket;
      socket.emit("send_command", {
        cmds: action.payload,
      });
    }

    if (sendProgramInput.match(action)) {
      if (!socketConnection) {
        return;
      }
      let socket = socketConnection.socket;
      socket.emit("send_program_input", {
        input: action.payload,
      });
    }

    next(action);
  };
};

export default socketMiddleware;
