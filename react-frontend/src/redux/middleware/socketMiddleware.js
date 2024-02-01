import SocketFactory from "../../scripts/SocketConnection";
import {
  initSocket,
  disconnect,
  connectionEstablished,
  connectionLost,
  setGdbPID,
} from "../slice/sessionSlice";

const socketMiddleware = (store) => {
  let socketConnection = null;

  return (next) => (action) => {
    if (initSocket.match(action)) {
      if (!socketConnection) {
        console.log("starting socket factory");
        socketConnection = SocketFactory.create();
        let socket = socketConnection.socket;
        socket.connect();
        // handle connect
        socket.on("connect", () => {
          console.log("socket connected");
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
          console.log("handling disconnect");
          store.dispatch(connectionLost());
          store.dispatch(setGdbPID(null));
        });
      }
    }

    if (disconnect.match(action)) {
      if (socketConnection) {
        console.log("disconnecting socket");
        console.log("terminating gdb session");
        let socket = socketConnection.socket;
        socket.emit("terminate_pid", {
          pid: action.payload,
        });
        socket.off("connect");
        socket.off("error");
        socket.disconnect();

        socketConnection = null;
      }
    }

    next(action);
  };
};

export default socketMiddleware;
