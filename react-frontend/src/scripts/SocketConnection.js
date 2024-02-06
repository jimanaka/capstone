import { io } from "socket.io-client";

class SocketConnection {
  constructor() {
    this.socketEndpoint = "ws://localhost:80/";
    this.socket = io(this.socketEndpoint, {
      path: "/revenv/socket.io",
      autoConnect: false,
      withCredentials: true,
      query: {
        cmd: "gdb",
      },
    });
  }

}

let socketConnection = null;

class SocketFactory {
  static create() {
    if (!socketConnection) {
      socketConnection = new SocketConnection();
    }
    return socketConnection;
  }

  static destroy() {
    if (socketConnection) {
      socketConnection = null;
    }
  }
}

export default SocketFactory;
