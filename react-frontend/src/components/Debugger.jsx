import React, { useState } from "react";
import { useEffect } from "react";
import CodeView from "./CodeView";
import io from "socket.io-client";
const REVENV_URL = "ws://localhost:80/";

const Debugger = () => {
  const [socket, setSocket] = useState(null);
  useEffect(() => {
    if (socket === null) {
      setSocket(
        io(REVENV_URL, {
          path: "/revenv/socket.io",
          autoConnect: false,
          withCredentials: true,
          query: {
            cmd: "test cmd",
          },
        }),
      );
    }
    if (socket) {
      socket.connect();
      socket.on("connect", () => {
        console.log(socket.connected);
        socket.emit("test_event", { data: 1 });
      });
    }
  }, [socket]);

  return (
    <div className="m-5 flex h-[35rem] justify-center space-x-4">
      <CodeView>Assembly</CodeView>
      <div className="flex flex-col space-y-4">
        <CodeView>Registers</CodeView>
        <CodeView>Stack</CodeView>
      </div>
      <CodeView>Debugger, breakpoints, etc.</CodeView>
    </div>
  );
};

export default Debugger;
