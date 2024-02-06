import React from "react";
import CodeView from "./CodeView";
import { sendCommand } from "../redux/slice/sessionSlice";
import { useDispatch } from "react-redux";

const Debugger = () => {
  const dispatch = useDispatch();
  const handleButtonPress1 = () => {
    dispatch(sendCommand("-file-exec-and-symbols /app/example-bins/hello_world.out"));
    dispatch(sendCommand(""))
  };
  const handleButtonPress2 = () => {
    console.log("sending command: -break-insert main");
    dispatch(sendCommand("-break-insert main"));
  };

  return (
    <div className="m-5 flex h-[35rem] justify-center space-x-4">
      <CodeView>Assembly</CodeView>
      <div className="flex flex-col space-y-4">
        <CodeView>Registers</CodeView>
        <CodeView>Stack</CodeView>
      </div>
      <CodeView>Debugger, breakpoints, etc.</CodeView>
      <button onClick={handleButtonPress1} className="btn-primary">
        start
      </button>
      <button onClick={handleButtonPress2} className="btn-primary">
        break main
      </button>
    </div>
  );
};

export default Debugger;
