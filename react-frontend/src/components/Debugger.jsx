import React from "react";
import CodeView from "./CodeView";
import { sendCommand } from "../redux/slice/sessionSlice";
import { useDispatch, useSelector } from "react-redux";

const Debugger = () => {
  const dispatch = useDispatch();
  // const gdbState = useSelector((state) => state.session.gdbState)

  const handleButtonPress1 = () => {
    dispatch(sendCommand("-file-exec-and-symbols /app/example-bins/hello_world.out"));
    //dispatch(sendCommand(""))
  };
  const handleButtonPress2 = () => {
    console.log("sending command: -break-insert main");
    dispatch(sendCommand("-break-insert main"));
  };
  const handleButtonPress3 = () => {
    console.log("running program in gdb...");
    dispatch(sendCommand("-exec-run"));
  }
  const handleButtonPress4 = () => {
    console.log("continuing program...");
    dispatch(sendCommand("-exec-next"));
  }

  return (
    <>
      <div className="flex">
        <button onClick={handleButtonPress1} className="btn-primary">
          start
        </button>
        <button onClick={handleButtonPress2} className="btn-primary">
          break main
        </button>
        <button onClick={handleButtonPress3} className="btn-primary">
          run
        </button>
        <button onClick={handleButtonPress4} className="btn-primary">
          next 
        </button>
      </div>
      <div className="m-5 flex h-[35rem] justify-center space-x-4">
        <CodeView>Assembly</CodeView>
        <div className="flex flex-col space-y-4">
          <CodeView>Registers</CodeView>
          <CodeView>Stack</CodeView>
        </div>
        <CodeView>Debugger, breakpoints, etc.</CodeView>
      </div>
    </>
  );
};

export default Debugger;
