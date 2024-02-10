import React from "react";
import CodeView from "./CodeView";
import Code from "./Code";
import { sendCommand, setProgramOutput } from "../redux/slice/sessionSlice";
import { useDispatch, useSelector } from "react-redux";

const Debugger = () => {
  const dispatch = useDispatch();
  const disassemblyOutput = useSelector((state) => state.session.disassemblyOutput);
  const frame = useSelector((state) => state.session.gdbFrame);

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
    <div className="p-4 flex w-full h-[50rem] justify-center space-x-4 flex-grow">
      <CodeView className="flex overflow-auto w-full">
        <ul>
          {
            disassemblyOutput ? disassemblyOutput.map((line) => {
              let highlight = line.address === frame.addr ? true : false;
              return (
                <li>
                  <Code key={line.address} language="x86asm" highlight={highlight} line={line.address} funcName={line["func-name"]} offset={line.offset}>{line.inst}</Code>
                </li>
              )
            }) : "No output"
          }
        </ul>
      </CodeView>
      <div className="flex flex-col space-y-4 w-4/5">
        <CodeView>Registers</CodeView>
        <CodeView>Stack</CodeView>
      </div>
      <div className="flex flex-col space-y-4 w-4/5">
        <CodeView className="h-1/3">Breakpoints</CodeView>
        <CodeView>
          GDB control
          <div className="flex mt-4 mr-8 ml-8">
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
          <hr className="mt-4 mb-4"/>
          Gdb output
        </CodeView>
      </div>
    </div>
  );
};

export default Debugger;
