import React from "react";
import CodeView from "./CodeView";
import Code from "./Code";
import { sendCommand, setProgramOutput } from "../redux/slice/sessionSlice";
import { useDispatch, useSelector } from "react-redux";

const Debugger = () => {
  const dispatch = useDispatch();
  const disassemblyOutput = useSelector((state) => state.session.disassemblyOutput);
  const frame = useSelector((state) => state.session.gdbFrame);
  const breakpoints = useSelector((state) => state.session.gdbBreakpoints);
  const registerNames = useSelector((state) => state.session.gdbRegisterNames);
  const registerValues = useSelector((state) => state.session.gdbRegisterValues);
  const changedRegisters = useSelector((state) => state.session.gdbChangedRegisters);

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
      <div className="flex flex-col w-full max-w-xl">
        <h1 className="w-full text-center">Assembly</h1>
        <CodeView className="flex overflow-auto w-full mt-2">
          <ul>
            {
              disassemblyOutput ? disassemblyOutput.map((line) => {
                let highlight = line.address === frame.addr ? true : false;
                return (
                  <li  key={line.address}>
                    <Code language="x86asm" highlight={highlight} line={line.address} funcName={line["func-name"]} offset={line.offset}>{line.inst}</Code>
                  </li>
                )
              }) : null
            }
          </ul>
        </CodeView>
      </div>
      <div className="flex flex-col space-y-4 w-4/5">
        <div className="flex flex-col w-full h-full">
          <h1 className="w-full text-center">Registers</h1>
          <CodeView className="flex overflow-auto w-full mt-2">
            <ul className="w-full">
              {
                registerValues.length > 0 && registerNames.length > 0 ? registerNames.map((regName, index) => {
                  let highlightStyle = changedRegisters.includes(registerValues[index].number) ? "bg-ctp-overlay0" : null;
                  return (
                    <li key={regName} className={`flex justify-between ${highlightStyle}`}>
                      <div className="text-left">{regName}</div>
                      <div className="text-left">{registerValues[index].value}</div>
                    </li>
                  );
                }) : null
              }
            </ul>
          </CodeView>
        </div>
        <CodeView>Stack</CodeView>
      </div>
      <div className="flex flex-col space-y-4 w-4/5">
        <div className="flex flex-col w-full h-1/3">
          <h1 className="text-center w-full">Breakpoints</h1>
          <CodeView className="flex overflow-auto mt-2">
            <ul>
              {
                breakpoints.length > 0 ? breakpoints.map((breakpoint) => {
                  return (
                    <li key={`breakpoint ${breakpoint.number}`}>
                      <div className="mt-2 mb-2">{breakpoint.number} {breakpoint.addr} in {breakpoint.func} at {breakpoint.file}:{breakpoint.line}</div>
                    </li>
                  )
                }): null
              }
            </ul>
          </CodeView>
        </div>
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
