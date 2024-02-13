import React from "react";
import CodeView from "./CodeView";
import Code from "./Code";
import { sendCommand, setProgramOutput } from "../redux/slice/sessionSlice";
import { useDispatch, useSelector } from "react-redux";
import { PlayCircleIcon, DocumentPlusIcon, ChevronRightIcon, ChevronDoubleRightIcon} from "@heroicons/react/24/outline";

const Debugger = () => {
  const dispatch = useDispatch();
  const disassemblyOutput = useSelector((state) => state.session.disassemblyOutput);
  const frame = useSelector((state) => state.session.gdbFrame);
  const breakpoints = useSelector((state) => state.session.gdbBreakpoints);
  const registerNames = useSelector((state) => state.session.gdbRegisterNames);
  const registerValues = useSelector((state) => state.session.gdbRegisterValues);
  const changedRegisters = useSelector((state) => state.session.gdbChangedRegisters);
  const stack = useSelector((state) => state.session.gdbStack);

  const handleFileLoadPress = () => {
    dispatch(sendCommand("-file-exec-and-symbols /app/example-bins/hello_world.out"));
    //dispatch(sendCommand(""))
  };
  const handleButtonPress2 = () => {
    dispatch(sendCommand("-break-insert main"));
  };;
  const handleRunPress = () => {
    dispatch(sendCommand("-exec-run"));
  };
  const handleNextPress = () => {
    dispatch(sendCommand("-exec-next"));
  };
  const handleContinuePress = () => {
    dispatch(sendCommand("-exec-continue"));
  };

  return (
    <div className="flex flex-col">
      <div className="flex mt-4 mr-8 ml-8">
        <button onClick={handleFileLoadPress} className="text-ctp-text active:text-ctp-mauve active:bg-ctp-crust mr-2">
          <DocumentPlusIcon className="h-8 w-8" />
        </button>
        <button onClick={handleRunPress} className="text-ctp-green active:text-green-300 active:bg-ctp-crust mr-2 h-8 w-8">
          <PlayCircleIcon />
        </button>
        <button onClick={handleNextPress}>
          <ChevronRightIcon className="text-ctp-text active:text-ctp-mauve active:bg-ctp-crust mr-2 h-8 w-8" />
        </button>
        <button onClick={handleContinuePress}>
          <ChevronDoubleRightIcon className="text-ctp-text active:text-ctp-mauve active:bg-ctp-crust mr-2 h-8 w-8" />
        </button>
      </div>
      <div className="pl-4 pr-4 pb-4 flex w-full h-[50rem] justify-center space-x-4 flex-grow">
        <div className="flex flex-col w-full max-w-2xl">
          <h1 className="w-full text-center">Assembly</h1>
          <CodeView className="flex overflow-auto w-full mt-2">
            <ul>
              {
                disassemblyOutput && frame ? disassemblyOutput.map((line) => {
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
        <div className="flex flex-col space-y-4 w-4/5 h-full">
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
          <div className="w-full flex flex-col h-full">
            <h1 className="w-full text-center">Stack</h1>
            <CodeView className="flex overflow-auto w-full mt-2">
              <ul className="w-full">
                {
                  stack.length > 0 ? stack.map((stackLine) => {
                    return (
                      <li key={`stackAddr ${stackLine.addr}`} className="flex justify-between">
                        <div>{stackLine.addr}:</div>
                        <div>{stackLine.data}</div>
                      </li>
                    )
                  }) : null
                }
              </ul>
            </CodeView>
          </div>
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
                        <div className="mt-2 mb-2">#{breakpoint.number} {breakpoint.addr} in {breakpoint.func} at {breakpoint.file}:{breakpoint.line}</div>
                      </li>
                    )
                  }): null
                }
              </ul>
            </CodeView>
          </div>
          <CodeView>
            Program output
          </CodeView>
        </div>
      </div>
    </div>
  );
};

export default Debugger;
