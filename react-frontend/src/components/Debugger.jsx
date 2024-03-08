import React from "react";
import CodeView from "./CodeView";
import Code from "./Code";
import { useForm } from "react-hook-form";
import { sendCommand } from "../redux/slice/sessionSlice";
import { useDispatch, useSelector } from "react-redux";
import {
  PlusCircleIcon,
  ArrowRightCircleIcon,
} from "@heroicons/react/24/outline";

const Debugger = () => {
  const dispatch = useDispatch();
  const { register, handleSubmit } = useForm();
  const disassemblyOutput = useSelector(
    (state) => state.session.disassemblyOutput,
  );
  const frame = useSelector((state) => state.session.gdbFrame);
  const breakpoints = useSelector((state) => state.session.gdbBreakpoints);
  const registerNames = useSelector((state) => state.session.gdbRegisterNames);
  const registerValues = useSelector(
    (state) => state.session.gdbRegisterValues,
  );
  const changedRegisters = useSelector(
    (state) => state.session.gdbChangedRegisters,
  );
  const stack = useSelector((state) => state.session.gdbStack);
  const output = useSelector((state) => state.session.output);

  const handleBreakpointAdd = (data) => {
    dispatch(sendCommand(`-break-insert ${data.newBreakpoint}`));
    document.getElementById("newBreakpoint").value = "";
  };
  const handleUserCmdSend = (data) => {
    dispatch(sendCommand(data.gdbCommand));
    document.getElementById("gdbCommand").value = "";
  };

  return (
    <div className="flex max-h-[calc(100vh_-_10rem)] flex-1 justify-center space-x-4 pb-4 pl-4 pr-4">
      <div className="flex flex-1 flex-col overflow-hidden">
        <h1 className="w-full text-center">Assembly</h1>
        <CodeView className="mt-2 flex flex-1 flex-col overflow-scroll text-left font-mono">
          <ul className="w-full">
            {disassemblyOutput && frame
              ? disassemblyOutput.map((line) => {
                  let highlight = line.address === frame.addr ? true : false;
                  return (
                    <li key={line.address}>
                      <Code
                        language="x86asm"
                        highlight={highlight}
                        line={line.address}
                        funcName={line["func-name"]}
                        offset={line.offset}
                      >
                        {line.inst}
                      </Code>
                    </li>
                  );
                })
              : null}
          </ul>
        </CodeView>
      </div>
      <div className="flex max-w-md flex-1 flex-col space-y-4">
        <div className="flex flex-1 flex-col">
          <h1 className="w-full text-center">Registers</h1>
          <CodeView className="mt-2 flex flex-1 flex-col overflow-scroll text-left font-mono">
            <ul className="w-full">
              {registerValues.length > 0 && registerNames.length > 0
                ? registerNames.map((regName, index) => {
                    let highlightStyle = changedRegisters.includes(
                      registerValues[index].number,
                    )
                      ? "bg-ctp-overlay0"
                      : null;
                    return (
                      <li
                        key={regName}
                        className={`flex justify-between ${highlightStyle}`}
                      >
                        <div className="text-left">{regName}</div>
                        <div className="text-left">
                          {registerValues[index].value}
                        </div>
                      </li>
                    );
                  })
                : null}
            </ul>
          </CodeView>
        </div>
        <div className="flex flex-1 flex-col">
          <h1 className="w-full text-center">Stack</h1>
          <CodeView className="mt-2 flex flex-1 flex-col overflow-scroll text-left font-mono">
            <ul className="w-full">
              {stack.length > 0
                ? stack.map((stackLine) => {
                    return (
                      <li
                        key={`stackAddr ${stackLine.addr}`}
                        className="flex justify-between"
                      >
                        <div>{stackLine.addr}:</div>
                        <div>{stackLine.data}</div>
                      </li>
                    );
                  })
                : null}
            </ul>
          </CodeView>
        </div>
      </div>
      <div className="flex max-w-lg flex-1 flex-col space-y-4">
        <div className="flex h-[16rem] w-full flex-col overflow-hidden">
          <h1 className="w-full text-center">Breakpoints</h1>
          <CodeView className="mt-2 flex flex-1 flex-col justify-between overflow-scroll text-left font-mono">
            <ul role="list" className="mb-2 w-full">
              {breakpoints.length > 0
                ? breakpoints.map((breakpoint) => {
                    return (
                      <li
                        className="my-2"
                        key={`breakpoint ${breakpoint.number}`}
                      >
                        <div>
                          #{breakpoint.number} {breakpoint.addr} in{" "}
                          {breakpoint.func} at {breakpoint.file}:
                          {breakpoint.line}
                        </div>
                      </li>
                    );
                  })
                : null}
            </ul>
            <form
              className="flex w-full"
              onSubmit={handleSubmit(handleBreakpointAdd)}
            >
              <input
                type="text"
                name="newBreakpoint"
                id="newBreakpoint"
                placeholder="Symbol name, address, etc..."
                required
                className="mr-2 w-full appearance-none rounded-lg border-2 border-ctp-surface1 bg-ctp-surface0 px-2 placeholder:text-gray-500 focus:shadow-lg focus:outline-none focus:ring-2 focus:ring-ctp-mauve"
                {...register("newBreakpoint")}
              />
              <button
                type="submit"
                className="mr-2 rounded-full text-ctp-text active:bg-ctp-crust active:text-ctp-mauve"
              >
                <PlusCircleIcon className="h-7 w-7" />
              </button>
            </form>
          </CodeView>
        </div>
        <div className="flex flex-1 flex-col overflow-hidden">
          <h1 className="w-full text-center">Output</h1>
          <CodeView className="mt-2 flex flex-1 flex-col justify-between overflow-scroll text-left font-mono">
            <ul role="list" className="mb-2 w-full">
              {output.length > 0
                ? output.map((line, index) => {
                    return (
                      <li key={`output${index + 1}`} className="my-2">
                        #{index + 1} {line}
                      </li>
                    );
                  })
                : null}
            </ul>
            <form
              className="flex w-full"
              onSubmit={handleSubmit(handleUserCmdSend)}
            >
              <input
                type="text"
                name="gdbCommand"
                id="gdbCommand"
                placeholder="Gdb CLI command"
                required
                className="mr-2 w-full appearance-none rounded-lg border-2 border-ctp-surface1 bg-ctp-surface0 px-2 placeholder:text-gray-500 focus:shadow-lg focus:outline-none focus:ring-2 focus:ring-ctp-mauve"
                {...register("gdbCommand")}
              />
              <button
                type="submit"
                className="mr-2 rounded-full text-ctp-text active:bg-ctp-crust active:text-ctp-mauve"
              >
                <ArrowRightCircleIcon className="h-7 w-7" />
              </button>
            </form>
          </CodeView>
        </div>
      </div>
    </div>
  );
};

export default Debugger;
