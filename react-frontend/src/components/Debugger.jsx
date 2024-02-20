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
    document.getElementById("gdbCommand").value ="";
  }

  return (
    <div className="flex flex-col">
      <div className="pl-4 pr-4 pb-4 flex w-full h-[50rem] justify-center space-x-4">
        <div className="flex flex-col w-[30rem] shrink-0">
          <h1 className="w-full text-center">Assembly</h1>
          <CodeView className="overflow-y-scroll w-full mt-2 h-full">
            <div className="overflow-auto h-full w-full">
              <ul>
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
            </div>
          </CodeView>
        </div>
        <div className="flex flex-col space-y-4 w-4/5 h-full">
          <div className="flex flex-col w-full h-full">
            <h1 className="w-full text-center">Registers</h1>
            <CodeView className="flex overflow-auto w-full mt-2">
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
          <div className="w-full flex flex-col h-full">
            <h1 className="w-full text-center">Stack</h1>
            <CodeView className="flex overflow-auto w-full mt-2">
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
        <div className="flex flex-col space-y-4 w-4/5">
          <div className="flex flex-col w-full h-[16rem]">
            <h1 className="text-center w-full">Breakpoints</h1>
            <CodeView className="flex flex-col overflow-auto mt-2 w-full justify-between h-full">
              <div className="w-full overflow-y-scroll mb-2">
                <ul role="list" className="w-full text-left">
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
              </div>
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
                  className="focus:ring-ctp-mauve bg-ctp-surface0 border-ctp-surface1 appearance-none rounded-lg border-2 placeholder:text-gray-500 focus:shadow-lg focus:outline-none focus:ring-2 px-2 mr-2 w-full"
                  {...register("newBreakpoint")}
                />
                <button
                  type="submit"
                  className="rounded-full text-ctp-text active:text-ctp-mauve active:bg-ctp-crust mr-2"
                >
                  <PlusCircleIcon className="h-7 w-7" />
                </button>
              </form>
            </CodeView>
          </div>
          <div className="grow flex flex-col w-full max-h-[32rem]">
            <h1 className="text-center w-full">Output</h1>
            <CodeView className="flex flex-col overflow-auto mt-2 w-full justify-between h-full">
              <div className="w-full overflow-y-scroll mb-2">
                <ul role="list" className="w-full text-left">
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
              </div>
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
                  className="focus:ring-ctp-mauve bg-ctp-surface0 border-ctp-surface1 appearance-none rounded-lg border-2 placeholder:text-gray-500 focus:shadow-lg focus:outline-none focus:ring-2 px-2 mr-2 w-full"
                  {...register("gdbCommand")}
                />
                <button
                  type="submit"
                  className="rounded-full text-ctp-text active:text-ctp-mauve active:bg-ctp-crust mr-2"
                >
                  <ArrowRightCircleIcon className="h-7 w-7" />
                </button>
              </form>
            </CodeView>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Debugger;
