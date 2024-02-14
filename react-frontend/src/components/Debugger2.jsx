import React from "react";
import CodeView from "./CodeView";
import Code from "./Code";
import { useForm } from "react-hook-form";
import { sendCommand, setOutput } from "../redux/slice/sessionSlice";
import { useDispatch, useSelector } from "react-redux";
import {
  PlayCircleIcon,
  DocumentPlusIcon,
  ChevronRightIcon,
  ChevronDoubleRightIcon,
  PlusCircleIcon,
  StopIcon,
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

  //Todo: create global constants for gdbmi commands
  const handleFileLoadPress = () => {
    dispatch(
      sendCommand("-file-exec-and-symbols /app/example-bins/hello_world.out"),
    );
  };
  const handleBreakpointAdd = (data) => {
    dispatch(sendCommand(`-break-insert ${data.newBreakpoint}`));
    document.getElementById("newBreakpoint").value = "";
  };
  const handleRunPress = () => {
    dispatch(sendCommand("-exec-run"));
    dispatch(setOutput([]));
  };
  const handleNextPress = () => {
    dispatch(sendCommand("-exec-next"));
  };
  const handleContinuePress = () => {
    dispatch(sendCommand("-exec-continue"));
  };

  return (
    <div className="flex flex-col">
      <div className="flex mt-2 mr-6 ml-6">
        <button
          onClick={handleFileLoadPress}
          className="rounded-full text-ctp-text active:text-ctp-mauve active:bg-ctp-crust mr-2"
        >
          <DocumentPlusIcon className="h-6 w-6" />
        </button>
        <button
          onClick={handleRunPress}
          className="rounded-full text-ctp-green active:text-green-300 active:bg-ctp-crust mr-2"
        >
          <PlayCircleIcon className="h-6 w-6" />
        </button>
        <button
          onClick={handleRunPress}
          className="rounded-full text-ctp-red active:text-red-300 active:bg-ctp-crust mr-2"
        >
          <StopIcon className="h-6 w-6" />
        </button>
        <button
          onClick={handleNextPress}
          className="rounded-full text-ctp-text active:text-ctp-mauve active:bg-ctp-crust mr-2"
        >
          <ChevronRightIcon className="h-6 w-6" />
        </button>
        <button
          onClick={handleContinuePress}
          className="rounded-full text-ctp-text active:text-ctp-mauve active:bg-ctp-crust mr-2"
        >
          <ChevronDoubleRightIcon className="h-6 w-6" />
        </button>
      </div>
      <div className="pl-4 pr-4 pb-4 flex w-full h-[50rem] justify-center space-x-4">
        <div className="flex flex-col h-1/3 w-4/5">
          <h1 className="text-center w-full">Breakpoints</h1>
          <CodeView className="flex flex-col overflow-auto mt-2 w-full justify-between h-full">
            <div className="w-full overflow-y-scroll mb-2">
              <ul role="list" className="w-full text-left">
                {breakpoints.length > 0
                  ? breakpoints.map((breakpoint) => {
                      return (
                        <li className="my-2" key={`breakpoint ${breakpoint.number}`}>
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
      </div>
    </div>
  );
};

export default Debugger;
